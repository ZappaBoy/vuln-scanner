import asyncio
import logging
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

from vuln_scanner.config.models import AppConfig
from vuln_scanner.tools.enums import ScanStatus
from vuln_scanner.tools.models import ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool

log = logging.getLogger(__name__)


class _ProgressTracker:
    """Thread-safe progress counter; renders inline in TTY, logs otherwise."""
    def __init__(self, total: int) -> None:
        self._total = total
        self._done = 0
        self._ok = 0
        self._fail = 0
        self._skip = 0
        self._running: set[str] = set()
        self._lock = threading.Lock()
        self._tty = sys.stderr.isatty()

    def start(self, label: str) -> None:
        with self._lock:
            self._running.add(label)

    def finish(self, label: str, status: ScanStatus) -> None:
        with self._lock:
            self._running.discard(label)
            self._done += 1
            if status == ScanStatus.SUCCESS:
                self._ok += 1
            elif status == ScanStatus.SKIPPED:
                self._skip += 1
            else:
                self._fail += 1
            if self._tty:
                self._render_tty()

    def _render_tty(self) -> None:
        width = 24
        filled = int(width * self._done / max(self._total, 1))
        bar = "█" * filled + "░" * (width - filled)
        running_list = ", ".join(sorted(self._running)[:4])
        if len(self._running) > 4:
            running_list += f" +{len(self._running) - 4}"
        suffix = f"  running: [{running_list}]" if running_list else ""
        line = (
            f"\r  [{bar}] {self._done}/{self._total}"
            f"  ✓{self._ok} ✗{self._fail} ~{self._skip}{suffix}"
        )
        print(line, end="", flush=True, file=sys.stderr)
        if self._done == self._total:
            print(file=sys.stderr)  # final newline

    def summary_line(self) -> str:
        return (
            f"{self._total} task(s) completed: "
            f"✓ {self._ok} success  ✗ {self._fail} failed  ~ {self._skip} skipped"
        )


class ScanOrchestrator:
    def __init__(self, config: AppConfig, tools: list[AbstractTool]) -> None:
        self._config = config
        self._tools = tools

    def _filter_tools(self) -> list[AbstractTool]:
        cfg_tools = self._config.tools
        cfg_cats = self._config.categories

        result: list[AbstractTool] = []
        for tool in self._tools:
            if cfg_cats.include and tool.category not in cfg_cats.include:
                log.debug("Skipping tool '%s': category '%s' not in include list.", tool.name, tool.category)
                continue
            if tool.category in cfg_cats.exclude:
                log.debug("Skipping tool '%s': category '%s' is excluded.", tool.name, tool.category)
                continue
            if cfg_tools.include and tool.name not in cfg_tools.include:
                log.debug("Skipping tool '%s': not in include list.", tool.name)
                continue
            if tool.name in cfg_tools.exclude:
                log.debug("Skipping tool '%s': explicitly excluded.", tool.name)
                continue
            result.append(tool)

        return result

    async def _run_task(
        self,
        loop: asyncio.AbstractEventLoop,
        executor: ThreadPoolExecutor,
        tool: AbstractTool,
        target: str,
        scan_input: ScanInput,
        tracker: _ProgressTracker,
        timeout_override: int | None = None,
    ) -> ScanResult:
        label = f"{tool.name}→{target}"
        if timeout_override is not None:
            scan_input = scan_input.model_copy(update={"timeout": timeout_override})
        tracker.start(label)
        try:
            result = await loop.run_in_executor(executor, tool.run, target, scan_input)
        except Exception as exc:
            log.exception("Unexpected error from tool '%s' on target '%s'.", tool.name, target)
            result = ScanResult(
                tool=tool.name,
                target=target,
                status=ScanStatus.FAILED,
                error=str(exc),
            )
        tracker.finish(label, result.status)
        if result.status == ScanStatus.SUCCESS:
            icon = "✓"
        elif result.status == ScanStatus.SKIPPED:
            icon = "-"
        else:
            icon = "✗"
        log.info(
            "  [%d/%d] [%s] %s → %s (%s, %.1fs, %d finding(s))",
            tracker._done,
            tracker._total,
            icon,
            tool.name,
            target,
            result.status.value,
            result.duration,
            len(result.findings),
        )
        return result

    async def _run_async(self) -> list[ScanResult]:
        active_tools = self._filter_tools()
        targets = self._config.scan.targets

        if not active_tools:
            log.warning("No tools selected after filtering.")
            return []
        if not targets:
            log.warning("No targets specified.")
            return []

        # Build per-target ScanInputs so each carries the right auth credentials.
        # Per-target auth overrides the global config for that specific target.
        base_auth = self._config.auth
        scan_inputs: dict[str, ScanInput] = {
            target: ScanInput(
                targets=targets,
                timeout=self._config.scan.timeout,
                mode=self._config.scan.mode,
                rate_limit=self._config.scan.rate_limit,
                auth=base_auth.for_target(target),
                proxy=self._config.scan.proxy,
            )
            for target in targets
        }

        tasks: list[tuple[AbstractTool, str]] = []
        skipped_count = 0
        for tool in active_tools:
            for target in targets:
                if tool.applies_to(target):
                    tasks.append((tool, target))
                else:
                    log.debug(
                        "Skipping tool '%s' for target '%s': target type not applicable.",
                        tool.name, target,
                    )
                    skipped_count += 1

        max_workers = max(1, self._config.scan.max_concurrent)
        log.info(
            "Starting scan: %d tool(s) × %d target(s) = %d task(s) "
            "(%d type-gated skips) | mode=%s | workers=%d",
            len(active_tools),
            len(targets),
            len(tasks),
            skipped_count,
            self._config.scan.mode.value,
            max_workers,
        )

        tracker = _ProgressTracker(len(tasks))
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            coroutines = [
                self._run_task(
                    loop, executor, tool, target, scan_inputs[target],
                    tracker=tracker,
                    timeout_override=self._config.tools.timeouts.get(tool.name),
                )
                for tool, target in tasks
            ]
            results = await asyncio.gather(*coroutines)

        log.info(tracker.summary_line())
        return list(results)

    def run(self) -> list[ScanResult]:
        """Run all tool×target pairs concurrently. Blocking entry point."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Already inside an event loop (e.g. Jupyter / tests)
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                    return ex.submit(asyncio.run, self._run_async()).result()
            return loop.run_until_complete(self._run_async())
        except RuntimeError:
            return asyncio.run(self._run_async())
