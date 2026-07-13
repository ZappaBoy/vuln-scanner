import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from vuln_scanner.config.models import AppConfig
from vuln_scanner.tools.base import AbstractTool, ScanInput, ScanResult, ScanStatus

log = logging.getLogger(__name__)


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

    def run(self) -> list[ScanResult]:
        active_tools = self._filter_tools()
        targets = self._config.scan.targets

        if not active_tools:
            log.warning("No tools selected after filtering.")
            return []

        if not targets:
            log.warning("No targets specified.")
            return []

        scan_input = ScanInput(
            targets=targets,
            timeout=self._config.scan.timeout,
            mode=self._config.scan.mode,
            rate_limit=self._config.scan.rate_limit,
        )

        tasks = [(tool, target) for tool in active_tools for target in targets]
        log.info(
            "Starting scan: %d tool(s) × %d target(s) = %d task(s) | mode=%s | workers=%d",
            len(active_tools),
            len(targets),
            len(tasks),
            scan_input.mode.value,
            self._config.scan.max_concurrent,
        )

        results: list[ScanResult] = []
        max_workers = max(1, self._config.scan.max_concurrent)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_task = {
                executor.submit(tool.run, target, scan_input): (tool.name, target)
                for tool, target in tasks
            }
            for future in as_completed(future_to_task):
                tool_name, target = future_to_task[future]
                try:
                    result = future.result()
                except Exception as exc:
                    log.exception("Unexpected error from tool '%s' on target '%s'.", tool_name, target)
                    result = ScanResult(
                        tool=tool_name,
                        target=target,
                        status=ScanStatus.FAILED,
                        error=str(exc),
                    )

                icon = "✓" if result.status == ScanStatus.SUCCESS else "✗"
                log.info(
                    "  [%s] %s → %s (%s, %.1fs, %d finding(s))",
                    icon,
                    tool_name,
                    target,
                    result.status.value,
                    result.duration,
                    len(result.findings),
                )
                results.append(result)

        return results
