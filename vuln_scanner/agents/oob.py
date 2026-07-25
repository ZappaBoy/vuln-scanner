"""Out-of-band interaction (OAST) via interactsh-client.

Gives agents a callback domain to inject into payloads and a way to poll for the
DNS/HTTP/SMTP interactions that prove blind bugs (SSRF, XXE, blind XSS, log4shell,
blind command injection).  Container-only; degrades gracefully when the binary or
network is unavailable.
"""

import json
import logging
import queue
import re
import shutil
import subprocess
import threading
import time

from vuln_scanner.agents.guards import is_in_container

log = logging.getLogger(__name__)

_BINARY = "interactsh-client"
_DOMAIN_RE = re.compile(r"\b([a-z0-9]{20,}\.[a-z0-9.\-]+\.[a-z]{2,})\b", re.IGNORECASE)


def parse_callback_domain(text: str) -> str:
    """Extract the registered interactsh payload domain from client output."""
    for line in text.splitlines():
        m = _DOMAIN_RE.search(line)
        if m:
            return m.group(1)
    return ""


def parse_interaction(line: str) -> dict | None:
    """Parse one JSONL interaction record from interactsh-client -json."""
    line = line.strip()
    if not line or not line.startswith("{"):
        return None
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None
    if "protocol" not in data:
        return None
    return {
        "protocol": data.get("protocol", ""),
        "source": data.get("remote-address", data.get("remote_address", "")),
        "raw": data.get("raw-request", data.get("raw_request", "")),
        "timestamp": data.get("timestamp", ""),
    }


class OobSession:
    """A running interactsh-client session with a background line reader."""

    def __init__(self, server: str = "", token: str = "") -> None:
        self._server = server
        self._token = token
        self._proc: subprocess.Popen | None = None
        self._q: "queue.Queue[str]" = queue.Queue()
        self._reader: threading.Thread | None = None
        self.domain: str = ""
        self.available: bool = False
        self.interactions: list[dict] = []

    def _argv(self) -> list[str]:
        argv = [_BINARY, "-json", "-v"]
        if self._server:
            argv += ["-server", self._server]
        if self._token:
            argv += ["-token", self._token]
        return argv

    def start(self, register_timeout: float = 15.0) -> bool:
        """Launch the client and capture the registered callback domain.

        Returns True if a domain was registered.  Never raises.
        """
        if not is_in_container():
            log.debug("OOB unavailable: not in container.")
            return False
        if shutil.which(_BINARY) is None:
            log.warning("OOB unavailable: %s not installed.", _BINARY)
            return False
        try:
            self._proc = subprocess.Popen(
                self._argv(),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
            )
        except OSError as exc:  # pragma: no cover - defensive
            log.warning("OOB start failed: %s", exc)
            return False

        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

        deadline = time.monotonic() + register_timeout
        buffer: list[str] = []
        while time.monotonic() < deadline and not self.domain:
            try:
                line = self._q.get(timeout=0.5)
            except queue.Empty:
                continue
            buffer.append(line)
            dom = parse_callback_domain(line)
            if dom:
                self.domain = dom
                self.available = True
                break
        return self.available

    def _read_loop(self) -> None:  # pragma: no cover - thread I/O
        if not self._proc or not self._proc.stdout:
            return
        for line in self._proc.stdout:
            self._q.put(line)

    def check(self) -> list[dict]:
        """Drain and parse any interactions observed since the last check."""
        new: list[dict] = []
        while True:
            try:
                line = self._q.get_nowait()
            except queue.Empty:
                break
            rec = parse_interaction(line)
            if rec:
                new.append(rec)
        self.interactions.extend(new)
        return new

    def stop(self) -> None:
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=3)
            except (subprocess.TimeoutExpired, OSError):
                try:
                    self._proc.kill()
                except OSError:
                    pass
