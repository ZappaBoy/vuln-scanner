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

INTERACTSH_BINARY = "interactsh-client"
_DOMAIN_RE = re.compile(r"\b([a-z0-9]{20,}\.[a-z0-9.\-]+\.[a-z]{2,})\b", re.IGNORECASE)
_DEFAULT_REGISTER_TIMEOUT = 15.0


def parse_callback_domain(text: str) -> str:
    """Extract the registered interactsh payload domain from client output."""
    for line in text.splitlines():
        match = _DOMAIN_RE.search(line)
        if match:
            return match.group(1)
    return ""


def parse_interaction(line: str) -> dict | None:
    """Parse one JSONL interaction record from ``interactsh-client -json``."""
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
        self._process: subprocess.Popen | None = None
        self._queue: "queue.Queue[str]" = queue.Queue()
        self._reader: threading.Thread | None = None
        self.domain: str = ""
        self.available: bool = False
        self.interactions: list[dict] = []

    def _argv(self) -> list[str]:
        argv = [INTERACTSH_BINARY, "-json", "-v"]
        if self._server:
            argv += ["-server", self._server]
        if self._token:
            argv += ["-token", self._token]
        return argv

    def start(self, register_timeout: float = _DEFAULT_REGISTER_TIMEOUT) -> bool:
        """Launch the client and capture the registered callback domain.

        Returns True if a domain was registered.  Never raises.
        """
        if not is_in_container():
            log.debug("OOB unavailable: not in container.")
            return False
        if shutil.which(INTERACTSH_BINARY) is None:
            log.warning("OOB unavailable: %s not installed.", INTERACTSH_BINARY)
            return False
        try:
            self._process = subprocess.Popen(
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
        while time.monotonic() < deadline and not self.domain:
            try:
                line = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            domain = parse_callback_domain(line)
            if domain:
                self.domain = domain
                self.available = True
                break
        return self.available

    def _read_loop(self) -> None:  # pragma: no cover - thread I/O
        if not self._process or not self._process.stdout:
            return
        for line in self._process.stdout:
            self._queue.put(line)

    def check(self) -> list[dict]:
        """Drain and parse any interactions observed since the last check."""
        new_interactions: list[dict] = []
        while True:
            try:
                line = self._queue.get_nowait()
            except queue.Empty:
                break
            record = parse_interaction(line)
            if record:
                new_interactions.append(record)
        self.interactions.extend(new_interactions)
        return new_interactions

    def stop(self) -> None:
        if self._process and self._process.poll() is None:
            try:
                self._process.terminate()
                self._process.wait(timeout=3)
            except (subprocess.TimeoutExpired, OSError):
                try:
                    self._process.kill()
                except OSError:
                    pass
