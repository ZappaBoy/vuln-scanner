import json
import logging
from datetime import date
from io import BytesIO

import requests

from vuln_scanner.config.models import DefectDojoConfig
from vuln_scanner.tools.enums import Severity
from vuln_scanner.tools.models import ScanResult

log = logging.getLogger(__name__)

_SEVERITY_MAP: dict[Severity, str] = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Info",
}


class DefectDojoClient:
    def __init__(self, config: DefectDojoConfig) -> None:
        self._config = config
        self._base = config.url.rstrip("/")
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": f"Token {config.api_key}",
                "Accept": "application/json",
            }
        )

    def is_configured(self) -> bool:
        return bool(self._config.api_key and self._config.product_name)

    def _get_or_create_product(self) -> int:
        name = self._config.product_name
        resp = self._session.get(f"{self._base}/api/v2/products/", params={"name": name})
        resp.raise_for_status()
        results = resp.json().get("results", [])
        if results:
            log.debug("Found existing DefectDojo product '%s' (id=%d).", name, results[0]["id"])
            return results[0]["id"]

        log.info("Creating DefectDojo product '%s'.", name)
        resp = self._session.post(
            f"{self._base}/api/v2/products/",
            json={"name": name, "description": "Created by vuln-scanner.", "prod_type": 1},
        )
        resp.raise_for_status()
        product_id: int = resp.json()["id"]
        log.debug("Created product id=%d.", product_id)
        return product_id

    def _create_engagement(self, product_id: int) -> int:
        today = date.today().isoformat()
        resp = self._session.post(
            f"{self._base}/api/v2/engagements/",
            json={
                "name": self._config.engagement_name,
                "product": product_id,
                "target_start": today,
                "target_end": today,
                "status": "In Progress",
                "engagement_type": "CI/CD",
            },
        )
        resp.raise_for_status()
        engagement_id: int = resp.json()["id"]
        log.debug("Created engagement id=%d.", engagement_id)
        return engagement_id

    def _build_generic_json(self, results: list[ScanResult]) -> bytes:
        today = date.today().isoformat()
        findings = []
        for result in results:
            for f in result.findings:
                entry: dict = {
                    "title": f.title,
                    "description": f.description,
                    "severity": _SEVERITY_MAP[f.severity],
                    "date": today,
                    "active": True,
                    "verified": False,
                }
                if f.cve:
                    entry["cve"] = f.cve[0]
                if f.references:
                    entry["references"] = "\n".join(f.references)
                findings.append(entry)
        return json.dumps({"findings": findings}).encode()

    def _import_findings(self, engagement_id: int, results: list[ScanResult]) -> None:
        payload = self._build_generic_json(results)
        resp = self._session.post(
            f"{self._base}/api/v2/import-scan/",
            data={
                "scan_type": "Generic Findings Import",
                "engagement": engagement_id,
                "minimum_severity": "Info",
                "active": True,
                "verified": False,
                "close_old_findings": False,
            },
            files={"file": ("findings.json", BytesIO(payload), "application/json")},
        )
        resp.raise_for_status()
        log.debug("Import response: %s", resp.json())

    def push(self, results: list[ScanResult]) -> None:
        if not self.is_configured():
            log.debug("DefectDojo not configured (missing api_key or product_name) — skipping push.")
            return

        total = sum(len(r.findings) for r in results)
        if total == 0:
            log.info("No findings to push to DefectDojo.")
            return

        log.info("Pushing %d finding(s) to DefectDojo at %s...", total, self._base)
        try:
            product_id = self._get_or_create_product()
            engagement_id = self._create_engagement(product_id)
            self._import_findings(engagement_id, results)
            log.info(
                "DefectDojo push complete (product_id=%d, engagement_id=%d, findings=%d).",
                product_id,
                engagement_id,
                total,
            )
        except requests.RequestException as exc:
            log.error("Failed to push findings to DefectDojo: %s", exc)
