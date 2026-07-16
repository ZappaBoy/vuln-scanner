"""Multi-pass LLM analysis: triage → PoC design → mitigation → clustering."""


import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING

from vuln_scanner.model import Assessment, Cluster
from vuln_scanner.tools.enums import Confidence, ScanStatus
from vuln_scanner.tools.models import Finding, ScanResult

if TYPE_CHECKING:
    from vuln_scanner.llm.models import LLMConfig
    from vuln_scanner.llm.client import LLMClient
    from vuln_scanner.tools.enums import Severity

log = logging.getLogger(__name__)

_TRUNCATE_RAW = 2000  # chars of raw_output to send to LLM


class LLMAnalyzer:
    def __init__(self, config: "LLMConfig") -> None:
        self._config = config
        self._client: "LLMClient | None" = None

    def _get_client(self) -> "LLMClient":
        if self._client is None:
            from vuln_scanner.llm.client import LLMClient
            self._client = LLMClient(self._config)
        return self._client

    def analyze(self, assessment: Assessment) -> Assessment:
        """Enrich an Assessment in-place and return it."""
        if not self._config.is_active:
            return assessment

        try:
            self._config.validate_active()
        except ValueError as exc:
            log.error("LLM config error: %s", exc)
            return assessment

        in_scope = [
            r for r in assessment.results
            if r.status != ScanStatus.SKIPPED
            and r.findings
            and self._config.in_scope(r.tool, self._get_category(r))
        ]

        if not in_scope:
            log.info("LLM: no in-scope results with findings — skipping analysis.")
            return assessment

        log.info("LLM: analyzing %d result(s) across %d finding(s).",
                 len(in_scope), sum(len(r.findings) for r in in_scope))

        # Triage & PoC design (per result, threaded)
        poc_plans: dict[str, str] = {}  # finding key → poc_plan
        with ThreadPoolExecutor(max_workers=4) as ex:
            futures = {
                ex.submit(self._triage_result, r): r
                for r in in_scope
            }
            for fut in as_completed(futures):
                r = futures[fut]
                try:
                    plans = fut.result()
                    poc_plans.update(plans)
                except Exception as exc:
                    log.warning("LLM triage failed for %s/%s: %s", r.tool, r.target, exc)

        # PoC generation (deferred to poc/generator.py, called from main.py)
        # The poc_plans dict is stored in assessment.metadata for the generator to consume.
        assessment.metadata["llm_poc_plans"] = poc_plans

        # Mitigation (per finding with poc evidence placeholder)
        with ThreadPoolExecutor(max_workers=4) as ex:
            futures_mit = {
                ex.submit(self._mitigation_for_result, r, poc_plans): r
                for r in in_scope
            }
            for fut in as_completed(futures_mit):
                r = futures_mit[fut]
                try:
                    fut.result()
                except Exception as exc:
                    log.warning("LLM mitigation failed for %s/%s: %s", r.tool, r.target, exc)

        # Clustering + executive summary
        features = self._config.features
        if features.cluster:
            try:
                self._cluster(assessment)
            except Exception as exc:
                log.warning("LLM clustering failed: %s", exc)

        return assessment

    @staticmethod
    def _get_category(result: ScanResult) -> str:
        try:
            from vuln_scanner.tools import TOOL_REGISTRY
            cls = TOOL_REGISTRY.get(result.tool)
            if cls:
                return cls().category
        except Exception as e:
            log.warning("LLM category lookup failed: %s", e)
            pass
        return "unknown"

    @staticmethod
    def _finding_key(f: Finding) -> str:
        return f"{f.tool}::{f.target}::{f.title}"

    def _triage_result(self, result: ScanResult) -> dict[str, str]:
        """Enrich each finding in a ScanResult. Returns {finding_key: poc_plan}."""
        cfg = self._config
        features = cfg.resolve_features(result.tool, self._get_category(result))
        if not features.enrich:
            return {}

        client = self._get_client()
        poc_plans: dict[str, str] = {}
        raw_snippet = ""
        if features.logs_analysis and result.raw_output:
            raw_snippet = result.raw_output[:_TRUNCATE_RAW]

        for finding in result.findings:
            try:
                system = cfg.prompts.get("enrich_system")
                user = cfg.prompts.get("enrich_user").format(
                    tool=finding.tool,
                    target=finding.target,
                    title=finding.title,
                    severity=finding.severity.value,
                    description=finding.description[:800],
                    cves=", ".join(finding.cve) or "none",
                    raw_output=raw_snippet,
                )
                data = client.complete_json(system, user)

                finding.cwe = data.get("cwe") or []
                conf_str = data.get("confidence", "unknown")
                try:
                    finding.confidence = Confidence(conf_str)
                except ValueError:
                    finding.confidence = Confidence.UNKNOWN
                finding.false_positive = data.get("false_positive")
                finding.exploitability = data.get("exploitability", "")
                finding.llm_notes = data.get("notes", "")

                poc_plan = data.get("poc_plan", "")
                if poc_plan and features.generate_poc:
                    poc_plans[self._finding_key(finding)] = poc_plan

                if features.false_positive_filter and finding.false_positive is True:
                    log.debug("LLM marked finding as FP: %s", finding.title)

            except Exception as exc:
                log.debug("LLM triage error on finding '%s': %s", finding.title, exc)

        return poc_plans

    def _mitigation_for_result(
        self,
        result: ScanResult,
        poc_plans: dict[str, str],
    ) -> None:
        """Mitigation + remediation per finding."""
        cfg = self._config
        features = cfg.resolve_features(result.tool, self._get_category(result))
        if not features.mitigation:
            return

        client = self._get_client()
        for finding in result.findings:
            if finding.false_positive:
                continue
            try:
                poc_evidence = ""
                # If poc execution results are attached, include them
                poc_exec = finding.raw.get("_poc_evidence", "")
                if poc_exec:
                    poc_evidence = f"PoC execution evidence:\n{poc_exec}\n"

                system = cfg.prompts.get("mitigation_system")
                user = cfg.prompts.get("mitigation_user").format(
                    poc_evidence=poc_evidence,
                    title=finding.title,
                    severity=finding.severity.value,
                    description=finding.description[:800],
                    cwe=", ".join(finding.cwe) or "unknown",
                    exploitability=finding.exploitability or "unknown",
                    tool=finding.tool,
                    target=finding.target,
                )
                data = client.complete_json(system, user)
                finding.mitigation = data.get("mitigation", "")
                finding.remediation = data.get("remediation", "")
            except Exception as exc:
                log.debug("LLM mitigation error on '%s': %s", finding.title, exc)

    def _cluster(self, assessment: Assessment) -> None:
        """Cluster all findings and produce executive summary."""
        all_findings = assessment.all_findings
        if not all_findings:
            return

        findings_payload = [
            {
                "tool": tool,
                "target": f.target,
                "title": f.title,
                "severity": f.severity.value,
                "cwe": f.cwe,
                "description": f.description[:300],
                "exploitability": f.exploitability,
            }
            for tool, f in all_findings
            if not f.false_positive
        ]

        if not findings_payload:
            return

        client = self._get_client()
        system = self._config.prompts.get("cluster_system")
        user = self._config.prompts.get("cluster_user").format(
            findings_json=json.dumps(findings_payload, indent=2)
        )
        data = client.complete_json(system, user)

        assessment.executive_summary = data.get("executive_summary", "")

        # Build Cluster objects and assign cluster_id back to findings
        clusters: list[Cluster] = []
        for c in data.get("clusters", []):
            cluster = Cluster(
                id=c.get("id", f"cluster-{len(clusters)+1}"),
                title=c.get("title", ""),
                severity=self._parse_severity(c.get("severity", "medium")),
                summary=c.get("summary", ""),
                shared_remediation=c.get("shared_remediation", ""),
                tags=c.get("tags", []),
            )
            # Assign cluster_id to member findings
            for member_title in c.get("member_titles", []):
                for _, f in all_findings:
                    if f.title == member_title:
                        f.cluster_id = cluster.id
                        cluster.member_ids.append(self._finding_key(f))
            clusters.append(cluster)

        assessment.clusters = clusters

    @staticmethod
    def _parse_severity(s: str) -> "Severity":  # type: ignore[return]
        from vuln_scanner.tools.enums import _parse_severity
        return _parse_severity(s)
