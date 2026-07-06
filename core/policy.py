import json


from core.models import Finding, RawFinding, Severity


class PolicyEngine:
    def __init__(self, path: str):
        with open(path, "r", encoding="utf-8") as file:
            self.kb_data = json.load(file)

    def enrich(self, raw_finding: RawFinding) -> Finding:
        try:
            vuln_data = self.kb_data[raw_finding.vuln_id]
            return Finding(
                name=vuln_data["name"],
                severity=Severity(vuln_data["severity"]),
                endpoint=raw_finding.endpoint,
                evidence=raw_finding.evidence,
                description=vuln_data["description"],
                impact=vuln_data["impact"],
            )
        except KeyError:
            return Finding(
                name=f"Unknown Vulnerability ({raw_finding.vuln_id})",
                severity=Severity.LOW,
                endpoint=raw_finding.endpoint,
                evidence=raw_finding.evidence,
                description="This vulnerability is not present in the Knowledge Base.",
                impact="Unknown",
            )
