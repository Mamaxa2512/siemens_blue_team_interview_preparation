import json


from core.models import Finding, RawFinding, Severity


class PolicyEngine:
    def __init__(self, path: str):
        with open(path, "r", encoding="utf-8") as file:
            self.kb_data = json.load(file)

    def enrich(self, raw_finding: RawFinding) -> Finding:
        return Finding(
            name=self.kb_data[raw_finding.vuln_id]["name"],
            severity=Severity(self.kb_data[raw_finding.vuln_id]["severity"]),
            endpoint=raw_finding.endpoint,
            evidence=raw_finding.evidence,
            description=self.kb_data[raw_finding.vuln_id]["description"],
            impact=self.kb_data[raw_finding.vuln_id]["impact"],
        )
