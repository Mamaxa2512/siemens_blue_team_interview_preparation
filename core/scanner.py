from enum import Enum
from typing import Any, List

from core.models import HttpClient, Finding, HttpResponse, Method, RawFinding
from core.policy import PolicyEngine


class Scanner:
    def __init__(
        self,
        http_client: HttpClient,
        policy_engine: PolicyEngine,
        passive_checks: list[Any],
    ):
        self.http_client = http_client
        self.policy_engine = policy_engine
        self.passive_checks = passive_checks

    def run(self, target_url: str) -> List[Finding]:
        response = self.http_client.request(path=target_url, method=Method.GET)
        raw_findings: List[RawFinding] = []
        enriched_findings: List[Finding] = []
        for check in self.passive_checks:
            result = check.execute(response)
            raw_findings.extend(result)
        for finding in raw_findings:
            enriched_findings.append(self.policy_engine.enrich(finding))

        return enriched_findings
