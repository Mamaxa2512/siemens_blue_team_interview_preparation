import asyncio
import logging
from typing import Any, List

from core.models import HttpClient, Finding, Method, RawFinding
from core.policy import PolicyEngine


class Scanner:
    def __init__(
        self,
        http_client: HttpClient,
        policy_engine: PolicyEngine,
        passive_checks: list[Any],
        global_checks: list[Any],
        endpoint_checks: list[Any]
    ):
        self.http_client = http_client
        self.policy_engine = policy_engine
        self.passive_checks = passive_checks
        self.global_checks = global_checks
        self.endpoint_checks = endpoint_checks


    async def run_passive(self, target_url: str) -> List[Finding]:
        response = await self.http_client.request(path=target_url, method=Method.GET)
        raw_findings: List[RawFinding] = []
        enriched_findings: List[Finding] = []

        async def run_check(check):
            try:
                return await check.execute(response)
            except Exception as e:
                logging.error(f"Перевірка {check.__class__.__name__} впала з помилкою: {e}")
                return []

        results = await asyncio.gather(*(run_check(check) for check in self.passive_checks))
        for res in results:
            raw_findings.extend(res)

        for finding in raw_findings:
            enriched_findings.append(self.policy_engine.enrich(finding))

        return enriched_findings

    async def run_global_checks(self, target_url: str) -> List[Finding]:
        raw_findings: List[RawFinding] = []
        enriched_findings: List[Finding] = []

        async def run_check(check):
            try:
                return await check.execute(http_client=self.http_client, target_url=target_url)
            except Exception as e:
                logging.error(f"Перевірка {check.__class__.__name__} впала з помилкою: {e}")
                return []

        results = await asyncio.gather(*(run_check(check) for check in self.global_checks))
        for res in results:
            raw_findings.extend(res)

        for finding in raw_findings:
            enriched_findings.append(self.policy_engine.enrich(finding))
        return enriched_findings


    async def run_endpoint_checks(self, target_url: str) -> List[Finding]:
        raw_findings: List[RawFinding] = []
        enriched_findings: List[Finding] = []

        async def run_check(check):
            try:
                return await check.execute(http_client=self.http_client, target_url=target_url)
            except Exception as e:
                logging.error(f"Перевірка {check.__class__.__name__} впала з помилкою: {e}")
                return []

        results = await asyncio.gather(*(run_check(check) for check in self.endpoint_checks))
        for res in results:
            raw_findings.extend(res)

        for finding in raw_findings:
            enriched_findings.append(self.policy_engine.enrich(finding))
        return enriched_findings



    async def run(self, target_url: str) -> List[Finding]:
        run_passive_results = await self.run_passive(target_url)
        run_global_results = await self.run_global_checks(target_url)
        run_endpoint_results = await self.run_endpoint_checks(target_url)

        return [*run_passive_results, *run_global_results, *run_endpoint_results]
