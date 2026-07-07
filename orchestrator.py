import asyncio
from checks.disclosure import InformationDisclosureCheck
from checks.discovery import Discovery
from checks.sqli import SQLiScanner
from core.models import HttpClient
from core.policy import PolicyEngine
from core.scanner import Scanner
from checks.sec_headers import SecurityHeadersCheck
from reports.reporter import MarkdownReporter
from core.crawler import Crawler

class ScannerOrchestrator:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.client = HttpClient(base_url=self.target_url)
        self.policy = PolicyEngine("knowledge_base/vulnerabilities.json")
        
        self.passive_checks = [SecurityHeadersCheck(), InformationDisclosureCheck()]
        self.global_checks = [Discovery()]
        self.endpoint_checks = [SQLiScanner()]
        
        self.scanner = Scanner(
            http_client=self.client,
            policy_engine=self.policy,
            passive_checks=self.passive_checks,
            global_checks=self.global_checks,
            endpoint_checks=self.endpoint_checks,
        )

    async def run_scan(self):
        try:
            # Crawl from the root rather than /#/ to find all JS files
            endpoints = await Crawler(target_url="/", http_client=self.client).crawl()
            endpoints.add("/")
            
            all_results = []
            
            # Use Semaphore to limit concurrent endpoint scans
            semaphore = asyncio.Semaphore(10)
            
            async def scan_endpoint(url):
                async with semaphore:
                    return await self.scanner.run_endpoint_checks(target_url=url)

            endpoint_tasks = [scan_endpoint(url) for url in endpoints]
            endpoint_results = await asyncio.gather(*endpoint_tasks)
            
            for res in endpoint_results:
                all_results.extend(res)

            global_results, passive_results = await asyncio.gather(
                self.scanner.run_global_checks(target_url=self.target_url),
                self.scanner.run_passive(target_url=self.target_url)
            )
            
            all_results.extend(global_results)
            all_results.extend(passive_results)
            
            return all_results
        finally:
            await self.client.close()
