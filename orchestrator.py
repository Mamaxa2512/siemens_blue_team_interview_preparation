import asyncio
import logging
from checks.disclosure import InformationDisclosureCheck
from checks.discovery import Discovery
from checks.sqli import SQLiScanner
from checks.waf import WAFCheck
from core.models import HttpClient
from core.policy import PolicyEngine
from core.scanner import Scanner
from checks.sec_headers import SecurityHeadersCheck
from reports.reporter import MarkdownReporter
from core.crawler import Crawler

class ScannerOrchestrator:
    MAX_ENDPOINTS = 40

    def __init__(self, target_url: str, timeout: int = 15, max_concurrent: int = 3):
        self.target_url = target_url
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.client = HttpClient(base_url=self.target_url, timeout=self.timeout)
        self.policy = PolicyEngine("knowledge_base/vulnerabilities.json")
        
        self.passive_checks = [SecurityHeadersCheck(), InformationDisclosureCheck()]
        self.global_checks = [Discovery(), WAFCheck()]
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
            logging.info("[*] Starting Crawler...")
            endpoints = await Crawler(target_url="/", http_client=self.client, max_pages=15).crawl()
            endpoints.add("/")
            endpoints = set(sorted(endpoints)[:self.MAX_ENDPOINTS])
            
            all_results = []
            
            # Use Semaphore to limit concurrent endpoint scans
            semaphore = asyncio.Semaphore(self.max_concurrent)
            
            logging.info(f"[*] Found {len(endpoints)} endpoints to scan. Starting Active Checks...")
            
            async def scan_endpoint(url):
                async with semaphore:
                    logging.info(f"  [>] Fuzzing endpoint: {url}")
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
