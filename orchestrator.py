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

    def run_scan(self):
        # Crawl from the root rather than /#/ to find all JS files
        endpoints = Crawler(target_url="/", http_client=self.client).crawl()
        endpoints.add("/")
        
        all_results = []
        for url in endpoints:
            results = self.scanner.run_endpoint_checks(target_url=url)
            all_results.extend(results)

        all_results.extend(self.scanner.run_global_checks(target_url=self.target_url))
        all_results.extend(self.scanner.run_passive(target_url=self.target_url))
        
        return all_results
