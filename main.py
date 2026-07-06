from checks.disclosure import InformationDisclosureCheck
from checks.discovery import Discovery
from checks.sqli import SQLiScanner
from core.models import HttpClient
from core.policy import PolicyEngine
from core.scanner import Scanner
from checks.sec_headers import SecurityHeadersCheck
from reports.reporter import MarkdownReporter
from core.crawler import Crawler


def main():
    # 1. Ініціалізація базових компонентів
    base_url = "http://localhost:3000"
    client = HttpClient(
        base_url=base_url
    )  # Можеш вказати будь-який тестовий URL
    policy = PolicyEngine("knowledge_base/vulnerabilities.json")

    # Crawl from the root rather than /#/ to find all JS files
    endpoints = Crawler(target_url="/", http_client= client).crawl()
    endpoints.add("/")


    # 2. Реєстрація чеків
    passive_checks = [SecurityHeadersCheck(), InformationDisclosureCheck()]
    global_checks = [Discovery()]
    endpoint_checks = [SQLiScanner()]

    # 3. Створення та запуск сканера
    scanner = Scanner(
        http_client=client,
        policy_engine=policy,
        passive_checks=passive_checks,
        global_checks=global_checks,
        endpoint_checks=endpoint_checks,
    )

    all_results = []
    for url in endpoints:
        print(f"[*] Скануємо: {url}")
        results = scanner.run_endpoint_checks(target_url=url)
        all_results.extend(results)

    all_results.extend(scanner.run_global_checks(target_url=base_url))
    all_results.extend(scanner.run_passive(target_url=base_url))
    # 4. Print results
    print("====================================")
    print(f"Vulnerabilities found: {len(all_results)}")
    print("====================================")
    for r in all_results:
        print(f"[{r.severity.name}] {r.name} at {r.endpoint}")

    # 5. Generate Markdown report
    reporter = MarkdownReporter("report.md")
    reporter.generate(all_results)
    print("\n[+] Report saved to report.md")


if __name__ == "__main__":
    main()
