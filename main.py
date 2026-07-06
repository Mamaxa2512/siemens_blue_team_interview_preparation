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
    client = HttpClient(
        base_url="http://localhost:3000/#/"
    )  # Можеш вказати будь-який тестовий URL
    policy = PolicyEngine("knowledge_base/vulnerabilities.json")

    endpoints = Crawler(target_url= client.base_url, http_client= client).crawl()
    endpoints.add("/")


    # 2. Реєстрація чеків
    passive_checks = [SecurityHeadersCheck(), InformationDisclosureCheck()]
    active_checks = [Discovery(), SQLiScanner()]

    # 3. Створення та запуск сканера
    scanner = Scanner(
        http_client=client,
        policy_engine=policy,
        passive_checks=passive_checks,
        active_checks=active_checks,
    )

    all_results = []
    for url in endpoints:
        print(f"[*] Скануємо: {url}")
        results = scanner.run(target_url=url)
        all_results.extend(results)

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
