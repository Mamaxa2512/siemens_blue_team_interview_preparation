from checks.disclosure import InformationDisclosureCheck
from checks.discovery import Discovery
from core.models import HttpClient
from core.policy import PolicyEngine
from core.scanner import Scanner
from checks.sec_headers import SecurityHeadersCheck
from reports.reporter import MarkdownReporter


def main():
    # 1. Ініціалізація базових компонентів
    client = HttpClient(
        base_url="http://localhost:3000/#/"
    )  # Можеш вказати будь-який тестовий URL
    policy = PolicyEngine("knowledge_base/vulnerabilities.json")

    # 2. Реєстрація чеків
    passive_checks = [SecurityHeadersCheck(), InformationDisclosureCheck()]
    active_checks = [Discovery()]

    # 3. Створення та запуск сканера
    scanner = Scanner(http_client= client, policy_engine= policy,passive_checks =  passive_checks, active_checks = active_checks)
    results = scanner.run(target_url="/")  # Робимо запит в корінь

    # 4. Print results
    print("====================================")
    print(f"Vulnerabilities found: {len(results)}")
    print("====================================")
    for r in results:
        print(f"[{r.severity.name}] {r.name} at {r.endpoint}")

    # 5. Generate Markdown report
    reporter = MarkdownReporter("report.md")
    reporter.generate(results)
    print("\n[+] Report saved to report.md")


if __name__ == "__main__":
    main()
