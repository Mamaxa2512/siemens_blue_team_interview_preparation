from orchestrator import ScannerOrchestrator
from reports.reporter import MarkdownReporter

def main():
    base_url = "http://localhost:3000"
    orchestrator = ScannerOrchestrator(target_url=base_url)
    
    print(f"[*] Starting scan against {base_url}...")
    all_results = orchestrator.run_scan()

    print("====================================")
    print(f"Vulnerabilities found: {len(all_results)}")
    print("====================================")
    for r in all_results:
        print(f"[{r.severity.name}] {r.name} at {r.endpoint}")

    reporter = MarkdownReporter("report.md")
    reporter.generate(all_results)
    print("\n[+] Report saved to report.md")


if __name__ == "__main__":
    main()
