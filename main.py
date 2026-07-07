import asyncio
import logging
from orchestrator import ScannerOrchestrator
from reports.reporter import MarkdownReporter

async def main():
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    base_url = "https://preview.owasp-juice.shop"
    orchestrator = ScannerOrchestrator(target_url=base_url)
    
    print(f"[*] Starting scan against {base_url}...")
    all_results = await orchestrator.run_scan()

    print("====================================")
    print(f"Vulnerabilities found: {len(all_results)}")
    print("====================================")
    for r in all_results:
        print(f"[{r.severity.name}] {r.name} at {r.endpoint}")

    reporter = MarkdownReporter("report.md")
    reporter.generate(all_results)
    print("\n[+] Report saved to report.md")


if __name__ == "__main__":
    asyncio.run(main())
