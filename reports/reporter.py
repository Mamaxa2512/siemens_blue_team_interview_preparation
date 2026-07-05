from typing import List
from core.models import Finding

class MarkdownReporter:
    def __init__(self, filename: str = "report.md"):
        self.filename = filename

    def generate(self, findings: List[Finding]):
        with open(self.filename, "w", encoding="utf-8") as f:
            f.write("# Security Scan Report (Automated Attack Surface Analyzer)\n\n")
            f.write(f"**Total Vulnerabilities Found:** {len(findings)}\n\n")
            f.write("---\n\n")

            for idx, finding in enumerate(findings, start=1):
                f.write(f"## {idx}. [{finding.severity.name}] {finding.name}\n")
                f.write(f"**Endpoint:** `{finding.endpoint}`\n\n")
                
                f.write("### Description\n")
                f.write(f"{finding.description}\n\n")
                
                f.write("### Impact\n")
                f.write(f"{finding.impact}\n\n")
                
                # Evidence
                f.write("### Evidence\n")
                f.write("<details>\n<summary>Click to expand Request / Response</summary>\n\n")
                f.write("#### Request\n")
                f.write("```http\n")
                f.write(f"{finding.evidence.request}\n")
                f.write("```\n\n")
                
                f.write("#### Response\n")
                f.write("```http\n")
                f.write(f"{finding.evidence.response}\n")
                f.write("```\n")
                f.write("</details>\n\n")
                
                f.write("---\n\n")
