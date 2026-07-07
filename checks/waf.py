import logging
from typing import List

from core.models import HttpClient, RawFinding, Evidence, Method


class WAFCheck:
    def __init__(self):
        # A payload that is almost guaranteed to be blocked by any decent WAF
        self.payload = "/?q=<script>alert('waf_test')</script> UNION SELECT 1,2,3--"
        
        # Common headers indicating WAF presence
        self.waf_headers = [
            "server: cloudflare",
            "server: awselb",
            "x-sucuri-id",
            "x-sucuri-cache",
            "x-iinfo",           # Imperva
            "x-cdn",             # Incapsula
            "cf-ray",            # Cloudflare
        ]

    async def execute(self, http_client: HttpClient, target_url: str) -> List[RawFinding]:
        findings = []
        if not target_url.endswith("/"):
            target_url += "/"
            
        test_url = target_url.rstrip("/") + self.payload
        
        try:
            response = await http_client.request(
                method=Method.GET, path=test_url
            )
            
            waf_detected = False
            evidence_details = ""
            
            # 1. Check for WAF-like status codes (403, 406)
            if response.code in [403, 406]:
                waf_detected = True
                evidence_details = f"Blocked with suspicious status code: {response.code}\n"
                
            # 2. Check headers
            response_headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
            
            for header_sig in self.waf_headers:
                if ":" in header_sig:
                    key, val = header_sig.split(":", 1)
                    key = key.strip()
                    val = val.strip()
                    if key in response_headers_lower and val in response_headers_lower[key]:
                        waf_detected = True
                        evidence_details += f"Found WAF Header: {key}: {response.headers.get(key, val)}\n"
                else:
                    if header_sig in response_headers_lower:
                        waf_detected = True
                        evidence_details += f"Found WAF Header: {header_sig}\n"
            
            if waf_detected:
                findings.append(
                    RawFinding(
                        vuln_id="WAF-DETECTED",
                        endpoint=target_url,
                        evidence=Evidence(
                            request=f"GET {test_url} HTTP/1.1",
                            response=evidence_details.strip() or f"HTTP {response.code}",
                            parameters=["q"],
                        )
                    )
                )
            else:
                findings.append(
                    RawFinding(
                        vuln_id="WAF-MISSING",
                        endpoint=target_url,
                        evidence=Evidence(
                            request=f"GET {test_url} HTTP/1.1",
                            response=f"HTTP {response.code} (Not blocked by WAF)",
                            parameters=["q"],
                        )
                    )
                )
                
        except Exception as e:
            logging.error(f"Error checking WAF: {e}")
            
        return findings
