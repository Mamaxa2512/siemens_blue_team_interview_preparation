from typing import List

from core.models import Finding, Severity, Evidence, HttpResponse


class SecurityHeadersCheck:
    def execute(self, response: HttpResponse) -> List[Finding]:
        findings = []
        headers_lower = {k.lower(): v for k, v in response.headers.items()}

        if "strict-transport-security" not in headers_lower:
            findings.append(Finding(
                name="Missing Strict-Transport-Security Header",
                severity=Severity.MEDIUM,
                endpoint=response.path,
                evidence=Evidence(
                    request=f"GET {response.path}",
                    response="Header 'Strict-Transport-Security' is missing",
                    parameters=[]
                ),
                description="The application does not enforce HSTS.",
                impact="Users are vulnerable to Man-in-the-Middle attacks."
            ))
        elif "max-age=0" in headers_lower["strict-transport-security"].lower().replace(" ", ""):
            findings.append(Finding(
                name="Misconfigured Strict-Transport-Security",
                severity=Severity.MEDIUM,
                endpoint=response.path,
                evidence=Evidence(
                    request=f"GET {response.path}",
                    response=f"Strict-Transport-Security: {headers_lower['strict-transport-security']}",
                    parameters=["strict-transport-security"]
                ),
                description="HSTS is disabled by setting max-age to 0.",
                impact="Users are vulnerable to Man-in-the-Middle attacks."
            ))

        if "x-frame-options" not in headers_lower:
            findings.append(Finding(
                name="Missing X-Frame-Options Header",
                severity=Severity.MEDIUM,
                endpoint=response.path,
                evidence=Evidence(
                    request=f"GET {response.path}",
                    response="Header 'X-Frame-Options' is missing",
                    parameters=[]
                ),
                description="The application does not protect against clickjacking.",
                impact="Attackers can embed the application in an iframe to trick users."
            ))
        else:
            xfo = headers_lower["x-frame-options"].upper().strip()
            if xfo not in ["DENY", "SAMEORIGIN"]:
                findings.append(Finding(
                    name="Misconfigured X-Frame-Options",
                    severity=Severity.LOW,
                    endpoint=response.path,
                    evidence=Evidence(
                        request=f"GET {response.path}",
                        response=f"X-Frame-Options: {headers_lower['x-frame-options']}",
                        parameters=["x-frame-options"]
                    ),
                    description="X-Frame-Options is not set to DENY or SAMEORIGIN.",
                    impact="Potential clickjacking vulnerability."
                ))

        if "x-content-type-options" not in headers_lower:
            findings.append(Finding(
                name="Missing X-Content-Type-Options Header",
                severity=Severity.LOW,
                endpoint=response.path,
                evidence=Evidence(
                    request=f"GET {response.path}",
                    response="Header 'X-Content-Type-Options' is missing",
                    parameters=[]
                ),
                description="The application does not prevent MIME sniffing.",
                impact="Browsers may execute files as unexpected types."
            ))
        elif headers_lower["x-content-type-options"].lower().strip() != "nosniff":
            findings.append(Finding(
                name="Misconfigured X-Content-Type-Options",
                severity=Severity.LOW,
                endpoint=response.path,
                evidence=Evidence(
                    request=f"GET {response.path}",
                    response=f"X-Content-Type-Options: {headers_lower['x-content-type-options']}",
                    parameters=["x-content-type-options"]
                ),
                description="X-Content-Type-Options is not set to 'nosniff'.",
                impact="Browsers may execute files as unexpected types."
            ))

        if "content-security-policy" not in headers_lower:
            findings.append(Finding(
                name="Missing Content-Security-Policy Header",
                severity=Severity.MEDIUM,
                endpoint=response.path,
                evidence=Evidence(
                    request=f"GET {response.path}",
                    response="Header 'Content-Security-Policy' is missing",
                    parameters=[]
                ),
                description="The application does not implement a CSP.",
                impact="Increased risk of Cross-Site Scripting (XSS) and data injection."
            ))

        return findings