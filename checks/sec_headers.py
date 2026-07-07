from typing import List

from core.models import Evidence, HttpResponse, RawFinding


class SecurityHeadersCheck:
    async def execute(self, response: HttpResponse) -> List[RawFinding]:
        findings = []
        headers_lower = {k.lower(): v for k, v in response.headers.items()}

        if "strict-transport-security" not in headers_lower:
            findings.append(
                RawFinding(
                    vuln_id="SEC-HDR-HSTS-MISSING",
                    endpoint=response.path,
                    evidence=Evidence(
                        request=f"GET {response.path}",
                        response="Header 'Strict-Transport-Security' is missing",
                        parameters=["strict-transport-security"],
                    ),
                )
            )
        elif "max-age=0" in headers_lower["strict-transport-security"].lower().replace(
            " ", ""
        ):
            findings.append(
                RawFinding(
                    vuln_id="SEC-HDR-HSTS-MISCONF",
                    endpoint=response.path,
                    evidence=Evidence(
                        request=f"GET {response.path}",
                        response=f"Strict-Transport-Security: {headers_lower['strict-transport-security']}",
                        parameters=["strict-transport-security"],
                    ),
                )
            )

        if "x-frame-options" not in headers_lower:
            findings.append(
                RawFinding(
                    vuln_id="SEC-HDR-XFO-MISSING",
                    endpoint=response.path,
                    evidence=Evidence(
                        request=f"GET {response.path}",
                        response="Header 'X-Frame-Options' is missing",
                        parameters=[],
                    ),
                )
            )
        else:
            xfo = headers_lower["x-frame-options"].upper().strip()
            if xfo not in ["DENY", "SAMEORIGIN"]:
                findings.append(
                    RawFinding(
                        vuln_id="SEC-HDR-XFO-MISCONF",
                        endpoint=response.path,
                        evidence=Evidence(
                            request=f"GET {response.path}",
                            response=f"X-Frame-Options: {headers_lower['x-frame-options']}",
                            parameters=["x-frame-options"],
                        ),
                    )
                )

        if "x-content-type-options" not in headers_lower:
            findings.append(
                RawFinding(
                    vuln_id="SEC-HDR-XCTO-MISSING",
                    endpoint=response.path,
                    evidence=Evidence(
                        request=f"GET {response.path}",
                        response="Header 'X-Content-Type-Options' is missing",
                        parameters=[],
                    ),
                )
            )
        elif headers_lower["x-content-type-options"].lower().strip() != "nosniff":
            findings.append(
                RawFinding(
                    vuln_id="SEC-HDR-XCTO-MISCONF",
                    endpoint=response.path,
                    evidence=Evidence(
                        request=f"GET {response.path}",
                        response=f"X-Content-Type-Options: {headers_lower['x-content-type-options']}",
                        parameters=["x-content-type-options"],
                    ),
                )
            )

        if "content-security-policy" not in headers_lower:
            findings.append(
                RawFinding(
                    vuln_id="SEC-HDR-CSP-MISSING",
                    endpoint=response.path,
                    evidence=Evidence(
                        request=f"GET {response.path}",
                        response="Header 'Content-Security-Policy' is missing",
                        parameters=[],
                    ),
                )
            )

        return findings
