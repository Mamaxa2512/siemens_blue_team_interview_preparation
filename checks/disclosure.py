from typing import List

from core.models import HttpResponse, RawFinding, Evidence


class InformationDisclosureCheck:
    def execute(self, response: HttpResponse) -> List[RawFinding]:
        findings = []
        headers_lower = {k.lower(): v for k, v in response.headers.items()}

        if "server" in headers_lower:
            findings.append(RawFinding(
                vuln_id= "INFO-DISC-SERVER-HEADER",
                endpoint= response.path,
                evidence= Evidence(
                    request= f"GET {response.path}",
                    response= f"Server: {headers_lower['server']}",
                    parameters= ["server"]
                )
            ))
        if "x-powered-by" in headers_lower:
            findings.append(RawFinding(
                vuln_id= "INFO-DISC-X-POWERED-BY",
                endpoint= response.path,
                evidence= Evidence(
                    request= f"GET {response.path}",
                    response= f"Powered by: {headers_lower['x-powered-by']}",
                    parameters= ["x-powered-by"]
                )
            ))
        return findings

