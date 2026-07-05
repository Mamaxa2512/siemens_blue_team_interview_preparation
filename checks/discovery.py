import logging
from typing import List


from core.models import HttpClient, RawFinding, Evidence, Method


class Discovery:
    def __init__(self, wordlist=None):
        self.wordlist = wordlist or [".git/config", ".env", "admin/", "backup.zip", ".venv"]

    def execute(self, http_client: HttpClient, target_url: str) -> List[RawFinding]:
        findings = []
        if not target_url.endswith("/"):
            target_url += "/"
        for word in self.wordlist:
            try:
                response = http_client.request(method=Method.GET, path=target_url+word)
                if 200 <= response.code < 300:
                    findings.append(RawFinding(
                        vuln_id="DISCOVERY-HIDDEN-DIR",
                        endpoint= target_url + word,
                        evidence= Evidence(
                            request= f"GET {target_url+word} HTTP/1.1",
                            response= "200 OK",
                            parameters=[]
                        )
                    ))
            except Exception as e:
                logging.error(f"Error: {e} on word: {word}")
        return findings





