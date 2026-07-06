import re
from core.models import HttpClient, Method


class Crawler:
    def __init__(self, target_url: str, http_client: HttpClient):
        self.target_url = target_url
        self.http_client = http_client

    def crawl(self):
        findings = []
        response = self.http_client.request(path = self.target_url, method=Method.GET)
        findings.extend(re.findall(r'href=[\'"]?([^\'" >]+)', response.body))
        return set(findings)