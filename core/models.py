from dataclasses import dataclass
import time
from enum import Enum
from typing import Dict
from urllib.parse import urljoin
import requests
from requests.exceptions import RequestException
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Evidence:
    def __init__(self, request, response, parameters):
        self.request = request
        self.response = response
        self.parameters = parameters


class Finding:
    def __init__(
        self,
        name: str,
        severity: Severity,
        endpoint: str,
        evidence: Evidence,
        description: str,
        impact: str,
    ):
        self.name = name
        self.severity = severity
        self.endpoint = endpoint
        self.evidence = evidence
        self.description = description
        self.impact = impact


@dataclass(frozen=True)
class HttpResponse:
    code: int
    body: str
    headers: Dict[str, str]
    time_ms: int
    path: str


class Method(Enum):
    GET = "GET"
    POST = "POST"


class HttpClient:
    def __init__(self, base_url: str, timeout: int = 10):
        self.base_url = base_url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "SecurityScanner/1.0"})

    def request(self, method: Method, path: str, json: dict = None, **kwargs) -> HttpResponse:
        url = urljoin(self.base_url, path)
        start_time = time.perf_counter()

        try:
            if method == Method.GET:
                resp = self.session.get(url, timeout=self.timeout, verify=False, **kwargs)
            elif method == Method.POST:
                resp = self.session.post(url, timeout=self.timeout, verify=False, json=json, **kwargs)
            else:
                raise NotImplementedError(f"Method {method.name} is not supported")
        except RequestException as e:
            raise RuntimeError(f"Network error during request to {url}: {e}")

        end_time = time.perf_counter()
        time_ms = int((end_time - start_time) * 1000)

        return HttpResponse(
            code=resp.status_code,
            body=resp.text,
            headers=dict(resp.headers),
            time_ms=time_ms,
            path=url,
        )


@dataclass(frozen=True)
class RawFinding:
    vuln_id: str
    endpoint: str
    evidence: Evidence
