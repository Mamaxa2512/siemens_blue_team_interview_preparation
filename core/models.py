from dataclasses import dataclass
import time
from enum import Enum
from typing import Dict
from urllib.parse import urljoin
import aiohttp
import asyncio
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
        self.timeout_sec = timeout
        self.session = None
        self.headers = {"User-Agent": "SecurityScanner/1.0"}

    async def get_session(self):
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=self.timeout_sec)
            connector = aiohttp.TCPConnector(ssl=False)
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers=self.headers,
                connector=connector
            )
        return self.session

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()

    async def request(self, method: Method, path: str, json: dict = None, **kwargs) -> HttpResponse:
        url = urljoin(self.base_url, path)
        start_time = time.perf_counter()
        session = await self.get_session()

        try:
            if method == Method.GET:
                async with session.get(url, **kwargs) as resp:
                    body = await resp.text()
                    status_code = resp.status
                    headers = dict(resp.headers)
            elif method == Method.POST:
                async with session.post(url, json=json, **kwargs) as resp:
                    body = await resp.text()
                    status_code = resp.status
                    headers = dict(resp.headers)
            else:
                raise NotImplementedError(f"Method {method.name} is not supported")
        except aiohttp.ClientError as e:
            raise RuntimeError(f"Network error during request to {url}: {e}")

        end_time = time.perf_counter()
        time_ms = int((end_time - start_time) * 1000)

        return HttpResponse(
            code=status_code,
            body=body,
            headers=headers,
            time_ms=time_ms,
            path=url,
        )


@dataclass(frozen=True)
class RawFinding:
    vuln_id: str
    endpoint: str
    evidence: Evidence
