from dataclasses import dataclass
import time
from enum import Enum
from typing import Dict
from urllib.parse import urljoin
import aiohttp
import asyncio
import logging


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
    def __init__(self, base_url: str, timeout: int = 8):
        self.base_url = base_url
        self.timeout_sec = timeout
        self.session = None
        self.headers = {"User-Agent": "SecurityScanner/1.0"}

    async def get_session(self):
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(
                total=self.timeout_sec,
                connect=self.timeout_sec,
                sock_connect=self.timeout_sec,
                sock_read=self.timeout_sec,
            )
            connector = aiohttp.TCPConnector(ssl=False, limit_per_host=10)
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
        
        logging.debug(f"[HTTP] -> {method.name} {url}")

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
        except asyncio.TimeoutError as e:
            logging.error(f"[HTTP] Timeout {method.name} {url}: {e}")
            raise RuntimeError(f"Timeout during request to {url}") from e
        except aiohttp.ClientError as e:
            logging.error(f"[HTTP] Error {method.name} {url}: {e}")
            raise RuntimeError(f"Network error during request to {url}: {e}") from e

        end_time = time.perf_counter()
        time_ms = int((end_time - start_time) * 1000)
        
        logging.debug(f"[HTTP] <- {status_code} {url} ({time_ms}ms) | Body: {len(body)} bytes")

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
