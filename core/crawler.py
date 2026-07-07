import asyncio
import re
import logging
from urllib.parse import urljoin, urlparse, urlunparse
from core.models import HttpClient, Method


class Crawler:
    def __init__(self, target_url: str, http_client: HttpClient, max_pages: int = 25):
        self.target_url = target_url
        self.http_client = http_client
        self.max_pages = max_pages

    async def crawl(self):
        endpoints = set()
        visited_pages = set()
        pages_to_visit = [self.target_url]
        base_url = self.http_client.base_url
        base_origin = self._origin(base_url)

        def normalize_url(link: str, current_url: str) -> str | None:
            absolute = urljoin(current_url, link)
            parsed = urlparse(absolute)
            if parsed.scheme not in {"http", "https"}:
                return None
            if self._origin(absolute) != base_origin:
                return None
            return urlunparse(parsed._replace(fragment=""))

        async def fetch_html(page_url: str):
            try:
                return await self.http_client.request(path=page_url, method=Method.GET)
            except Exception as e:
                logging.error(f"Exception: {e}. \n While crawling {page_url}")
                return None

        async def fetch_and_extract_js(link):
            js_path = normalize_url(link, base_url)
            if not js_path:
                return []
            logging.info(f"  [Crawler] Extracting APIs from JS file: {js_path}")
            try:
                resp = await self.http_client.request(path=js_path, method=Method.GET)
                found_apis = re.findall(r'(/api/[^\'" >`]+|/rest/[^\'" >`]+)', resp.body)
                return found_apis
            except Exception as e:
                logging.error(f"Exception: {e}. \n While crawling {js_path}")
                return []

        while pages_to_visit and len(visited_pages) < self.max_pages:
            page_url = pages_to_visit.pop(0)
            if page_url in visited_pages:
                continue

            visited_pages.add(page_url)
            response = await fetch_html(page_url)
            if not response:
                continue

            links = re.findall(r'href=[\'"]?([^\'" >]+)', response.body, flags=re.IGNORECASE)
            scripts = re.findall(r'src=[\'"]?([^\'" >]+\.js)', response.body, flags=re.IGNORECASE)

            for link in links:
                normalized = normalize_url(link, response.path)
                if not normalized:
                    continue

                parsed = urlparse(normalized)
                path = parsed.path.lower()
                if parsed.query or path.endswith(".php") or path.startswith(("/api/", "/rest/")):
                    endpoints.add(normalized)

                if path.endswith((".html", ".htm", ".php", "/")) and normalized not in visited_pages:
                    pages_to_visit.append(normalized)

            results = await asyncio.gather(*(fetch_and_extract_js(link) for link in scripts))
            for res in results:
                endpoints.update(res)

        return endpoints

    @staticmethod
    def _origin(url: str) -> tuple[str, str, int | None]:
        parsed = urlparse(url)
        return parsed.scheme, parsed.hostname or "", parsed.port
