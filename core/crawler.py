import re
import logging
from core.models import HttpClient, Method


class Crawler:
    def __init__(self, target_url: str, http_client: HttpClient):
        self.target_url = target_url
        self.http_client = http_client

    async def crawl(self):
        response = await self.http_client.request(path = self.target_url, method=Method.GET)
        links = re.findall(r'href=[\'"]?([^\'" >]+)', response.body)
        scripts = re.findall(r'src=[\'"]?([^\'" >]+\.js)', response.body)
        links.extend(scripts)

        js_files = [link for link in links if link.endswith(".js")]

        endpoints = set()

        from urllib.parse import urljoin
        base_target = self.target_url.split('#')[0]

        for link in js_files:
            js_path = urljoin(base_target, link)

            try:
                resp = await self.http_client.request(path=js_path, method=Method.GET)
                found_apis = re.findall(r'(/api/[^\'" >`\?]+|/rest/[^\'" >`\?]+)', resp.body)
                endpoints.update(found_apis)
            except Exception as e:
                logging.error(f"Exception: {e}. \n While crawling {js_path}")
        return endpoints