from core.models import HttpClient
from core.crawler import Crawler

client = HttpClient(base_url="http://localhost:3000/#/")
endpoints = Crawler(target_url=client.base_url, http_client=client).crawl()
print("Found endpoints:", endpoints)
