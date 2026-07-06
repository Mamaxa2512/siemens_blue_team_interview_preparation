from core.models import HttpClient, Method
import re

client = HttpClient(base_url="http://localhost:3000/")
resp = client.request(path="main.js", method=Method.GET)
found_apis = re.findall(r'(/api/[^\'" >`\?]+|/rest/[^\'" >`\?]+)', resp.body)
print(f"main.js -> {len(found_apis)} APIs")
if "/rest/products/search" in found_apis:
    print("FOUND /rest/products/search IN main.js!")
else:
    print("Not found in main.js")
    idx = resp.body.find("/rest/products/search")
    if idx != -1:
        start = max(0, idx - 50)
        end = min(len(resp.body), idx + 50)
        print(f"Context in main.js: {resp.body[start:end]}")
