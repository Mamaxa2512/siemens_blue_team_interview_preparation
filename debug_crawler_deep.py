import re
from core.models import HttpClient, Method

client = HttpClient(base_url="http://localhost:3000/#/")
response = client.request(path="/", method=Method.GET)
links = re.findall(r'href=[\'"]?([^\'" >]+)', response.body)
js_files = [link for link in links if link.endswith(".js")]

print(f"Found {len(js_files)} JS files:")
for j in js_files:
    print(f" - {j}")

endpoints = set()
base_target = "http://localhost:3000/"

for link in js_files:
    js_path = base_target + link
    try:
        resp = client.request(path=js_path, method=Method.GET)
        found_apis = re.findall(r'(/api/[^\'" >`\?]+|/rest/[^\'" >`\?]+)', resp.body)
        print(f"File {link} -> {len(found_apis)} APIs")
        if found_apis:
            # print first 5 to see what they look like
            print(f"   Examples: {found_apis[:5]}")
        
        # Look specifically for product search
        if "/rest/products/search" in resp.body:
            print(f"   !!! STRING '/rest/products/search' IS PRESENT IN {link} !!!")
            
            # test regex directly on this string context
            # find the context
            idx = resp.body.find("/rest/products/search")
            start = max(0, idx - 50)
            end = min(len(resp.body), idx + 50)
            context = resp.body[start:end]
            print(f"   Context: {context}")
            
        endpoints.update(found_apis)
    except Exception as e:
        print(f"Error on {js_path}: {e}")

print(f"Total unique endpoints: {len(endpoints)}")
if "/rest/products/search" in endpoints:
    print("SUCCESS: Found /rest/products/search in endpoints!")
else:
    print("FAILURE: /rest/products/search NOT in endpoints!")
