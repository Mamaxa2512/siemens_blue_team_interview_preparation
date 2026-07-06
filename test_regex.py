import re

text = """
(`/rest/products/search?q=${e}`).pipe(W(i=>
'/api/Users/login'
"/rest/admin"
"""

found_apis = re.findall(r'[`"\'](/api/[^\'" >`\?]+|/rest/[^\'" >`\?]+)', text)
print(found_apis)
