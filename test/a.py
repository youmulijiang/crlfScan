from urllib.parse import urlparse,urljoin

url = "https://baidu.com"
print(urlparse(url))

# with open(r"src小脚本\db\crlf_payload.txt") as file:
#     for i in file:
#         print(urljoin(url,i.strip()))

import httpx

# print("content-length" in httpx.get(url).headers)
print(httpx.request("head",url).headers)

