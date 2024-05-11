try:
    import httpx
    from httpx import Response
    import asyncio
    import argparse
    from urllib.parse import urljoin,urlparse
    import os
    # from pprint import pprint
    import json

    from colorama import Fore,init
    init(autoreset=True)
except ImportError as e:
    print(e)
    import subprocess
    result = subprocess.run("pip install -r requirements.txt",shell=True,encoding="utf-8")
    result.check_returncode()

ua_header = {
    "User-Agent": "Mozilla/5.0(Windows NT 10.0;Win64;x64) AppleWebKit/537.36 (KHTML, likeGecko) Chrome/98.0.4758.102 Safari/537.36 MicroMessenger/7.0.20.1781 (0x6780143B )NetType/WIFI MiniProgramEnv/windowsWindowsWechat/WMPF XWEB/6945"
}

banner = """ 
             _    ___ ______                   
            | |  / __) _____)                  
  ____  ____| |_| |_( (____   ____ _____ ____  
 / ___)/ ___) (_   __)____ \ / ___|____ |  _ \ 
( (___| |   | | | |  _____) | (___/ ___ | | | |
 \____)_|    \_)|_| (______/ \____)_____|_| |_|
                                               
                                        
     """

parse = argparse.ArgumentParser()
# parse.epilog = banner
print(Fore.LIGHTRED_EX+banner)

mutually_parse = parse.add_mutually_exclusive_group()
# mutually_parse.add_argument("-u","--url",type=str,metavar="URL",help="指定url")
# mutually_parse.add_argument("-l","--url-list",type=str,metavar="URL-LIST",help="请指定url列表")
# parse.add_argument("-w","--wordlist",type=str,metavar="WORDLIST",help="请指定攻击payload")
# parse.add_argument("--header",metavar="HEADER",type=str,help="指定http头部",default=ua_header)
# parse.add_argument("--cookies",metavar="COOKIES",type=str,help="指定cookies")
# parse.add_argument("--proxy",type=str,metavar='',help="指定代理地址")
# parse.add_argument("-v",help="显示报文信息",action="store_true")

mutually_parse.add_argument("-u", "--url", type=str, metavar="URL", help="specify the URL")
mutually_parse.add_argument("-l", "--url-list", type=str, metavar="URL-LIST", help=" specify the URL list")
parse.add_argument("-w", "--wordlist", type=str, metavar="WORDLIST", help=" specify the attack payload")
parse.add_argument("--header", metavar="HEADER", type=str, help="specify the HTTP header", default=ua_header)
parse.add_argument("--cookies", metavar="COOKIES", type=str, help="specify cookies")
parse.add_argument("--proxy",type=str,metavar='',help="specify the proxy address")
parse.add_argument("-v",help="Displays details",action="store_true")

args = parse.parse_args()

payload_list = []

wordlist = args.wordlist

if (args.wordlist == None):
    wordlist = r'db\crlf_payload.txt' 

with open(wordlist) as file:
    if not os.path.exists(wordlist):
        raise FileExistsError(f"{wordlist}文件不存在")
    for i in file:
        payload_list.append(i.strip())

async def clrfscan(url,method="HEAD",headers=args.header,cookies=args.cookies):
    if args.proxy != None:
        timeout = 6000
    else:
        timeout = 30

    # headers =headers if args. == None else headers
    async with httpx.AsyncClient(follow_redirects=True,proxies=args.proxy,cookies=cookies,headers=headers,verify=False,timeout=timeout) as client:
        result:Response = await client.request(method,url)
        if args.v:
        #     print(Fore.GREEN+f"扫描了{result.url}")
        #     print(Fore.LIGHTCYAN_EX+f"返回包报文是:{json.dumps(dict(result.headers),indent=True)}")
        # # print(result.url)
        # if "Header-Test" in result.headers:
        #     print(Fore.RED + f"{result.url}存在crlf注入漏洞\n")
        # else:
        #     print(Fore.BLUE + f"{result.url}不存在crlf注入漏洞\n")
            print(Fore.GREEN+f"Scanned {result.url}")
            print(Fore.LIGHTCYAN_EX+f"Response packet: {json.dumps(dict(result.headers),indent=True)}")
            # print(result.url)
        if "Header-Test" in result.headers:
            print(Fore.RED + f"{result.url} has CRLF injection vulnerability\n")
        else:
            print(Fore.BLUE + f"{result.url} does not have CRLF injection vulnerability\n")
                
async def scan_url(url):
    payloads = list(map(lambda payload: urljoin(url, payload), payload_list))
    await asyncio.gather(*[asyncio.create_task(clrfscan(url)) for url in payloads])

async def scan_url_list(url_file):
    with open(url_file,"r") as file:
        for url in file:
            await scan_url(url.strip())

if __name__ == '__main__':
    # print(Fore.LIGHTRED_EX+ banner)
    # print(args._get_kwargs())

    if urlparse(args.url).netloc == "":
        args.url = "http://" + args.url
    
    try:
        if args.url != None:
            asyncio.run(scan_url(args.url))

        if args.url_list != None:
            asyncio.run(scan_url_list(args.url_list))
    except KeyboardInterrupt:
        print("KeyboardInterrupt")

        
    
        

    