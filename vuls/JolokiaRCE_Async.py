# coding:utf-8

import aiohttp
from util.Translate import tr

class JolokiaRCE_Async:
    def __init__(self):
        self.path1 = 'jolokia'
        self.path2 = 'actuator/jolokia'
        self.path3 = 'jolokia/list'

    async def fetch(self, session, url, path, proxies):
        try:
            async with session.post(url=url + path, timeout=10, allow_redirects=False, verify_ssl=False, proxies=proxies) as response:
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
                text1, code1 = await self.fetch(session, url, self.path1, proxy)
                text2, code2 = await self.fetch(session, url, self.path2, proxy)

                if int(code1) == 200 or int(code2) == 200:
                    result1 = tr("v.jolokia.path")
                    text3, code3 = await self.fetch(session, url, self.path3, proxy)

                    if 'reloadByURL' in text3 and code3 == 200:
                        result2 = tr("v.jolokia.logback", url=url + self.path3)
                        return result1 + result2
                    elif 'createJNDIRealm' in text3 and code3 == 200:
                        result2 = tr("v.jolokia.realm", url=url + self.path3)
                        return result1 + result2
                    else:
                        result = tr("v.jolokia.manual", url=url)
                        return result1 + result
                else:
                    result = tr("v.jolokia.none", url=url)
                    return result
        except Exception as e:
            error = tr("v.unknown", url=url, e=e)
            return error
    async def exp(self, url, proxies, ProxyStute):
        pass