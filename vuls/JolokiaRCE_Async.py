# coding:utf-8

import aiohttp

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
                    result1 = "[+] 发现jolokia相关路径状态码为200，进一步验证\n"
                    text3, code3 = await self.fetch(session, url, self.path3, proxy)

                    if 'reloadByURL' in text3 and code3 == 200:
                        result2 = f'[+] {url + self.path3 } 存在Jolokia-Logback-JNDI-RCE漏洞下'
                        return result1 + result2
                    elif 'createJNDIRealm' in text3 and code3 == 200:
                        result2 = f'[+] {url + self.path3 } 存在Jolokia-Realm-JNDI-RCE漏洞下'
                        return result1 + result2
                    else:
                        result = f"[-] {url} 未发现jolokia/list路径存在关键词，请手动验证"
                        return result1 + result
                else:
                    result = f"[-] {url} Jolokia系列RCE漏洞不存在"
                    return result
        except Exception as e:
            error = f"[error] {url} 未知错误 {e}"
            return error
    async def exp(self, url, proxies, ProxyStute):
        pass