# coding:utf-8

import requests
# from util import URLMethod
# import urllib3
# import RandomUA

class ProxyCheck:
    def __init__(self):
        self.testurl = "https://www.baidu.com/"
        # self.ua_load = RandomUA.RandomUA()
        # self.ua = self.ua_load.UserAgent()
        # self.urlmethod = URLMethod.URLMethod()
        self.headers = {"User-Agent": "Mozilla/5.0"}
    def checkurl(self,proxy):
        proxies = proxy.strip("/")
        if "/" in proxies:
            proxies = proxies.split("/")[-1]
        proxies = {
                "http": "http://%(proxy)s/" % {'proxy': proxies},
                "https": "http://%(proxy)s/" % {'proxy': proxies}
                }
        try:
            requests.packages.urllib3.disable_warnings()
            res = requests.get(self.testurl, timeout=5, proxies=proxies, verify=False, headers=self.headers)
            if res.status_code == 200:
                return proxies
        except:
            return False
    def checkfile(self,proxyfile):
        proxy_list = []
        proxy_alive = []
        write_alive = []
        with open(proxyfile,"r") as f:
            proxy_file = f.read().split("\n")
            for i in proxy_file:
                if i != "":
                    i = i.strip("/")
                    if "/" in i:
                        i = i.split("/")[-1]
                    proxy_list.append(i)
        for i in proxy_list:
            proxies = {
                    "http": "http://%(proxy)s/" % {'proxy': i},
                    "https": "http://%(proxy)s/" % {'proxy': i}
                }
            try:
                requests.packages.urllib3.disable_warnings()
                res = requests.get(self.testurl, timeout=5, proxies=proxies, verify=False, headers=self.headers)
                if res.status_code == 200:
                    proxy_alive.append(proxies)
                    write_alive.append(i)
            except:
                pass
        # 刷新代理文件
        with open(proxyfile,"w") as f:
            for i in write_alive:
                f.write(i)
                f.write('\n')
        return proxy_alive
if __name__ == '__main__':
    proxy = ProxyCheck()
    url = proxy.checkurl('http://192.168.0.1/')
    print(url)
