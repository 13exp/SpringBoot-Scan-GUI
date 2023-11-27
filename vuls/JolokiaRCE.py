# coding:utf-8

import requests

class JolokiaRCE:
    def __init__(self):
        self.path1 = 'jolokia'
        self.path2 = 'actuator/jolokia'
        self.path3 = 'jolokia/list'
    def poc(self,url,proxies,ProxyStute):
        if ProxyStute == 1:
            proxies = proxies
        else:
            proxies = None
        try:
            requests.packages.urllib3.disable_warnings()

            re1 = requests.post(url=url + self.path1, timeout=10, allow_redirects=False, verify=False, proxies=proxies)
            re2 = requests.post(url=url + self.path2, timeout=10, allow_redirects=False, verify=False, proxies=proxies)

            code1 = re1.status_code
            code2 = re2.status_code
            if ((int(code1) == 200) or (int(code2) == 200)):
                result1  = "[+] 发现jolokia相关路径状态码为200，进一步验证\n"
                retest = requests.get(url=url + self.path3, timeout=10, verify=False, proxies=proxies)
                code3 = retest.status_code
                if ('reloadByURL' in str(retest.text)) and (code3 == 200):
                    result2 = f'[+] {url+ self.path3 } 存在Jolokia-Logback-JNDI-RCE漏洞下'
                    return result1 + result2
                elif ('createJNDIRealm' in str(retest.text)) and (code3 == 200):
                    result2 = f'[+] {url+ self.path3 } 存在Jolokia-Realm-JNDI-RCE漏洞下'
                    return result1 + result2
                else:
                    result = f"[-] {url} 未发现jolokia/list路径存在关键词，请手动验证"
                    return result1 + result
            else:
                result = f"[-] {url}Jolokia系列RCE漏洞不存在"
                return result
        except Exception as e:
            error = f"[error] {url} 未知错误 {e}"
            return error
    def exp(self,url,proxies,ProxyStute,cmd):
        pass