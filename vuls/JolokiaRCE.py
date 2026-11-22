# coding:utf-8

import requests
from util.Translate import tr

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
                result1 = tr("v.jolokia.path")
                retest = requests.get(url=url + self.path3, timeout=10, verify=False, proxies=proxies)
                code3 = retest.status_code
                if ('reloadByURL' in str(retest.text)) and (code3 == 200):
                    result2 = tr("v.jolokia.logback", url=url + self.path3)
                    return result1 + result2
                elif ('createJNDIRealm' in str(retest.text)) and (code3 == 200):
                    result2 = tr("v.jolokia.realm", url=url + self.path3)
                    return result1 + result2
                else:
                    result = tr("v.jolokia.manual", url=url)
                    return result1 + result
            else:
                result = tr("v.jolokia.none", url=url)
                return result
        except Exception as e:
            error = tr("v.unknown", url=url, e=e)
            return error
    def exp(self,url,proxies,ProxyStute,cmd):
        pass