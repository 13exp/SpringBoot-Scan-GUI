# coding:utf-8
import asyncio
import random

from util import JsonMethod
from util import YamlMethod
from util import RandomUA
from util import SystemCheck

from vuls import CVE_2021_21234
from vuls import CVE_2022_22947
from vuls import CVE_2022_22963
from vuls import CVE_2022_22965
from vuls import JolokiaRCE
from vuls import JeeSpring_2023
from vuls import SnakeYAML_RCE

from vuls import CVE_2021_21234_Async
from vuls import CVE_2022_22947_Async
from vuls import CVE_2022_22963_Async
from vuls import CVE_2022_22965_Async
from vuls import JolokiaRCE_Async
from vuls import JeeSpring_2023_Async
from vuls import SnakeYAML_RCE_Async

class core:
    def __init__(self):
        self.sysType = SystemCheck.SystemType()

        self.jsonRead = JsonMethod.JsonMethod()
        self.yamlRead = YamlMethod.YamlMethod()

        self.CVE_2021_21234 = CVE_2021_21234.CVE_2021_21234()
        self.CVE_2022_22947 = CVE_2022_22947.CVE_2022_22947()
        self.CVE_2022_22963 = CVE_2022_22963.CVE_2022_22963()
        self.CVE_2022_22965 = CVE_2022_22965.CVE_2022_22965()
        self.JolokiaRCE = JolokiaRCE.JolokiaRCE()
        self.JeeSpring_2023 = JeeSpring_2023.JeeSpring_2023()
        self.SnakeYAML_RCE = SnakeYAML_RCE.SnakeYAML_RCE()

        self.CVE_2021_21234_Async = CVE_2021_21234_Async.CVE_2021_21234_Async()
        self.CVE_2022_22947_Async = CVE_2022_22947_Async.CVE_2022_22947_Async()
        self.CVE_2022_22963_Async = CVE_2022_22963_Async.CVE_2022_22963_Async()
        self.CVE_2022_22965_Async = CVE_2022_22965_Async.CVE_2022_22965_Async()
        self.JolokiaRCE_Async = JolokiaRCE_Async.JolokiaRCE_Async()
        self.JeeSpring_2023_Async = JeeSpring_2023_Async.JeeSpring_2023_Async()
        self.SnakeYAML_RCE_Async = SnakeYAML_RCE_Async.SnakeYAML_RCE_Async()

        self.time = []
        self.id = []
        self.explain = []
        self.method = []
        self.url = []
        self.Gheader = []
        self.body = []
        self.Rheader = []
        self.content = []
        self.match_condition = []
        self.match = []
        self.Reference = []
        self.extractors = []

    def JsonOrYamlData(self,vulnFile):
        type = vulnFile.split(".")[-1]
        try:
            if type == "json":
                data = self.jsonRead.JsonRead(vulnFile)
            elif type == "yaml":
                data = self.yamlRead.YamlRead(vulnFile)
            else:
                return "Core Error!None Support Type"
        except:
            return "Core Error!Read File Error"
        return data
    def YamlOrJsonModel(self,data):
        try:
            # data = self.JsonOrYamlData(vuleFile)
            self.id.append(data['id'])

            if 'info' in data and 'description' in data['info'] and data['info']['description'] != None:
                self.explain.append(data['info']['description'])
            else:
                self.explain.append("未定义")

            if 'time' in data:
                self.time.append(data['time'])
            else:
                self.time.append("未定义")

            if 'body' in (data['http'])[0]:
                self.body.append(((data['http'])[0])['body'])
            else:
                self.body.append("占位符2")

            if 'Rheader' in (data['http'])[0]:
                self.Rheader.append(((data['http'])[0])['Rheader'])
            else:
                self.Rheader.append("None")

            if 'Gheader' in (data['http'])[0]:
                self.Gheader.append(((data['http'])[0])['Gheader'])
            else:
                self.Gheader.append("None")

            if 'extractors' in (data['http'])[0]:
                self.extractors.append(((data['http'])[0])['extractors'])
            else:
                self.extractors.append("None")

            self.method.append(((data['http'])[0])['method'])
            self.url.append(((data['http'])[0])['path'])
            if 'matchers-condition' in (data['http'])[0]:
                self.match_condition.append(((data['http'])[0])['matchers-condition'])  # 匹配条件
            else:
                self.match_condition.append("and")
            # 匹配内容
            self.match.append((((data['http'])[0])['matchers']))
            return True
        except Exception as e:
            return f"数据载入错误 {e}"
    def YamlOrJsonRequest(self,vulnName,model):
        vulns = self.jsonRead.VulnsConfigRead()
        vulnPathDict = vulns["path"]["standpath"]
        self.ua = RandomUA.RandomUA()
        random_ip = "{}.{}.{}.{}".format(random.randint(1, 254), random.randint(1, 254), random.randint(1, 254),
                                         random.randint(1, 254))
        self.headers = {
            "User-Agent": self.ua.UserAgent(),
            "Accept-Language": "en",
            "X-Forwarded-For": random_ip,
            "X-Real-IP": random_ip,
        }
        vulnPath = vulnPathDict[vulnName] + "." + model
        data = self.JsonOrYamlData(vulnPath)
        dataload = self.YamlOrJsonModel(data)
    def pyScan(self,url,proxies,vulnName,ProxyStute,attack,cmd):
        if attack == "PoC":
            if vulnName == "CVE-2021-21234":
                result = self.CVE_2021_21234.poc(url,proxies,ProxyStute)
            elif vulnName == "CVE-2022-22947":
                result = self.CVE_2022_22947.poc(url,proxies,ProxyStute)
            elif vulnName == "CVE-2022-22963":
                result = self.CVE_2022_22963.poc(url,proxies,ProxyStute)
            elif vulnName == "CVE-2022-22965":
                result = self.CVE_2022_22965.poc(url,proxies,ProxyStute)
            elif vulnName == "JeeSpring-2023":
                result = self.JeeSpring_2023.poc(url,proxies,ProxyStute)
            elif vulnName == "JolokiaRCE":
                result = self.JolokiaRCE.poc(url,proxies,ProxyStute)
            elif vulnName == "SnakeYAML-RCE":
                result = self.SnakeYAML_RCE.poc(url,proxies,ProxyStute)
            else:
                result = "Error"
            return result
        elif attack == "EXP":
            if vulnName == "CVE-2021-21234":
                result = self.CVE_2021_21234.exp(url,proxies,ProxyStute,cmd)
            elif vulnName == "CVE-2022-22947":
                result = self.CVE_2022_22947.exp(url,proxies,ProxyStute,cmd)
            elif vulnName == "CVE-2022-22963":
                result = self.CVE_2022_22963.exp(url,proxies,ProxyStute,cmd)
            elif vulnName == "CVE-2022-22965":
                result = self.CVE_2022_22965.exp(url,proxies,ProxyStute,cmd)
            elif vulnName == "JeeSpring-2023":
                result = self.JeeSpring_2023.exp(url,proxies,ProxyStute,cmd)
            elif vulnName == "JolokiaRCE":
                result = self.JolokiaRCE.exp(url,proxies,ProxyStute,cmd)
            elif vulnName == "SnakeYAML-RCE":
                result = self.SnakeYAML_RCE.exp(url,proxies,ProxyStute,cmd)
            else:
                result = "Error"
            return result
    def asyncScan(self,url,proxies,vulnName,ProxyStute,attack):
        if self.sysType == "Windows":
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        if attack == "PoC":
            if vulnName == "CVE-2021-21234":
                result = asyncio.run(self.CVE_2021_21234_Async.poc(url, proxies, ProxyStute))
            elif vulnName == "CVE-2022-22947":
                result = asyncio.run(self.CVE_2022_22947_Async.poc(url, proxies, ProxyStute))
            elif vulnName == "CVE-2022-22963":
                result = asyncio.run(self.CVE_2022_22963_Async.poc(url, proxies, ProxyStute))
            elif vulnName == "CVE-2022-22965":
                result = asyncio.run(self.CVE_2022_22965_Async.poc(url, proxies, ProxyStute))
            elif vulnName == "JeeSpring-2023":
                result = asyncio.run(self.JeeSpring_2023_Async.poc(url, proxies, ProxyStute))
            elif vulnName == "JolokiaRCE":
                result = asyncio.run(self.JolokiaRCE_Async.poc(url, proxies, ProxyStute))
            elif vulnName == "SnakeYAML-RCE":
                result = asyncio.run(self.SnakeYAML_RCE_Async.poc(url, proxies, ProxyStute))
            else:
                result = "Error"
            return result
        elif attack == "EXP":
            if self.sysType == "Windows":
                asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
            if vulnName == "CVE-2021-21234":
                result = asyncio.run(self.CVE_2021_21234_Async.exp(url, proxies, ProxyStute))
            elif vulnName == "CVE-2022-22947":
                result = asyncio.run(self.CVE_2022_22947_Async.exp(url, proxies, ProxyStute))
            elif vulnName == "CVE-2022-22963":
                result = asyncio.run(self.CVE_2022_22963_Async.exp(url, proxies, ProxyStute))
            elif vulnName == "CVE-2022-22965":
                result = asyncio.run(self.CVE_2022_22965_Async.exp(url, proxies, ProxyStute))
            elif vulnName == "JeeSpring-2023":
                result = asyncio.run(self.JeeSpring_2023_Async.exp(url, proxies, ProxyStute))
            elif vulnName == "JolokiaRCE":
                result = asyncio.run(self.JolokiaRCE_Async.exp(url, proxies, ProxyStute))
            elif vulnName == "SnakeYAML-RCE":
                result = asyncio.run(self.SnakeYAML_RCE_Async.exp(url, proxies, ProxyStute))
            else:
                result = "Error"
            return result
if __name__ == "__main__":
    core = core()
    yaml_date = core.JsonOrYamlData("../vuls/CVE_2021_21234.json")
    print(yaml_date)