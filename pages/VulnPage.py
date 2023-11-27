# coding:utf-8
import threading
from tkinter import messagebox, ttk, filedialog

import tkinter.font as tkFont
import tkinter as tk

# try:
from core import core
# except:
# messagebox.showerror("错误","core加载出错，请检查杀毒软件是否删除文件！")

from util import SystemCheck
from util import URLMethod
from util import RandomUA
from util import JsonMethod
from util import InputCheck
from util import ProxyCheck
from util import LogsMethod

from com import Banner

class VulnPage:
    def __init__(self, windows):
        # 操作系统类型
        self.sysType = SystemCheck.SystemType()
        # 功能中proxy logs载入配置
        self.urlmethod = URLMethod.URLMethod()

        self.log = LogsMethod.LogsMethod()

        self.vulns = JsonMethod.JsonMethod()

        self.proxyCheck = ProxyCheck.ProxyCheck()
        # 加载扫描核心
        self.core = core.core()
        self.vulnconfig = self.vulns.VulnsConfigRead()
        self.pocpath = self.vulnconfig["vulns"]['pocList']
        self.exppath = self.vulnconfig["vulns"]['expList']
        self.standmodel = self.vulnconfig["model"]["standmodel"]
        self.asyncmodel = self.vulnconfig["model"]["asyncmodel"]
        # 漏洞扫描
        tk.Label(windows, text="URL").place(x=50, y=30)
        tk.Label(windows, text="User-Agent").place(x=20, y=60)
        tk.Label(windows, text="PoC").place(x=55, y=90)

        tk.Button(windows, text="浏览", fg="white", bg="gray", activeforeground="white", command=self.urlsPath,
                  activebackground="black", cursor="hand2").place(x=550, y=25)

        # 漏洞扫描控件
        self.pocurl = tk.Entry(windows, width=60, bg='Ivory')
        self.pocurl.place(x=100, y=30)

        self.User_Agent_EXP = ttk.Combobox(windows, width=58)
        ua_list = ['自动']
        self.ua = RandomUA.RandomUA()
        uas = self.ua.UserAgentList(100)
        for i in uas:
            ua_list.append(i)
        self.User_Agent_EXP['value'] = ua_list
        self.User_Agent_EXP.current(0)
        self.User_Agent_EXP.place(x=100, y=60)

        self.info_pocs = ttk.Combobox(windows, width=58)
        self.info_pocs['value'] = self.pocpath
        self.info_pocs.current(0)
        self.info_pocs.place(x=100, y=90)

        self.BtnPoC = tk.Button(windows, text="扫描", width=15, fg="white", font=tkFont.Font(size=12),command=self.btnPoC,
                  height=1, bg="gray", activeforeground="white", activebackground="black", cursor="hand2")
        self.BtnPoC.place(x=250, y=118)
        # 反馈框
        self.vbar_poc = ttk.Scrollbar(windows)
        self.info_text_poc = tk.Text(windows, width=80, height=30, yscrollcommand=self.vbar_poc.set)
        self.info_text_poc.place(x=30, y=150)
        self.info_text_poc.insert(tk.INSERT, Banner.PoC())
        self.vbar_poc.config(command=self.info_text_poc.yview)
        self.vbar_poc.pack(side=tk.RIGHT, fill="y")

        # 漏洞利用
        tk.Button(windows, text="浏览", fg="white", bg="gray", activeforeground="white", command=self.ExpPath,
                  activebackground="black", cursor="hand2").place(x=1135, y=25)

        tk.Label(windows, text="利用地址").place(x=610, y=30)
        self.url_exp = tk.Entry(windows, width=60, bg='Ivory')
        self.url_exp.place(x=700, y=30)

        tk.Label(windows, text="执行命令").place(x=610, y=60)
        self.cmd_exp = tk.Entry(windows, width=60, bg='Ivory')
        self.cmd_exp.place(x=700, y=60)
        self.cmd_exp.insert(0, "whoami")

        tk.Label(windows, text="EXP").place(x=610, y=90)

        self.info_exps = ttk.Combobox(windows, width=58)
        self.info_exps['value'] = self.exppath
        self.info_exps.current(0)
        self.info_exps.place(x=700, y=90)

        self.BtnEXP = tk.Button(windows, text="EXP", width=15, fg="white", font=tkFont.Font(size=12),command=self.btnEXP,
                  height=1, bg="gray", activeforeground="white", activebackground="black", cursor="hand2")
        self.BtnEXP.place(x=850, y=118)
        # 反馈框
        self.vbar_exp = ttk.Scrollbar(windows)
        self.info_text_exp = tk.Text(windows, width=80, height=30, yscrollcommand=self.vbar_exp.set)
        self.info_text_exp.place(x=610, y=150)
        self.info_text_exp.insert(tk.INSERT, Banner.EXP())
        self.vbar_exp.config(command=self.info_text_exp.yview)
        self.vbar_exp.pack(side=tk.LEFT, fill="y")
        # 刷新按钮
        tk.Button(windows, text="F", fg="white", bg="gray", activeforeground="white", command=self.RefreshVar,
                  activebackground="black", cursor="hand2").place(x=30, y=85)
    def RefreshVar(self):
        self.vulnconfig = self.vulns.VulnsConfigRead()
        self.pocpath = self.vulnconfig["vulns"]['pocList']
        self.exppath = self.vulnconfig["vulns"]['expList']
        self.info_pocs['value'] = self.pocpath
        self.info_pocs.current(0)
        self.info_exps['value'] = self.exppath
        self.info_exps.current(0)
    def PoC(self):
        self.BtnPoC.config(state='disable')
        attack = "PoC"
        # 日志功能
        log = self.vulns.LogsConfigRead()
        logSwitch = log['switch']
        # 代理配置
        proxy = self.vulns.ProxyConfigRead()
        ProxyStute = proxy["switch"]
        proxies = proxy['ip'] + ":" + proxy['port']
        proxies = {
            "http": "http://%(proxy)s/" % {'proxy': proxies},
            "https": "http://%(proxy)s/" % {'proxy': proxies}
        }
        # 重新加载配置
        self.vulnconfig = self.vulns.VulnsConfigRead()

        self.pocpath = self.vulnconfig["vulns"]['pocList']
        self.exppath = self.vulnconfig["vulns"]['expList']

        self.vulnpath = self.vulnconfig["path"]
        self.standpath = self.vulnpath["standpath"]
        self.asyncpath = self.vulnpath["asyncpath"]

        model = self.vulnconfig["modelSet"]

        ua = self.User_Agent_EXP.get()
        poc = self.info_pocs.get()
        cmd = self.cmd_exp.get()
        pymodel = self.standmodel[0]
        jsonmodel = self.standmodel[1]
        yamlmodel = self.standmodel[2]
        asyncmodel = self.asyncmodel
        if ua == "自动":
            ua = self.ua.UserAgent()
        check = self.PoCInputCheck()
        if check == False:
            messagebox.showerror("错误", "URL信息错误！")
        else:
            # 载入地址
            List_Url = []
            if check[0] == "isFile":
                urls = check[-1]
                for i in urls:
                    i = self.urlmethod.StandURL(i)
                    List_Url.append(i)
            else:
                url = self.urlmethod.StandURL(check[-1])
                List_Url.append(url)
            if model == pymodel:
                for i in List_Url:
                    try:
                        data = self.core.pyScan(i,proxies,poc,ProxyStute,attack,cmd)
                        self.info_text_poc.insert(tk.INSERT, data)
                        self.info_text_poc.insert(tk.INSERT, '\n')
                    except Exception as e:
                        data = f"未知错误 {e}"
                        self.info_text_poc.insert(tk.INSERT, data)
                        self.info_text_poc.insert(tk.INSERT, '\n')
                    if logSwitch == 1:
                        if "error" not in data:
                            self.log.vulnlogs(data)
                        else:
                            self.log.errorlogs(data)
            elif model == asyncmodel:
                for i in List_Url:
                    try:
                        data = self.core.asyncScan(i,proxies,poc,ProxyStute,attack)
                        self.info_text_poc.insert(tk.INSERT, data)
                        self.info_text_poc.insert(tk.INSERT, '\n')
                    except Exception as e:
                        data = f"未知错误 {e}"
                        self.info_text_poc.insert(tk.INSERT, data)
                        self.info_text_poc.insert(tk.INSERT, '\n')
                    if logSwitch == 1:
                        if "error" not in data:
                            self.log.vulnlogs(data)
                        else:
                            self.log.errorlogs(data)
            elif model == jsonmodel or model == yamlmodel:
                for i in List_Url:
                    data = self.core.YamlOrJsonRequest(poc,model)
                    self.info_text_poc.insert(tk.INSERT, data)
                    self.info_text_poc.insert(tk.INSERT, '\n')
                    if logSwitch == 1:
                        self.log.vulnlogs(data)
            else:
                return messagebox.showerror("错误", "model type error!\nYou can view the vulns.json and try again!")
        self.BtnPoC.config(state='normal')
    def EXP(self):
        self.BtnEXP.config(state='disable')
        attack = "EXP"
        # 日志功能
        log = self.vulns.LogsConfigRead()
        logSwitch = log['switch']
        # 代理配置
        proxy = self.vulns.ProxyConfigRead()
        ProxyStute = proxy["switch"]
        proxies = proxy['ip'] + ":" + proxy['port']
        proxies = {
            "http": "http://%(proxy)s/" % {'proxy': proxies},
            "https": "http://%(proxy)s/" % {'proxy': proxies}
        }
        # 重新加载配置
        self.vulnconfig = self.vulns.VulnsConfigRead()

        self.pocpath = self.vulnconfig["vulns"]['pocList']
        self.exppath = self.vulnconfig["vulns"]['expList']

        self.vulnpath = self.vulnconfig["path"]
        self.standpath = self.vulnpath["standpath"]
        self.asyncpath = self.vulnpath["asyncpath"]

        pymodel = self.standmodel[0]
        asyncmodel = self.asyncmodel

        model = self.vulnconfig["modelSet"]

        ua = self.User_Agent_EXP.get()
        exp = self.info_exps.get()
        cmd = self.cmd_exp.get()
        if ua == "自动":
            ua = self.ua.UserAgent()
        check = self.EXPInputCheck()
        if check == False:
            messagebox.showerror("错误", "URL或命令信息错误！")
        else:
            # 载入地址
            List_Url = []
            if check[0] == "isFile":
                urls = check[-1]
                for i in urls:
                    i = self.urlmethod.StandURL(i)
                    List_Url.append(i)
            else:
                url = self.urlmethod.StandURL(check[-1])
                List_Url.append(url)
            if model == pymodel:
                for i in List_Url:
                    data = self.core.pyScan(i,proxies,exp,ProxyStute,attack,cmd)
                    self.info_text_exp.insert(tk.INSERT, data)
                    self.info_text_exp.insert(tk.INSERT, '\n')
                    if logSwitch == 1:
                        if "error" not in data:
                            self.log.vulnlogs(data)
                        else:
                            self.log.errorlogs(data)
            elif model == asyncmodel:
                for i in List_Url:
                    data = self.core.asyncScan(i,proxies,exp,ProxyStute,attack)
                    self.info_text_exp.insert(tk.INSERT, data)
                    self.info_text_exp.insert(tk.INSERT, '\n')
                    if logSwitch == 1:
                        if "error" not in data:
                            self.log.vulnlogs(data)
                        else:
                            self.log.errorlogs(data)
            else:
                return messagebox.showerror("错误","model type error!noly support py or async!\nYou can change model in the vulns.json and try again!")
        self.BtnEXP.config(state='normal')
    def btnPoC(self):
        try:
            threadFofa = threading.Thread(target=self.PoC)
            threadFofa.setDaemon(True)
            threadFofa.start()
            # threadFofa.join()
        except Exception as e:
            messagebox.showinfo('error', f'unkown error\n{e}')
    def btnEXP(self):
        try:
            threadFofa = threading.Thread(target=self.EXP)
            threadFofa.setDaemon(True)
            threadFofa.start()
            # threadFofa.join()
        except Exception as e:
            messagebox.showinfo('error', f'unkown error\n{e}')
       # messagebox.showinfo("提示","因不可抗因素，功能未开放······")
    def PoCInputCheck(self):
        check = InputCheck.InputCheck()
        url = self.pocurl.get()
        url_check = check.isNull(url)
        if url_check == True:
            return False
        else:
            url_check = check.FileOrUrl(url)
            if url_check == "isFile":
                with open(url, 'r') as f:
                    urls = f.read().strip('\n').split("\n")
                    return ["isFile", urls]
            elif url_check == "isURL":
                return ["isURL", url]
            else:
                return False

    def EXPInputCheck(self):
        check = InputCheck.InputCheck()
        url = self.url_exp.get()
        cmd = self.cmd_exp.get()
        url_check = check.isNull(url)
        cmd_check = check.isNull(cmd)
        if url_check == True or cmd_check == True:
            return False
        else:
            url_check = check.FileOrUrl(url)
            if url_check == "isFile":
                with open(url, 'r') as f:
                    urls = f.read().strip('\n').split("\n")
                    return ["isFile", urls]
            elif url_check == "isURL":
                return ["isURL", url]
            else:
                return False

    def ExpPath(self):
        self.dirsPath(self.url_exp)
    def urlsPath(self):
        self.dirsPath(self.pocurl)
    def dirsPath(self, entry):
        filetypes = [('txt', '*.txt'), ('all', '*.*')]
        path = filedialog.askopenfilename(title='文件选择', filetypes=filetypes)
        # systype
        if self.sysType == "Windows":
            # windows
            path = path.replace('/', '\\')
        else:
            # linux
            path = path.replace('\\', '/')
        entry.delete(0, 'end')
        entry.insert('insert', path)
    def jsonPoCLoad(self):
        pass

if __name__ == "__main__":
    pass
