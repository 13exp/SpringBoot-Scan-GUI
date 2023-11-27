# coding:utf-8
import os
from tkinter import *
from tkinter import ttk, messagebox, filedialog
import tkinter.font as tkFont

from util import JsonMethod, SystemCheck

class VulnConfig:
    def __init__(self):
        # 操作系统类型
        self.sysType = SystemCheck.SystemType()
        self.vulnspath = './config/vulns.json'
        self.configinit(self.vulnspath)

    def configinit(self,path):
        self.config = JsonMethod.JsonMethod()
        if not os.path.exists(path):
            data = {
    "vulns": {
        "pocList": [
        "CVE-2021-21234",
        "CVE-2022-22947",
        "CVE-2022-22963",
        "CVE-2022-22965",
        "JeeSpring-2023",
        "JolokiaRCE",
        "nakeYAMLRCE"
    ],
    "expList": [
        "CVE-2022-22947",
        "CVE-2022-22963",
        "CVE-2022-22965",
        "JeeSpring-2023",
        "JolokiaRCE",
        "nakeYAMLRCE"
    ]},
    "model": {
        "standmodel": [
        "py"
    ],
        "asyncmodel":"async"
    },
    "path": {
        "standpath": {
        "CVE-2021-21234": "./vuls/CVE_2021_21234",
        "CVE-2022-22947": "./vuls/CVE_2022_22947",
        "CVE-2022-22963": "./vuls/CVE_2022_22963",
        "CVE-2022-22965": "./vuls/CVE_2022_22965",
        "JeeSpring-2023": "./vuls/JeeSpring_2023",
        "JolokiaRCE": "./vuls/JeeSpring_2023",
        "nakeYAMLRCE": "./vuls/SnakeYAML_RCE"
    },
    "asyncpath": {
        "CVE-2021-21234": "./vuls/CVE_2021_21234_Async.py",
        "CVE-2022-22947": "./vuls/CVE_2022_22947_Async.py",
        "CVE-2022-22963": "./vuls/CVE_2022_22963_Async.py",
        "CVE-2022-22965": "./vuls/CVE_2022_22965_Async.py",
        "JeeSpring-2023": "./vuls/JeeSpring_2023_Async.py",
        "JolokiaRCE": "./vuls/JeeSpring_2023_Async.py",
        "nakeYAMLRCE": "./vuls/SnakeYAML_RCE_Async.py"
    }
    },
    "modelSet": "py",
    "expTypes": [
            "defualt",
            "aabysszg",
            "13EXP"
        ],
    "expType": "defualt"
}
            self.config.JsonWrite(data,path)
    def page(self):
        self.configinit(self.vulnspath)
        self.window = Toplevel(name='vulnscan')
        self.window.title("漏扫设置")
        self.window.geometry("500x480")
        self.window.resizable(0, 0)

        # 初始化json读取
        vulnconfig = self.config.JsonRead(self.vulnspath)

        self.poclist = vulnconfig["vulns"]['pocList']
        self.explist = vulnconfig["vulns"]['expList']

        self.standmodel = vulnconfig["model"]["standmodel"]
        self.asyncmodel = vulnconfig["model"]["asyncmodel"]

        vulnpath = vulnconfig["path"]
        self.standpath = vulnpath["standpath"]
        self.asyncpath = vulnpath["asyncpath"]

        self.modelSet = vulnconfig["modelSet"]

        self.expTypes = vulnconfig["expTypes"]

        self.expType = vulnconfig["expType"]
        self.models = []
        for i in self.standmodel:
            self.models.append(i)
        self.models.append(self.asyncmodel)

        Label(self.window, text="Model:", fg="black", font=("宋体", 12)).place(x=20, y=37)
        self.model = ttk.Combobox(self.window, width=50)
        self.model['value'] = self.models
        try:
            self.model.current(self.models.index(self.modelSet))
        except:
            self.window.destroy()
            return messagebox.showerror("错误", "model load error!\nYou can delete the vulns.json and try again!")
        self.model.place(x=90, y=37)

        Label(self.window, text="expType:", fg="black", font=("宋体", 12)).place(x=17, y=10)
        self.types = ttk.Combobox(self.window, width=50)
        self.types['value'] = self.expTypes
        try:
            self.types.current(self.expTypes.index(self.expType))
        except:
            self.window.destroy()
            return messagebox.showerror("错误", "types load error!\nYou can delete the vulns.json and try again!")
        self.types.place(x=90, y=10)

        Label(self.window, text="PoC:", fg="black", font=("宋体", 12)).place(x=20, y=60)
        self.vbar_poclist = ttk.Scrollbar(self.window)
        self.poclist_info = Text(self.window, width=30, height=15, yscrollcommand=self.vbar_poclist.set)
        self.poclist_info.place(x=20, y=90)
        self.vbar_poclist.config(command=self.poclist_info.yview)
        self.vbar_poclist.pack(side=RIGHT, fill="y")

        Label(self.window, text="EXP:", fg="black", font=("宋体", 12)).place(x=260, y=60)
        self.vbar_explist = ttk.Scrollbar(self.window)
        self.explist_info = Text(self.window, width=30, height=15, yscrollcommand=self.vbar_explist.set)
        self.explist_info.place(x=260, y=90)
        self.vbar_explist.config(command=self.explist_info.yview)
        self.vbar_explist.pack(side=LEFT, fill="y")

        self.poc = ttk.Combobox(self.window, width=16)
        self.poc['value'] = self.poclist
        self.poc.current(0)
        self.poc.place(x=20, y=310)

        Label(self.window, text="Vuln:", fg="black", font=("宋体", 12)).place(x=20, y=350)
        self.addvulnName_entry = Entry(self.window, width=38, bg='Ivory', font=tkFont.Font(size=12))
        self.addvulnName_entry.place(x=70, y=350)

        Label(self.window, text="Path:", fg="black", font=("宋体", 12)).place(x=20, y=380)
        self.addvulnPath_entry = Entry(self.window, width=38, bg='Ivory', font=tkFont.Font(size=12),cursor="hand2")
        self.addvulnPath_entry.place(x=70, y=380)
        self.addvulnPath_entry.bind("<Button-1>",self.vulnPath)

        self.AddVuln = Button(self.window, text="新增", font=tkFont.Font(size=12), width=9, command=self.addVuln,
                             height=2, fg="white", bg="gray", activeforeground="white", activebackground="black",
                             cursor="hand2")
        self.AddVuln.place(x=390, y=350)

        self.Delpoc = Button(self.window, text="删除", font=tkFont.Font(size=10), width=9, command=self.delpoc,
                             height=1, fg="white", bg="gray", activeforeground="white", activebackground="black",
                             cursor="hand2")
        self.Delpoc.place(x=160, y=310)

        self.exp = ttk.Combobox(self.window, width=16)
        self.exp['value'] = self.explist
        self.exp.current(0)
        self.exp.place(x=260, y=310)

        # Label(self.window, text="EXP:", fg="black", font=("宋体", 12)).place(x=260, y=350)
        # self.addexpname_entry = Entry(self.window, width=19, bg='Ivory', font=tkFont.Font(size=12))
        # self.addexpname_entry.place(x=310, y=350)

        # self.addexppath_entry = Entry(self.window, width=22, bg='Ivory', font=tkFont.Font(size=12))
        # self.addexppath_entry.place(x=290, y=380)

        # self.Addexp = Button(self.window, text="新增", font=tkFont.Font(size=12), width=9, command=self.addexp,
        #                      height=1, fg="white", bg="gray", activeforeground="white", activebackground="black",
        #                      cursor="hand2")
        # self.Addexp.place(x=320, y=410)

        self.Delexp = Button(self.window, text="删除", font=tkFont.Font(size=10), width=9, command=self.delexp,
                             height=1, fg="white", bg="gray", activeforeground="white", activebackground="black",
                             cursor="hand2")
        self.Delexp.place(x=400, y=310)

        # self.standpathget = {}
        # self.asyncpathget = {}
        # for i in self.poclist:
        #     self.standpathget[i] = ""
        #     self.asyncpathget[i] = ""

        Button(self.window, text="保存", font=tkFont.Font(size=12), width=9, command=self.update,
               height=1, fg="white", bg="gray", activeforeground="white", activebackground="black",
               cursor="hand2").place(x=140, y=420)

        Button(self.window, text="取消", font=tkFont.Font(size=12), width=9, command=self.window.destroy,
               height=1, fg="white", bg="gray", activeforeground="white", activebackground="black",
               cursor="hand2").place(x=260, y=420)

        self.pocs = self.ListToText(self.poclist)
        self.exps = self.ListToText(self.explist)

        self.poclist_info.insert(INSERT, self.pocs)
        self.poclist_info.config(state='disable')

        self.explist_info.insert(INSERT, self.exps)
        self.explist_info.config(state='disable')
    def ListToText(self,list):
        text = ""
        for i in list:
            text += i + "\n"
        return text
    def AsyncPath(self,path):
        path = path + "_Async.py"
        return path
    def delpoc(self):
        try:
            self.poclist_info.config(state="normal")
            self.poclist_info.delete(1.0, END)
            poc = self.poc.get()
            self.poclist.remove(poc)
            self.standpath.pop(poc)
            self.asyncpath.pop(poc)
            pocs = self.ListToText(self.poclist)
            if len(self.poclist) > 0:
                self.poc['value'] = self.poclist
                self.poc.current(0)
            else:
                self.poc['value'] = [""]
                self.poc.current(0)
            self.poclist_info.insert(INSERT, pocs)
            self.poclist_info.config(state="disable")
        except:
            messagebox.showerror("错误","未知错误")
            self.poclist_info.config(state="disable")
    def delexp(self):
        try:
            self.explist_info.config(state="normal")
            self.explist_info.delete(1.0, END)
            exp = self.exp.get()
            self.explist.remove(exp)
            exps = self.ListToText(self.explist)
            if len(self.explist) > 0:
                self.exp['value'] = self.explist
                self.exp.current(0)
            else:
                self.exp['value'] = [""]
                self.exp.current(0)
            self.explist_info.insert(INSERT, exps)
            self.explist_info.config(state="disable")
        except:
            messagebox.showerror("错误","未知错误")
            self.explist_info.config(state="disable")
    def dirsPath(self,entry):
        filetypes=[('py','*.py'),('yaml','*.yaml'),('json','*.json'),('all','*.*')]
        path = filedialog.askopenfilename(title='文件选择',filetypes=filetypes)
        # systype
        if self.sysType == "Windows":
            # windows
            path = path.replace('/','\\')
        else:
            # linux
            path = path.replace('\\','/')
        pwd = os.getcwd()
        if pwd in path:
            pfix = path.split(".")[-1]
            path = "." + path.replace(pwd,"").replace("\\","/").replace(".py","").\
                replace(".json","").replace("_Async","").replace(f".{pfix}","")
        else:
            path = path
        entry.delete(0,'end')
        entry.insert('insert',path)
    def vulnPath(self,event):
        self.dirsPath(self.addvulnPath_entry)
    def addVuln(self):
        vuln = self.addvulnName_entry.get()
        exp = self.addvulnName_entry.get()
        pocpath = self.addvulnPath_entry.get()
        asyncpath = self.AsyncPath(pocpath)
        self.explist_info.config(state="normal")
        self.poclist_info.config(state="normal")
        if vuln not in self.poclist and vuln != "":
            self.explist.append(exp)
            self.poclist.append(vuln)
            self.standpath[vuln] = pocpath
            self.asyncpath[vuln] = asyncpath
        else:
            self.explist_info.config(state="disable")
            self.poclist_info.config(state="disable")
            return messagebox.showerror("错误","空值或重复的键值")
        self.poc['value'] = self.poclist
        self.poc.current(0)
        self.exp['value'] = self.explist
        self.exp.current(0)
        self.explist_info.delete(1.0, END)
        self.poclist_info.delete(1.0, END)
        pocs = self.ListToText(self.poclist)
        exps = self.ListToText(self.explist)
        self.poclist_info.insert(INSERT, pocs)
        self.explist_info.insert(INSERT, exps)
        self.poclist_info.config(state="disable")
        self.explist_info.config(state="disable")
        return True
    def update(self):
        modelget = self.model.get()
        expType = self.types.get()
        data = {
    "vulns": {
        "pocList": self.poclist,
        "expList": self.explist
    },
    "model": {
        "standmodel": [
        "py",
        "json",
        "yaml"
    ],
        "asyncmodel":"async"
    },
    "path": {
        "standpath": self.standpath,
        "asyncpath": self.asyncpath
    },
    "modelSet": modelget,
    "expTypes": [
        "default",
        "aabysszg",
        "13EXP"
    ],
    "expType": expType
}
        self.config = JsonMethod.JsonMethod()
        self.config.JsonWrite(data, self.vulnspath)
        messagebox.showinfo("更新", "更新成功！")
