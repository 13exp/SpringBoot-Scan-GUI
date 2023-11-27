# coding:utf-8
from tkinter import ttk

import requests, base64, json,threading

from com import Banner
from util import RandomUA
from util import InputCheck
from util import URLMethod
from util import JsonMethod
from pages.config import FofaConfig
import tkinter.messagebox as messagebox
import tkinter.font as tkFont
import tkinter as tk
from tkinter import *

# 资产测绘
class FofaPage:
    def __init__(self, windows):

        self.url_str = URLMethod.URLMethod()
        # 初始化读取配置功能
        fofaconfig = FofaConfig.FofaConfig()
        
        self.frame_left = Frame(windows, width=900, height=600)
        # self.frame_left.grid(row=0, column=0, columnspan=2, padx=5, pady=5)
        self.frame_left.place(x=20,y=0)
        Label(self.frame_left, text="搜索语法:", fg="black", font=("宋体", 12)).place(x=60, y=5)

        self.asset_rule = Entry(self.frame_left, width=52, font=tkFont.Font(size=14), bg='Ivory')
        self.asset_rule.place(x=150, y=8)
        self.asset_rule.insert(0,'icon_hash="116323821" || body="Whitelabel Error Page"')
        self.btnSet = Button(self.frame_left, text="配置", font=tkFont.Font(size=12), width=5,command=fofaconfig.page,
               height=1, fg="white", bg="gray", activeforeground="white", activebackground="black",
               cursor="hand2")
        self.btnSet.place(x=0, y=5)

        self.btnQery =  Button(self.frame_left, text="查询", font=tkFont.Font(size=12), width=9,command=self.btnFofa,
               height=1, fg="white", bg="gray", activeforeground="white", activebackground="black",
               cursor="hand2")
        self.btnQery.place(x=690, y=5)

        self.btnOutput = Button(self.frame_left, text="导出", font=tkFont.Font(size=12), width=9,command=self.output,
               height=1, fg="white", bg="gray", activeforeground="white", activebackground="black",
               cursor="hand2")
        self.btnOutput.place(x=790, y=5)

        self.vbar_asset = ttk.Scrollbar(windows)
        self.asset_info = Text(self.frame_left, width=125, height=38, yscrollcommand=self.vbar_asset.set)
        self.asset_info.place(x=0, y=50)
        self.vbar_asset.config(command=self.asset_info.yview)
        self.vbar_asset.pack(side=tk.RIGHT, fill="y")

        ua = RandomUA.RandomUA()
        self.ua = ua.UserAgent()
        self.header = {
            'User-Agent': self.ua,
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
        }
        # 右方区域
        self.frame_right = Frame(windows, width=300, height=600)
        # self.frame_right.grid(row=0, column=2, columnspan=2, padx=5, pady=5)
        self.frame_right.place(x=910,y=0)

        Label(self.frame_right, text="查询语法", fg="black", font=("宋体", 12)).place(x=110, y=10)

        self.vbar_rules = ttk.Scrollbar(windows)
        self.fofa_rules = Text(self.frame_right, width=41, height=38, yscrollcommand=self.vbar_rules.set)
        self.fofa_rules.place(x=0, y=50)
        self.vbar_rules.config(command=self.fofa_rules.yview)
        self.vbar_rules.pack(side=tk.LEFT, fill="y")

        self.fofa_rules.insert(tk.INSERT,Banner.FofaInfo())
        self.fofa_rules.config(state='disable')
    def urlCheck(self):
        rule = self.asset_rule.get()
        check = InputCheck.InputCheck()
        status = check.isNull(rule)
        if status == True:
            return True
        else:
            return False
    def btnFofa(self):
        try:
            threadFofa = threading.Thread(target=self.btnfofa)
            threadFofa.setDaemon(True)
            threadFofa.start()
        except Exception as e:
            messagebox.showinfo('error', f'unkown error\n{e}')
    def btnfofa(self):
        self.btnOutput.config(state="disable")
        self.btnQery.config(state="disable")
        rule = self.asset_rule.get()
        check = self.urlCheck()
        if check == True:
            messagebox.showerror("错误","搜索规则功能为空！")
        else:
            try:
                self.fofa(rule)
            except:
                messagebox.showerror("错误", "搜索语法错误！")
        self.btnOutput.config(state="normal")
        self.btnQery.config(state="normal")
    def fofa(self,rule):
        configLoad = JsonMethod.JsonMethod()
        config = configLoad.FofaConfigRead()
        # 参数初始化
        self.fofa_api = config['api']
        self.fofa_email = config['email']
        self.fofa_key = config['key']
        self.fofa_size = config['size']

        rule = base64.b64encode(rule.encode('utf-8')).decode("utf-8")
        req = self.fofa_api.strip(
            "/") + "/api/v1/search/all?email=" + self.fofa_email + "&key=" + self.fofa_key + "&qbase64=" + rule + "&size=" + self.fofa_size
        response = requests.get(req, headers=self.header)
        if 'errmsg' not in response.text:
            self.asset_info.delete(1.0, tk.END)  # Clear previous results
        r = json.loads(response.text)

        for i in r['results']:
            s = i[0]
            s_with_protocol = self.url_str.StandURL(s)
            self.asset_info.insert(tk.END, s_with_protocol)
            self.asset_info.insert(tk.END, '\n')
    def output(self):
        try:
            threadOutput= threading.Thread(target=self.Output)
            threadOutput.setDaemon(True)
            threadOutput.start()
        except Exception as e:
            messagebox.showinfo('error', f'unkown error\n{e}')
    def Output(self):
        self.btnQery.config(state="disable")
        self.btnOutput.config(state="disable")
        # 清空操作
        f = open("./save/fofa.txt","w")
        f.close()
        data = self.asset_info.get("1.0","end")
        urls = data.strip("\n").split("\n")
        for i in urls:
            with open("./save/fofa.txt","a") as f:
                f.write(i)
                f.write("\n")
        messagebox.showinfo("提示", "导出成功./save/fofa.txt！")
        self.btnQery.config(state="normal")
        self.btnOutput.config(state="normal")
