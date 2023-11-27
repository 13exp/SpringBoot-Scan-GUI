# coding:utf-8

from tkinter import messagebox,ttk,filedialog
from tqdm import tqdm

import tkinter.font as tkFont
import tkinter as tk
import os ,requests , shutil, threading

from util import SystemCheck
from util import RandomUA
from util import JsonMethod
from util import InputCheck
from util import URLMethod
from util import LogsMethod
from com import Banner

class ScanPage:
    def __init__(self,windows):
        # 操作系统类型
        self.sysType = SystemCheck.SystemType()
        # 功能中proxy logs载入配置
        self.configLoad = JsonMethod.JsonMethod()
        self.urlmethod = URLMethod.URLMethod()
        self.logmethod = LogsMethod.LogsMethod()
        # 泄露扫描
        tk.Label(windows,text="检测URL", font=("宋体", 12)).place(x=70,y=30)
        tk.Label(windows,text="User-Agent", font=("宋体", 12)).place(x=50,y=60)
        tk.Label(windows,text="信息泄露字典", font=("宋体", 12)).place(x=40,y=90)
        tk.Label(windows,text="下载地址", font=("宋体", 12)).place(x=750,y=30)
        # 泄露扫描控件
        self.url = tk.Entry(windows, width=75, bg='Ivory')
        self.url.place(x=150,y=30)

        self.User_Agent = ttk.Combobox(windows,width=72)
        ua_list = ['自动']
        self.ua = RandomUA.RandomUA()
        uas = self.ua.UserAgentList(100)
        for i in uas:
            ua_list.append(i)
        self.User_Agent['value'] = ua_list
        self.User_Agent.current(0)
        self.User_Agent.place(x=150,y=60)

        self.info_dict = tk.Entry(windows, width=75, bg='Ivory')
        self.info_dict.place(x=150,y=90)
        self.info_dict.insert(0, "./dict/DirDict.txt")
        # 泄露下载器
        self.url_download = tk.Entry(windows, width=44, bg='Ivory')
        self.url_download.place(x=820,y=30)

        self.btnScan = tk.Button(windows,text="扫描", width=15, fg="white", font=tkFont.Font(size=12),command=self.scan,
                  height=1,bg="gray", activeforeground="white", activebackground="black",cursor="hand2")
        self.btnScan.place(x=280,y=118)
        self.btnDownload = tk.Button(windows,text="下载", width=15, fg="white", font=tkFont.Font(size=12),command=self.download,
                  height=2,bg="gray", activeforeground="white", activebackground="black",cursor="hand2")
        self.btnDownload.place(x=900,y=80)
        self.btnUrlsPath = tk.Button(windows,text="浏览", fg="white",bg="gray", activeforeground="white",command=self.urlsPath,
                  activebackground="black",cursor="hand2")
        self.btnUrlsPath.place(x=690,y=25)
        self.btnDictPath = tk.Button(windows,text="浏览", fg="white",bg="gray", activeforeground="white",command=self.dictPath,
                  activebackground="black",cursor="hand2")
        self.btnDictPath.place(x=690,y=85)
        self.btnDownloadPath = tk.Button(windows,text="浏览", fg="white",bg="gray", activeforeground="white",command=self.downloadPath,
                  activebackground="black",cursor="hand2")
        self.btnDownloadPath.place(x=1145,y=25)
        
        # 反馈框
        self.vbar = ttk.Scrollbar(windows)
        self.info_text = tk.Text(windows,width=102,height=30,yscrollcommand=self.vbar.set)
        self.info_text.insert(tk.INSERT,Banner.banner())
        self.info_text.place(x=20,y=150)
        self.vbar.config(command=self.info_text.yview)
        self.vbar.pack(side=tk.RIGHT, fill="y")
        # 请求线程锁
        # self.lock = threading.RLock()
        self.vbar_donwload = ttk.Scrollbar(windows)
        self.info_download = tk.Text(windows, width=64, height=30, yscrollcommand=self.vbar_donwload.set)
        self.info_download.insert(tk.INSERT, Banner.Download())
        self.info_download.place(x=750, y=150)
        self.vbar_donwload.config(command=self.info_download.yview)
        self.vbar_donwload.pack(side=tk.LEFT, fill="y")

    def scan(self):
        try:
            threadScan = threading.Thread(target=self.Scan)
            threadScan.setDaemon(True)
            threadScan.start()
            # threadFofa.join()
        except Exception as e :
            messagebox.showinfo('error', f'unkown error\n{e}')
    def Scan(self):
        self.btnScan.config(state="disable")
        switch = self.switchCheck()
        proxy_status = switch['proxyswitch']
        log_status = switch['logswitch']
        if proxy_status != 0:
            proxyconfig = self.configLoad.ProxyConfigRead()
            
            ip = proxyconfig['ip']
            port = proxyconfig['port']
            proxy = "{ip}:{port}".format(ip=ip,port=port)
            proxies = {
                "http": "http://%(proxy)s/" % {'proxy': proxy},
                "https": "http://%(proxy)s/" % {'proxy': proxy}
                }
        else:
            proxies = None

        ua = self.User_Agent.get()
        if ua == "自动":
            ua = self.ua.UserAgent()
        check = self.scanInputCheck()
        if check == False:
            messagebox.showerror("错误","URL或字典信息错误！")
        else:
            dir_file = self.info_dict.get()
            if check[0] == "isFile":
                urls = check[-1]
                for i in urls:
                    i = self.urlmethod.StandURL(i)
                    try:
                        self.SpringBootScan(ua,i,dir_file,proxy_status,log_status,proxies)
                        self.count()
                    except:
                        back = "{url}SpringBoot信息泄露扫描中的未知错误".format(url=i)
                        self.info_text.insert(tk.INSERT, back)
                        self.info_text.insert(tk.INSERT, '\n')
                        if log_status == 1:
                            self.logmethod.errorlogs(back)
            else:
                url = self.urlmethod.StandURL(check[-1])
                try:
                    self.SpringBootScan(ua,url,dir_file,proxy_status,log_status,proxies)
                    self.count()
                except:
                    back = "{url}SpringBoot信息泄露扫描中的未知错误".format(url=url)
                    self.info_text.insert(tk.INSERT, back)
                    self.info_text.insert(tk.INSERT, '\n')
                    if log_status == 1:
                        self.logmethod.errorlogs(back)
        self.btnScan.config(state="normal")
    def download(self):
        try:
            threadDownload = threading.Thread(target=self.Download)
            threadDownload.setDaemon(True)
            threadDownload.start()
        except Exception as e :
            messagebox.showinfo('error', f'unkown error\n{e}')
    def Download(self):
        path1 = "actuator/heapdump"
        path2 = "heapdump"
        path3 = "heapdump.json"
        path4 = "gateway/actuator/heapdump"
        path5 = "hystrix.stream"

        check200 = "<Response [200]>"
        check401 = "<Response [401]>"

        proxies = ""

        self.btnDownload.config(state="disable")
        switch = self.switchCheck()
        proxy_status = switch['proxyswitch']
        log_status = switch['logswitch']
        if proxy_status != 0:
            proxyconfig = self.configLoad.ProxyConfigRead()
            ip = proxyconfig['ip']
            port = proxyconfig['port']
            proxy = "{ip}:{port}".format(ip=ip,port=port)
            proxies = {
                "http": "http://%(proxy)s/" % {'proxy': proxy},
                "https": "http://%(proxy)s/" % {'proxy': proxy}
                }
        # ua = self.User_Agent.get()
        # if ua == "自动":
        #     ua = self.ua.UserAgent()
        check = self.downloadInputCheck()
        if check == False:
            messagebox.showerror("错误","地址信息错误，请填写完整URL！\neg:https://www.baidu.com")
        else:
            if check[0] == "isFile":
                urls = check[-1]
                for i in urls:
                    i = self.urlmethod.StandURL(i)
                    filedir = i.split("/")[-2].replace(":",'.')
                    save_path = './save/{filedir}'.format(filedir=filedir)
                    try:
                        self.SpringBootDump(i, path1, 'actuator.heapdump', save_path,proxy_status, log_status, proxies,check200)
                        self.SpringBootDump(i, path2, 'heapdump', save_path,proxy_status, log_status, proxies,check200)
                        self.SpringBootDump(i, path3, 'heapdump.json', save_path,proxy_status, log_status, proxies,check200)
                        self.SpringBootDump(i, path4, 'gateway.actuator.heapdump', save_path,proxy_status, log_status, proxies,check200)
                        self.SpringBootDump(i, path5, 'hystrix.stream', save_path,proxy_status, log_status, proxies,(check200 or check401))
                    except:
                        back = "{url} SpringBoot信息泄露下载中的未知错误".format(url=i)
                        self.info_download.insert(tk.INSERT, back)
                        self.info_download.insert(tk.INSERT, '\n')
                        if log_status == 1:
                            self.logmethod.errorlogs(back)
            else:
                url = self.urlmethod.StandURL(check[-1])
                filedir = url.split("/")[-2].replace(":",'.')
                save_path = './save/{filedir}'.format(filedir=filedir)
                try:
                    self.SpringBootDump(url, path1,'actuator.heapdump',save_path,proxy_status,log_status,proxies,check200)
                    self.SpringBootDump(url, path2, 'heapdump', save_path,proxy_status, log_status, proxies,check200)
                    self.SpringBootDump(url, path3, 'heapdump.json', save_path,proxy_status, log_status, proxies,check200)
                    self.SpringBootDump(url, path4, 'gateway.actuator.heapdump', save_path,proxy_status, log_status, proxies,check200)
                    self.SpringBootDump(url, path5, 'hystrix.stream', save_path,proxy_status, log_status, proxies,(check200 or check401))
                except:
                    back = "{url} SpringBoot信息泄露下载中的未知错误".format(url=url)
                    self.info_download.insert(tk.INSERT, back)
                    self.info_download.insert(tk.INSERT, '\n')
                    if log_status == 1:
                        self.logmethod.errorlogs(back)
        self.btnDownload.config(state="normal")
    def SpringBootDump(self,url,path,fname,dumpdir,proxyStaus,logStaus,proxies,checkRqe):
        path = url + path
        if str(requests.head(path)) != checkRqe:
            back = f"[-] 在 {path} 未发现{fname}敏感文件泄露 " .format(path=path,fname=fname)
            self.info_download.insert(tk.INSERT, back)
            self.info_download.insert(tk.INSERT, '\n')
        else:
            back = f"[+] 在 {path} 发现{fname}敏感文件泄露 ".format(path=path,fname=fname)
            self.info_download.insert(tk.INSERT, back)
            self.info_download.insert(tk.INSERT, '\n')
            if not os.path.exists(dumpdir):
                os.mkdir(dumpdir)
            self.DownloadFile(path,fname,proxyStaus, proxies)
            shutil.move(fname, dumpdir)
        if logStaus == 1:
            self.logmethod.dumplogs(back)
    def DownloadFile(self,url, fname, proxyStaus, proxies):
        requests.packages.urllib3.disable_warnings()
        if proxyStaus == 1:
            resp = requests.get(url, timeout=6, stream=True, verify=False, proxies=proxies)
        else:
            resp = requests.get(url, timeout=6, stream=True, verify=False)
        total = int(resp.headers.get('content-length', 0))
        with open(fname, 'wb') as file, tqdm(
                desc=fname,
                total=total,
                unit='iB',
                unit_scale=True,
                unit_divisor=1024,
        ) as bar:
            for data in resp.iter_content(chunk_size=1024):
                size = file.write(data)
                bar.update(size)
    def downloadPath(self):
        self.dirsPath(self.url_download)
    def urlsPath(self):
        self.dirsPath(self.url)
    def dictPath(self):
        self.dirsPath(self.info_dict)
    def dirsPath(self,entry):
        filetypes=[('txt','*.txt'),('all','*.*')]
        path = filedialog.askopenfilename(title='文件选择',filetypes=filetypes)
        # systype
        if self.sysType == "Windows":
            # windows
            path = path.replace('/','\\')
        else:
            # linux
            path = path.replace('\\','/')
        entry.delete(0,'end')
        entry.insert('insert',path)
    def count(self):
        count = len(open("./save/urlout.txt", 'r').readlines())
        if count >= 1:
            show = "[→] 发现目标URL存在SpringBoot敏感信息泄露，已经导出至 urlout.txt ，共%d行记录" % count
            self.info_text.insert(tk.INSERT,show)
            self.info_text.insert(tk.INSERT, '\n')
    def SpringBootScan(self,ua,url,dir_file,proxyStaus,logStaus,proxies):
        if not os.path.exists("./save/urlout.txt"):
            f = open("./save/urlout.txt","a")
            f.close()
        u = self.urlmethod.StandURL(url)
        # 读取泄露字典
        with open(dir_file, 'r') as web:
            webs = web.readlines()
            for web in webs:
                web = web.strip()
                url = u + web
                try:
                    header = {"User-Agent": ua}
                    requests.packages.urllib3.disable_warnings()
                    if proxyStaus == 1:
                        r = requests.get(url=url, headers=header, timeout=6, verify=False, proxies=proxies)  # 设置超时6秒
                    else:
                        r = requests.get(url=url, headers=header, timeout=6, verify=False)  # 设置超时6秒
                    if r.status_code == 503:
                        pass
                    elif r.status_code == 200:
                        back = "[+] 状态码%d" % r.status_code + ' ' + "信息泄露URL为:" + url + '    ' + "页面长度为:" + str(len(r.content))
                        self.info_text.insert(tk.INSERT,back)
                        self.info_text.insert(tk.INSERT, '\n')
                        f = open("./save/urlout.txt", "a")
                        f.write(back + '\n')
                        f.close()
                    else:
                        back = "[-] 状态码%d" % r.status_code + ' ' + "无法访问URL为:" + url
                        self.info_text.insert(tk.INSERT,back)
                        self.info_text.insert(tk.INSERT, '\n')
                except:
                    back = "[-] URL为 " + url + " 的目标积极拒绝请求，予以跳过！"
                    self.info_text.insert(tk.INSERT,back)
                    self.info_text.insert(tk.INSERT, '\n')
                    break
                if logStaus == 1:
                    self.logmethod.sacnlogs(back)
    def scanInputCheck(self):
        check = InputCheck.InputCheck()
        
        url = self.url.get()
        # ua = self.User_Agent.get()
        dicts = self.info_dict.get()
        
        dicts_check = check.FileOrUrl(dicts)

        # ua_check = check.isNull(ua)

        if dicts_check != "isFile":
            return False
        else:
            url_check = check.FileOrUrl(url)
            if url_check == "isFile" :
                with open(url,'r') as f:
                    urls = f.read().strip('\n').split("\n")
                    return ["isFile",urls]
            elif url_check == "isURL":
                return ["isURL",url]
            else:
                return False
    def downloadInputCheck(self):
        check = InputCheck.InputCheck()
        url = self.url_download.get()
        url_check = check.isNull(url)
        
        if url_check == True:
            return False
        else:
            url_check = check.FileOrUrl(url)
            if url_check == "isFile":
                with open(url,'r') as f:
                    urls = f.read().strip('\n').split("\n")
                    return ["isFile",urls]
            elif url_check == "isURL":
                return ["isURL",url]
            else:
                return False
    def switchCheck(self):
        proxyconfig = self.configLoad.ProxyConfigRead()
        logsconfig = self.configLoad.LogsConfigRead()
        proxyswitch = proxyconfig['switch']
        logswitch = logsconfig['switch']
        return {"proxyswitch":proxyswitch,"logswitch":logswitch}
if __name__ == "__main__":
    pass
    
