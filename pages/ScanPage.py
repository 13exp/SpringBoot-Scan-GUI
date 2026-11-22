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
from util.Translate import tr
from com import Banner

class ScanPage:
    def __init__(self,windows):
        # 操作系统类型
        self.sysType = SystemCheck.SystemType()
        # 功能中proxy logs载入配置
        self.configLoad = JsonMethod.JsonMethod()
        self.urlmethod = URLMethod.URLMethod()
        self.logmethod = LogsMethod.LogsMethod()
        # 泄露扫描（mise en page mesurée et redimensionnable）

        lab_url = tk.Label(windows, text=tr("scan.target_url"), font=("宋体", 12))
        lab_ua = tk.Label(windows, text="User-Agent", font=("宋体", 12))
        lab_dict = tk.Label(windows, text=tr("scan.dict_label"), font=("宋体", 12))
        lab_dl = tk.Label(windows, text=tr("scan.download_url"), font=("宋体", 12))

        self.url = tk.Entry(windows, bg='Ivory')
        self.info_dict = tk.Entry(windows, bg='Ivory')
        self.url_download = tk.Entry(windows, bg='Ivory')
        self.User_Agent = ttk.Combobox(windows)
        ua_list = [tr("common.auto")]
        self.ua = RandomUA.RandomUA()
        uas = self.ua.UserAgentList(100)
        for i in uas:
            ua_list.append(i)
        self.User_Agent['value'] = ua_list
        self.User_Agent.current(0)

        self.btnScan = tk.Button(windows, text=tr("common.scan"), fg="white", font=tkFont.Font(size=12),
                  command=self.scan, bg="gray", activeforeground="white", activebackground="black", cursor="hand2")
        self.btnDownload = tk.Button(windows, text=tr("scan.download"), fg="white", font=tkFont.Font(size=12),
                  command=self.download, bg="gray", activeforeground="white", activebackground="black", cursor="hand2")
        self.btnUrlsPath = tk.Button(windows, text=tr("common.browse"), fg="white", bg="gray",
                  activeforeground="white", command=self.urlsPath, activebackground="black", cursor="hand2")
        self.btnDictPath = tk.Button(windows, text=tr("common.browse"), fg="white", bg="gray",
                  activeforeground="white", command=self.dictPath, activebackground="black", cursor="hand2")
        self.btnDownloadPath = tk.Button(windows, text=tr("common.browse"), fg="white", bg="gray",
                  activeforeground="white", command=self.downloadPath, activebackground="black", cursor="hand2")

        # 反馈框
        self.vbar = ttk.Scrollbar(windows)
        self.info_text = tk.Text(windows, yscrollcommand=self.vbar.set)
        self.info_text.insert(tk.INSERT, Banner.banner())
        self.vbar.config(command=self.info_text.yview)
        self.vbar_donwload = ttk.Scrollbar(windows)
        self.info_download = tk.Text(windows, yscrollcommand=self.vbar_donwload.set)
        self.info_download.insert(tk.INSERT, Banner.Download())
        self.vbar_donwload.config(command=self.info_download.yview)
        self.info_dict.insert(0, "./dict/DirDict.txt")

        # mesures réelles (constantes pour la langue courante), positions via _layout()
        self.windows = windows
        self._lw = max(lab_url.winfo_reqwidth(), lab_ua.winfo_reqwidth(), lab_dict.winfo_reqwidth())
        self._rw = lab_dl.winfo_reqwidth()
        self._eh = max(self.url.winfo_reqheight(), lab_url.winfo_reqheight())
        self._row_h = self._eh + 10
        self._bwb = self.btnUrlsPath.winfo_reqwidth() + 24
        self._btn_h = self.btnScan.winfo_reqheight()
        self._lab = (lab_url, lab_ua, lab_dict, lab_dl)
        self._w = 0
        self._h = 0

        self._layout()
        self._apply_minsize()
        windows.bind("<Configure>", self._on_configure)

    def _on_configure(self, event):
        # recalcul quand la taille de l'onglet change (fenêtre redimensionnable)
        if event.widget is self.windows and (event.width, event.height) != (self._w, self._h):
            self._layout()

    def _apply_minsize(self):
        top = self.windows.winfo_toplevel()
        need_w = 10 + self._lw + 15 + 220 + self._bwb + 20 + self._rw + 15 + 220 + self._bwb + 10
        need_h = 25 + 4 * self._row_h + self._btn_h + 20 + 200
        try:
            cur_w, cur_h = top.wm_minsize()
            cur_w, cur_h = int(cur_w), int(cur_h)
        except Exception:
            cur_w = cur_h = 1
        top.minsize(max(cur_w, need_w), max(cur_h, need_h))

    def _layout(self):
        w, h = self.windows.winfo_width(), self.windows.winfo_height()
        if w < 100: w = self.windows.winfo_screenwidth() - 4
        if h < 100: h = self.windows.winfo_screenheight() - 120
        self._w, self._h = w, h
        lw, rw, eh, row_h, bwb = self._lw, self._rw, self._eh, self._row_h, self._bwb
        lab_url, lab_ua, lab_dict, lab_dl = self._lab

        lx = 10
        ex = lx + lw + 15
        # largeur des champs : fraction de la fenêtre, garantie sans chevauchement
        ew = max(200, int((w - ex - rw - 2 * bwb - 65) * 0.48))
        rcx = ex + ew + bwb + 20           # début colonne droite (libellés)
        rex = rcx + rw + 15                # champs colonne droite
        rew = max(200, w - rex - bwb - 10)
        y0 = 25
        y1 = y0 + row_h
        y2 = y1 + row_h
        yb = y2 + row_h

        lab_url.place(x=lx, y=y0 + 4)
        lab_ua.place(x=lx, y=y1 + 4)
        lab_dict.place(x=lx, y=y2 + 4)
        lab_dl.place(x=rcx, y=y0 + 4)
        self.url.place(x=ex, y=y0, width=ew)
        self.User_Agent.place(x=ex, y=y1, width=ew)
        self.info_dict.place(x=ex, y=y2, width=ew)
        self.url_download.place(x=rex, y=y0, width=rew)
        self.btnUrlsPath.place(x=ex + ew + 10, y=y0, width=bwb, height=eh)
        self.btnDictPath.place(x=ex + ew + 10, y=y2, width=bwb, height=eh)
        self.btnDownloadPath.place(x=rex + rew + 10, y=y0, width=bwb, height=eh)
        self.btnScan.place(x=ex, y=yb, width=self.btnScan.winfo_reqwidth() + 40, height=self._btn_h + 6)
        self.btnDownload.place(x=rex, y=y1, width=self.btnDownload.winfo_reqwidth() + 40, height=self._btn_h + 6)

        # 反馈框
        ty = yb + self._btn_h + 20
        th = max(150, h - ty - 15)
        half = (w - 30) // 2
        tw = half - 18
        self.info_text.place(x=10, y=ty, width=tw, height=th)
        self.vbar.place(x=10 + tw + 2, y=ty, width=14, height=th)
        rx = 10 + half + 10
        self.info_download.place(x=rx, y=ty, width=tw, height=th)
        self.vbar_donwload.place(x=rx + tw + 2, y=ty, width=14, height=th)

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
        if ua == tr("common.auto"):
            ua = self.ua.UserAgent()
        check = self.scanInputCheck()
        if check == False:
            messagebox.showerror(tr("common.error"),tr("scan.url_or_dict_err"))
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
                        back = tr("scan.unknown_scan_err", url=i)
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
                    back = tr("scan.unknown_scan_err", url=url)
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
        # if ua == tr("common.auto"):
        #     ua = self.ua.UserAgent()
        check = self.downloadInputCheck()
        if check == False:
            messagebox.showerror(tr("common.error"),tr("scan.url_incomplete"))
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
                        back = tr("scan.unknown_download_err", url=i)
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
                    self.SpringBootDump(url, path2, 'heapdump', save_path,proxy_status,log_status,proxies,check200)
                    self.SpringBootDump(url, path3, 'heapdump.json', save_path,proxy_status,log_status,proxies,check200)
                    self.SpringBootDump(url, path4, 'gateway.actuator.heapdump', save_path,proxy_status,log_status,proxies,check200)
                    self.SpringBootDump(url, path5, 'hystrix.stream', save_path,proxy_status,log_status,proxies,(check200 or check401))
                except:
                    back = tr("scan.unknown_download_err", url=url)
                    self.info_download.insert(tk.INSERT, back)
                    self.info_download.insert(tk.INSERT, '\n')
                    if log_status == 1:
                        self.logmethod.errorlogs(back)
        self.btnDownload.config(state="normal")
    def SpringBootDump(self,url,path,fname,dumpdir,proxyStaus,logStaus,proxies,checkRqe):
        path = url + path
        if str(requests.head(path)) != checkRqe:
            back = tr("scan.no_leak", path=path, fname=fname)
            self.info_download.insert(tk.INSERT, back)
            self.info_download.insert(tk.INSERT, '\n')
        else:
            back = tr("scan.found_leak", path=path, fname=fname)
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
        path = filedialog.askopenfilename(title=tr("common.file_select"),filetypes=filetypes)
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
            show = tr("scan.found_export", count=count)
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
                        back = tr("scan.status_leak", code=r.status_code, url=url, length=len(r.content))
                        self.info_text.insert(tk.INSERT,back)
                        self.info_text.insert(tk.INSERT, '\n')
                        f = open("./save/urlout.txt", "a")
                        f.write(back + '\n')
                        f.close()
                    else:
                        back = tr("scan.status_fail", code=r.status_code, url=url)
                        self.info_text.insert(tk.INSERT,back)
                        self.info_text.insert(tk.INSERT, '\n')
                except:
                    back = tr("scan.refused", url=url)
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

