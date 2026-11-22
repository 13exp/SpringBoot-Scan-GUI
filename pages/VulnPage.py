# coding:utf-8
import threading
from tkinter import messagebox, ttk, filedialog

import tkinter.font as tkFont
import tkinter as tk

# try:
from core import core
# except:
# messagebox.showerror(tr("common.error"),"core加载出错，请检查杀毒软件是否删除文件！")

from util import SystemCheck
from util import URLMethod
from util import RandomUA
from util import JsonMethod
from util import InputCheck
from util import ProxyCheck
from util import LogsMethod
from util.Translate import tr

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
        # 漏洞扫描（mise en page mesurée et redimensionnable）
        lab_url = tk.Label(windows, text="URL")
        lab_ua = tk.Label(windows, text="User-Agent")
        lab_poc = tk.Label(windows, text="PoC")
        lab_exp = tk.Label(windows, text=tr("vuln.exploit_url"))
        lab_cmd = tk.Label(windows, text=tr("vuln.cmd"))
        lab_exp_lbl = tk.Label(windows, text="EXP")

        self.pocurl = tk.Entry(windows, bg='Ivory')
        self.url_exp = tk.Entry(windows, bg='Ivory')
        self.cmd_exp = tk.Entry(windows, bg='Ivory')
        self.cmd_exp.insert(0, "whoami")
        self.User_Agent_EXP = ttk.Combobox(windows)
        ua_list = [tr("common.auto")]
        self.ua = RandomUA.RandomUA()
        uas = self.ua.UserAgentList(100)
        for i in uas:
            ua_list.append(i)
        self.User_Agent_EXP['value'] = ua_list
        self.User_Agent_EXP.current(0)
        self.info_pocs = ttk.Combobox(windows)
        self.info_pocs['value'] = self.pocpath
        self.info_pocs.current(0)
        self.info_exps = ttk.Combobox(windows)
        self.info_exps['value'] = self.exppath
        self.info_exps.current(0)

        btn_browse_poc = tk.Button(windows, text=tr("common.browse"), fg="white", bg="gray",
                  activeforeground="white", command=self.urlsPath, activebackground="black", cursor="hand2")
        btn_browse_exp = tk.Button(windows, text=tr("common.browse"), fg="white", bg="gray",
                  activeforeground="white", command=self.ExpPath, activebackground="black", cursor="hand2")
        self.BtnPoC = tk.Button(windows, text=tr("common.scan"), fg="white", font=tkFont.Font(size=12),
                  command=self.btnPoC, bg="gray", activeforeground="white", activebackground="black", cursor="hand2")
        self.BtnEXP = tk.Button(windows, text="EXP", fg="white", font=tkFont.Font(size=12),
                  command=self.btnEXP, bg="gray", activeforeground="white", activebackground="black", cursor="hand2")
        btn_refresh = tk.Button(windows, text="F", fg="white", bg="gray", activeforeground="white",
                  command=self.RefreshVar, activebackground="black", cursor="hand2")

        # 反馈框
        self.vbar_poc = ttk.Scrollbar(windows)
        self.info_text_poc = tk.Text(windows, yscrollcommand=self.vbar_poc.set)
        self.info_text_poc.insert(tk.INSERT, Banner.PoC())
        self.vbar_poc.config(command=self.info_text_poc.yview)
        self.vbar_exp = ttk.Scrollbar(windows)
        self.info_text_exp = tk.Text(windows, yscrollcommand=self.vbar_exp.set)
        self.info_text_exp.insert(tk.INSERT, Banner.EXP())
        self.vbar_exp.config(command=self.info_text_exp.yview)

        # mesures réelles (constantes pour la langue courante), positions via _layout()
        self.windows = windows
        self._lw = max(lab_url.winfo_reqwidth(), lab_ua.winfo_reqwidth(), lab_poc.winfo_reqwidth())
        self._rw = max(lab_exp.winfo_reqwidth(), lab_cmd.winfo_reqwidth(), lab_exp_lbl.winfo_reqwidth())
        self._eh = max(self.pocurl.winfo_reqheight(), lab_ua.winfo_reqheight())
        self._row_h = self._eh + 10
        self._bwb = btn_browse_poc.winfo_reqwidth() + 24
        self._btn_h = self.BtnPoC.winfo_reqheight()
        self._fw = btn_refresh.winfo_reqwidth() + 10
        self._lab = (lab_url, lab_ua, lab_poc, lab_exp, lab_cmd, lab_exp_lbl)
        self._btn_browse_poc = btn_browse_poc
        self._btn_browse_exp = btn_browse_exp
        self._btn_refresh = btn_refresh
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
        lab_url, lab_ua, lab_poc, lab_exp, lab_cmd, lab_exp_lbl = self._lab

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
        # bouton F (actualisation) à gauche du libellé PoC, comme à l'origine
        self._btn_refresh.place(x=lx, y=y2, width=self._fw, height=eh)
        lab_poc.place(x=lx + self._fw + 10, y=y2 + 4)
        lab_exp.place(x=rcx, y=y0 + 4)
        lab_cmd.place(x=rcx, y=y1 + 4)
        lab_exp_lbl.place(x=rcx, y=y2 + 4)
        self.pocurl.place(x=ex, y=y0, width=ew)
        self.User_Agent_EXP.place(x=ex, y=y1, width=ew)
        self.info_pocs.place(x=ex, y=y2, width=ew)
        self.url_exp.place(x=rex, y=y0, width=rew)
        self.cmd_exp.place(x=rex, y=y1, width=rew)
        self.info_exps.place(x=rex, y=y2, width=rew)
        self._btn_browse_poc.place(x=ex + ew + 10, y=y0, width=bwb, height=eh)
        self._btn_browse_exp.place(x=rex + rew + 10, y=y0, width=bwb, height=eh)
        self.BtnPoC.place(x=ex, y=yb, width=self.BtnPoC.winfo_reqwidth() + 40, height=self._btn_h + 6)
        self.BtnEXP.place(x=rex, y=yb, width=self.BtnEXP.winfo_reqwidth() + 40, height=self._btn_h + 6)

        # 反馈框
        ty = yb + self._btn_h + 20
        th = max(150, h - ty - 15)
        half = (w - 30) // 2
        tw = half - 18
        self.info_text_poc.place(x=10, y=ty, width=tw, height=th)
        self.vbar_poc.place(x=10 + tw + 2, y=ty, width=14, height=th)
        rx = 10 + half + 10
        self.info_text_exp.place(x=rx, y=ty, width=tw, height=th)
        self.vbar_exp.place(x=rx + tw + 2, y=ty, width=14, height=th)
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
        if ua == tr("common.auto"):
            ua = self.ua.UserAgent()
        check = self.PoCInputCheck()
        if check == False:
            messagebox.showerror(tr("common.error"), tr("vuln.url_err"))
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
                        data = tr("common.unknown_error") + f" {e}"
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
                        data = tr("common.unknown_error") + f" {e}"
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
                return messagebox.showerror(tr("common.error"), "model type error!\nYou can view the vulns.json and try again!")
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
        if ua == tr("common.auto"):
            ua = self.ua.UserAgent()
        check = self.EXPInputCheck()
        if check == False:
            messagebox.showerror(tr("common.error"), tr("vuln.url_cmd_err"))
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
                return messagebox.showerror(tr("common.error"),"model type error!noly support py or async!\nYou can change model in the vulns.json and try again!")
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
       # messagebox.showinfo(tr("common.info"),"因不可抗因素，功能未开放······")
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
        path = filedialog.askopenfilename(title=tr("common.file_select"), filetypes=filetypes)
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
