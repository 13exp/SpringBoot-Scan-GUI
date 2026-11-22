# coding:utf-8
from tkinter import ttk

import requests, base64, json,threading

from com import Banner
from util import RandomUA
from util import InputCheck
from util import URLMethod
from util import JsonMethod
from util.Translate import tr
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

        # 布局（mise en page mesurée et redimensionnable）
        self.windows = windows
        self.frame_left = Frame(windows)
        self.frame_right = Frame(windows)

        lab_rule = Label(self.frame_left, text=tr("fofa.search_syntax"), fg="black", font=("宋体", 12))
        self.asset_rule = Entry(self.frame_left, font=tkFont.Font(size=14), bg='Ivory')
        self.asset_rule.insert(0, 'icon_hash="116323821" || body="Whitelabel Error Page"')
        self.btnSet = Button(self.frame_left, text=tr("fofa.config"), font=tkFont.Font(size=12), command=fofaconfig.page,
               fg="white", bg="gray", activeforeground="white", activebackground="black",
               cursor="hand2")
        self.btnQery = Button(self.frame_left, text=tr("fofa.query"), font=tkFont.Font(size=12), command=self.btnFofa,
               fg="white", bg="gray", activeforeground="white", activebackground="black",
               cursor="hand2")
        self.btnOutput = Button(self.frame_left, text=tr("fofa.export"), font=tkFont.Font(size=12), command=self.output,
               fg="white", bg="gray", activeforeground="white", activebackground="black",
               cursor="hand2")

        self.vbar_asset = ttk.Scrollbar(self.frame_left)
        self.asset_info = Text(self.frame_left, yscrollcommand=self.vbar_asset.set)
        self.vbar_asset.config(command=self.asset_info.yview)

        ua = RandomUA.RandomUA()
        self.ua = ua.UserAgent()
        self.header = {
            'User-Agent': self.ua,
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
        }
        # 右方区域
        lab_rules = Label(self.frame_right, text=tr("fofa.rules_title"), fg="black", font=("宋体", 12))

        self.vbar_rules = ttk.Scrollbar(self.frame_right)
        self.fofa_rules = Text(self.frame_right, yscrollcommand=self.vbar_rules.set)
        self.vbar_rules.config(command=self.fofa_rules.yview)
        self.fofa_rules.insert(tk.INSERT,Banner.FofaInfo())
        self.fofa_rules.config(state='disable')

        # mesures réelles (constantes pour la langue courante), positions via _layout()
        self._bw_set = self.btnSet.winfo_reqwidth() + 24
        self._lw = lab_rule.winfo_reqwidth()
        self._bw_q = self.btnQery.winfo_reqwidth() + 24
        self._bw_o = self.btnOutput.winfo_reqwidth() + 24
        self._hh = max(self.asset_rule.winfo_reqheight(), self.btnSet.winfo_reqheight())
        self._lab_rule = lab_rule
        self._lab_rules = lab_rules
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
        # largeur mini : simulée pour garantir ≥150px au champ de recherche
        rex = self._bw_set + 10 + self._lw + 10
        need_w = 1200
        while need_w < 2600:
            frw = max(260, int(need_w * 0.235))
            flw = need_w - frw - 35
            if flw - rex - self._bw_q - self._bw_o - 30 >= 150:
                break
            need_w += 25
        need_h = 8 + self._hh + 12 + 200
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

        # répartition gauche (résultats) / droite (syntaxe)
        frw = max(260, int(w * 0.235))
        flw = max(400, w - frw - 35)
        frx = 10 + flw + 15
        self.frame_left.place(x=10, y=0, width=flw, height=h - 10)
        self.frame_right.place(x=frx, y=0, width=frw, height=h - 10)

        setx = 0
        labx = setx + self._bw_set + 10
        rex = labx + self._lw + 10
        # champ de recherche : largeur réellement disponible entre libellé et boutons
        rew = max(100, flw - rex - self._bw_q - self._bw_o - 30)
        hy = 8
        self.btnSet.place(x=setx, y=hy, width=self._bw_set, height=self._hh)
        self._lab_rule.place(x=labx, y=hy + 4)
        self.asset_rule.place(x=rex, y=hy, width=rew)
        self.btnQery.place(x=flw - self._bw_o - self._bw_q - 10, y=hy, width=self._bw_q, height=self._hh)
        self.btnOutput.place(x=flw - self._bw_o - 10, y=hy, width=self._bw_o, height=self._hh)

        ty = hy + self._hh + 12
        th = max(120, h - ty - 14)
        self.asset_info.place(x=0, y=ty, width=flw - 18, height=th)
        self.vbar_asset.place(x=flw - 16, y=ty, width=14, height=th)

        self._lab_rules.place(x=(frw - self._lab_rules.winfo_reqwidth()) // 2, y=12)
        self.fofa_rules.place(x=0, y=ty, width=frw - 18, height=th)
        self.vbar_rules.place(x=frw - 16, y=ty, width=14, height=th)
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
            messagebox.showerror(tr("common.error"),tr("fofa.rule_empty"))
        else:
            try:
                self.fofa(rule)
            except:
                messagebox.showerror(tr("common.error"), tr("fofa.syntax_err"))
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
        messagebox.showinfo(tr("common.info"), tr("fofa.export_ok"))
        self.btnQery.config(state="normal")
        self.btnOutput.config(state="normal")
