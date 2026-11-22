# coding:utf-8

import webbrowser,requests,sys,os
from tkinter import *
from tkinter import messagebox

from pages.config import FofaConfig
from pages.config import VulnConfig
from pages.config import LogConfig
from pages.config import ProxyConfig
from util import JsonMethod
from util import Translate
from util.Translate import tr

class MenuTab:
    def __init__(self,window,on_language_change=None):
        self.window = window
        self.on_language_change = on_language_change

        # 初始化读取配置功能页面
        self.fofaconfig = FofaConfig.FofaConfig()
        self.proxyconfig = ProxyConfig.ProxyConfig()
        self.logconfig = LogConfig.LogConfig()
        self.vulnconfig = VulnConfig.VulnConfig()
        # 获得当前版本
        self.version_load = JsonMethod.JsonMethod()
        # menutab
        menu = Menu(self.window)
        menu_kid = Menu(menu, tearoff=0)
        menu.add_cascade(label=tr("menu.menu"), menu=menu_kid)
        menu_clear = Menu(menu_kid, tearoff=0)
        menu_kid.add_cascade(label='clear', menu=menu_clear)
        menu_clear.add_command(label='save', command=self.SaveClear)
        menu_clear.add_command(label='logs', command=self.LogsClear)
        menu_kid.add_separator()
        menu_kid.add_command(label='FofaInfo', command=self.FofaInfo)
        menu_kid.add_command(label='ShellInfo', command=self.ShellInfo)
        menu_kid.add_separator()
        menu_kid.add_command(label=tr("menu.exit"), command=self.Exit, accelerator='Esc')

        menu_set = Menu(menu, tearoff=0)
        menu.add_cascade(label=tr("menu.config"), menu=menu_set)
        menu_set.add_command(label=tr("menu.fofa_cfg"), command=self.fofaconfig.page, accelerator='Ctrl+F')
        menu_set.add_command(label=tr("menu.proxy_cfg"), command=self.proxyconfig.page, accelerator='Ctrl+P')
        menu_set.add_command(label=tr("menu.log_cfg"), command=self.logconfig.page, accelerator='Ctrl+U')
        menu_set.add_command(label=tr("menu.vuln_cfg"), command=self.vulnconfig.page, accelerator='Ctrl+G')

        menu_lang = Menu(menu, tearoff=0)
        menu.add_cascade(label=tr("menu.language"), menu=menu_lang)
        menu_lang.add_command(label='中文', command=lambda: self.SwitchLanguage('CN'))
        menu_lang.add_command(label='English', command=lambda: self.SwitchLanguage('US'))
        menu_lang.add_command(label='Français', command=lambda: self.SwitchLanguage('FR'))

        menu_help = Menu(menu, tearoff=0)
        menu.add_cascade(label=tr("menu.help"), menu=menu_help)
        menu_help.add_command(label='issues', command=self.Issues)
        menu_help.add_command(label=tr("menu.about"), command=self.About)

        menu_about = Menu(menu, tearoff=0)
        menu.add_cascade(label=tr("menu.more"), menu=menu_about)
        menu_about.add_command(label='13EXP', command=self.MyGitHub)
        menu_about.add_command(label='AabyssZGBlog', command=self.AabyssZGBlog)
        menu_about.add_command(label='FofaViwer', command=self.FofaViwer)
        menu_about.add_command(label='HongYan', command=self.MoreVulns)
        menu_about.add_command(label=tr("menu.check_update"), command=self.UpdateCheck)
        # 右键菜单加载
        self.MenuPageRight()

        self.window.config(menu=menu)
    def SwitchLanguage(self,lang):
        if self.on_language_change is not None:
            self.on_language_change(lang)
    def SaveClear(self):
        path = "./save"
        result = self.DirClear(path)
        messagebox.showinfo(tr("menu.del_title"),result)
    def LogsClear(self):
        path = "./logs"
        result = self.DirClear(path)
        messagebox.showinfo(tr("menu.del_title"), result)
    def DirClear(self,path):
        if os.path.exists(path):
            for root, dirs, files in os.walk(path, topdown=False):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        os.remove(file_path)
                    except:
                        result = tr("menu.del_file_err")
                        return result
                for dir in dirs:
                    dir_path = os.path.join(root, dir)
                    try:
                        os.rmdir(dir_path)
                    except:
                        result = tr("menu.del_dir_err")
                        return result
            result = tr("menu.del_ok", path=path)
            return result
        else:
            os.mkdir(path)
            result = tr("menu.del_missing", path=path)
            return result
    def UpdateCheck(self):
        try:
            git_url = "https://raw.githubusercontent.com/13exp/SpringBoot-Scan-GUI/main/config/version.json"
            now_version = self.version_load.JsonRead("./config/version.json")["version"]
            req = requests.get(url=git_url)
            git_version = eval(req.text)["version"]
            if git_version > now_version:
                update = messagebox.askokcancel(tr("common.update"),tr("menu.update_found", version=git_version))
                if update == True:
                    webbrowser.open('https://github.com/13exp/SpringBoot-Scan-GUI')
            else:
                 messagebox.showinfo(tr("common.update"), tr("menu.update_latest"))
        except:
            messagebox.showerror(tr("common.error"), tr("menu.update_fail"))
    def FofaInfo(self):
        messagebox.showinfo("FofaInfo",tr("menu.fofa_info"))

    def ShellInfo(self):
        messagebox.showinfo("CVE-2022-22965 ShellInfo","CVE-2022-22965     :    shell.jsp?cmd=whoami\n22965-13exp-shell :    wbexp.jsp?pwd=13exp&cmd=whoami\n22965-aabyss-shell:    tomcatwar.jsp?pwd=aabysszg&cmd=whoami")

    def Exit(self):
        Exit = messagebox.askokcancel(tr("menu.exit"),tr("menu.exit_confirm"))
        if Exit == True:
            self.window.destroy()
            sys.exit()

    def About(self):
        messagebox.showinfo(tr("menu.about"),tr("menu.about_text"))

    def FofaViwer(self):
        webbrowser.open('https://github.com/wgpsec/fofa_viewer')

    def MyGitHub(self):
        webbrowser.open('https://github.com/13exp/SpringBoot-Scan-GUI')

    def AabyssZGBlog(self):
        webbrowser.open('https://blog.zgsec.cn/archives/129.html')

    def MoreVulns(self):
        webbrowser.open('https://github.com/hongyan454/SpringBootVulExploit')
    def VulnRight(self,event=None):
        self.vulnconfig.page()
    def FofaRight(self,event=None):
        self.fofaconfig.page()
    def ProxyRight(self,event=None):
        self.proxyconfig.page()
    def LogsRight(self,event=None):
        self.logconfig.page()
    def ExitRight(self,event=None):
        self.Exit()
    def Issues(self):
        webbrowser.open('https://github.com/13exp/SpringBoot-Scan-GUI/issues')
    def MenuPageRight(self):
        # 右键菜单设置
        self.menu_right = Menu(self.window, tearoff=False)
        # self.menu_right.add_command(label='漏扫利用', command=self.vule, accelerator='Ctrl+R')
        # self.menu_right.add_separator()
        self.right_config = Menu(self.menu_right, tearoff=0)
        self.menu_right.add_cascade(label=tr("menu.config"), menu=self.right_config)
        self.right_config.add_command(label=tr("menu.fofa_cfg"), command=self.fofaconfig.page, accelerator='Ctrl+F')
        self.right_config.add_command(label=tr("menu.proxy_cfg"), command=self.proxyconfig.page, accelerator='Ctrl+P')
        self.right_config.add_command(label=tr("menu.log_cfg"), command=self.logconfig.page, accelerator='Ctrl+U')
        self.right_config.add_command(label=tr("menu.vuln_cfg"), command=self.vulnconfig.page, accelerator='Ctrl+G')
        self.right_more = Menu(self.menu_right, tearoff=0)
        self.menu_right.add_cascade(label=tr("menu.more"), menu=self.right_more)
        self.right_more.add_command(label='13EXP', command=self.MyGitHub)
        self.right_more.add_command(label=tr("menu.usage"), command=self.AabyssZGBlog)
        self.right_more.add_command(label='FofaViewer', command=self.FofaViwer)
        self.right_more.add_command(label='HongYan', command=self.MoreVulns)
        self.right_more.add_command(label=tr("menu.check_update"), command=self.UpdateCheck)
        self.menu_right.add_separator()
        self.right_clear = Menu(self.menu_right, tearoff=0)
        self.menu_right.add_cascade(label=tr("menu.clear"), menu=self.right_clear)
        self.right_clear.add_command(label='save', command=self.SaveClear)
        self.right_clear.add_command(label='logs', command=self.LogsClear)
        self.menu_right.add_separator()
        self.menu_right.add_command(label=tr("menu.exit"), command=self.Exit, accelerator='Esc')
        # 快捷键
        self.window.bind("<Control-f>", self.FofaRight)
        self.window.bind("<Control-F>", self.FofaRight)
        self.window.bind("<Control-p>", self.ProxyRight)
        self.window.bind("<Control-P>", self.ProxyRight)
        self.window.bind("<Control-u>", self.LogsRight)
        self.window.bind("<Control-U>", self.LogsRight)
        self.window.bind("<Control-g>", self.VulnRight)
        self.window.bind("<Control-G>", self.VulnRight)
        self.window.bind("<Escape>", self.ExitRight)
        self.window.bind("<Button-3>", self.MenuRight)
    def MenuRight(self,event):
        global right
        self.menu_right.post(event.x_root, event.y_root)
