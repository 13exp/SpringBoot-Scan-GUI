# coding:utf-8

import webbrowser,requests,sys,os
from tkinter import *
from tkinter import messagebox

from pages.config import FofaConfig
from pages.config import VulnConfig
from pages.config import LogConfig
from pages.config import ProxyConfig
from util import JsonMethod
class MenuTab:
    def __init__(self,window):
        self.window = window

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
        menu.add_cascade(label='菜单', menu=menu_kid)
        menu_clear = Menu(menu_kid, tearoff=0)
        menu_kid.add_cascade(label='clear', menu=menu_clear)
        menu_clear.add_command(label='save', command=self.SaveClear)
        menu_clear.add_command(label='logs', command=self.LogsClear)
        menu_kid.add_separator()
        menu_kid.add_command(label='FofaInfo', command=self.FofaInfo)
        menu_kid.add_command(label='ShellInfo', command=self.ShellInfo)
        menu_kid.add_separator()
        menu_kid.add_command(label='退出', command=self.Exit, accelerator='Esc')

        menu_set = Menu(menu, tearoff=0)
        menu.add_cascade(label='配置', menu=menu_set)
        menu_set.add_command(label='资产测绘', command=self.fofaconfig.page, accelerator='Ctrl+F')
        menu_set.add_command(label='代理设置', command=self.proxyconfig.page, accelerator='Ctrl+P')
        menu_set.add_command(label='日志设置', command=self.logconfig.page, accelerator='Ctrl+U')
        menu_set.add_command(label='漏扫设置', command=self.vulnconfig.page, accelerator='Ctrl+G')

        menu_help = Menu(menu, tearoff=0)
        menu.add_cascade(label='帮助', menu=menu_help)
        menu_help.add_command(label='issues', command=self.Issues)
        menu_help.add_command(label='关于', command=self.About)

        menu_about = Menu(menu, tearoff=0)
        menu.add_cascade(label='更多', menu=menu_about)
        menu_about.add_command(label='13EXP', command=self.MyGitHub)
        menu_about.add_command(label='AabyssZGBlog', command=self.AabyssZGBlog)
        menu_about.add_command(label='FofaViwer', command=self.FofaViwer)
        menu_about.add_command(label='HongYan', command=self.MoreVulns)
        menu_about.add_command(label='检查更新', command=self.UpdateCheck)
        # 右键菜单加载
        self.MenuPageRight()

        self.window.config(menu=menu)
    def SaveClear(self):
        path = "./save"
        result = self.DirClear(path)
        messagebox.showinfo("删除",result)
    def LogsClear(self):
        path = "./logs"
        result = self.DirClear(path)
        messagebox.showinfo("删除", result)
    def DirClear(self,path):
        if os.path.exists(path):
            for root, dirs, files in os.walk(path, topdown=False):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        os.remove(file_path)
                    except:
                        result = "删除文件时出现未知错误！"
                        return result
                for dir in dirs:
                    dir_path = os.path.join(root, dir)
                    try:
                        os.rmdir(dir_path)
                    except:
                        result = "删除目录时出现未知错误！"
                        return result
            result = f"删除{path}下文件成功"
            return result
        else:
            os.mkdir(path)
            result = f"不存在{path}已自动创建!"
            return result
    def UpdateCheck(self):
        try:
            git_url = "https://raw.githubusercontent.com/13exp/SpringBoot-Scan-GUI/main/config/version.json"
            now_version = self.version_load.JsonRead("./config/version.json")["version"]
            req = requests.get(url=git_url)
            git_version = eval(req.text)["version"]
            if git_version > now_version:
                update = messagebox.askokcancel("更新",f"检测到新版本{git_version},是否前往更新？")
                if update == True:
                    webbrowser.open('https://github.com/13exp/SpringBoot-Scan-GUI')
            else:
                 messagebox.showinfo("更新", "当前已为最新版本")
        except:
            messagebox.showerror("错误", "网络、代理或未知错误，检查更新失败！\n请稍后再试")
    def FofaInfo(self):
        messagebox.showinfo("Fofa语法",'根据图标     :    icon_hash="116323821"\n网页内容识别 :    body="Whitelabel Error Page"')

    def ShellInfo(self):
        messagebox.showinfo("CVE-2022-22965 Shell信息","CVE-2022-22965     :    shell.jsp?cmd=whoami\n22965-13exp-shell :    wbexp.jsp?pwd=13exp&cmd=whoami\n22965-aabyss-shell:    tomcatwar.jsp?pwd=aabysszg&cmd=whoami")

    def Exit(self):
        Exit = messagebox.askokcancel('退出','确定退出吗?')
        if Exit == True:
            self.window.destroy()
            sys.exit()

    def About(self):
        messagebox.showinfo("关于","敬请期待···")

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
        self.menu_right.add_cascade(label='配置', menu=self.right_config)
        self.right_config.add_command(label='资产测绘', command=self.fofaconfig.page, accelerator='Ctrl+F')
        self.right_config.add_command(label='代理设置', command=self.proxyconfig.page, accelerator='Ctrl+P')
        self.right_config.add_command(label='日志设置', command=self.logconfig.page, accelerator='Ctrl+U')
        self.right_config.add_command(label='漏扫设置', command=self.vulnconfig.page, accelerator='Ctrl+G')
        self.menu_right.add_separator()
        self.right_more = Menu(self.menu_right, tearoff=0)
        self.menu_right.add_cascade(label='更多', menu=self.right_more)
        self.right_more.add_command(label='13EXP', command=self.MyGitHub)
        self.right_more.add_command(label='利用姿势', command=self.AabyssZGBlog)
        self.right_more.add_command(label='FofaViewer', command=self.FofaViwer)
        self.right_more.add_command(label='HongYan', command=self.MoreVulns)
        self.right_more.add_command(label='检查更新', command=self.UpdateCheck)
        self.menu_right.add_separator()
        self.right_clear = Menu(self.menu_right, tearoff=0)
        self.menu_right.add_cascade(label='清除', menu=self.right_clear)
        self.right_clear.add_command(label='save', command=self.SaveClear)
        self.right_clear.add_command(label='logs', command=self.LogsClear)
        self.menu_right.add_separator()
        self.menu_right.add_command(label='退出', command=self.Exit, accelerator='Esc')
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