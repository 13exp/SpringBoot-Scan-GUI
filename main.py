#!/usr/bin/env python
# coding=utf-8

from tkinter import *
from tkinter import ttk

from pages import FofaPage
from pages import CreatePage
from pages import ScanPage
from pages import VulnPage

from com import MenuTab

from util import SystemCheck
from util import Translate

class SpringBootScanGUI:
    def __init__(self):
        systype = SystemCheck.SystemType()

        # set when the user picks a new language in the menu
        self.restart_requested = False

        self.window = Tk()
        self.window.title("SpringBootScanGUI   by:13EXP")
        self.window.resizable(True, True)
        if systype == 'Windows':
            self.window.iconbitmap('./images/gui.ico')

        # open maximized (full screen); F11 toggles true fullscreen
        self.fullscreen = False
        self.maximize()
        self.window.bind("<F11>", self.toggle_fullscreen)

        tabControl = ttk.Notebook(self.window)

        self.leakagetab = ttk.Frame(tabControl)
        self.exptab = ttk.Frame(tabControl)
        self.fofatab = ttk.Frame(tabControl)
        # self.createtab = ttk.Frame(tabControl)

        tabControl.add(self.leakagetab,text=Translate.tr("tab.leak"))
        tabControl.add(self.exptab,text=Translate.tr("tab.vuln"))
        tabControl.add(self.fofatab,text=Translate.tr("tab.fofa"))
        # tabControl.add(self.createtab, text="PoC制作台")

        # 载入页面
        ScanPage.ScanPage(self.leakagetab)
        VulnPage.VulnPage(self.exptab)
        FofaPage.FofaPage(self.fofatab)
        # CreatePage.CreatePage(self.createtab)
        # 初始化菜单功能
        MenuTab.MenuTab(self.window, on_language_change=self.change_language)

        tabControl.pack(expand=1,fill="both")
        self.window.mainloop()

    def maximize(self):
        # Windows
        try:
            self.window.state('zoomed')
            return
        except Exception:
            pass
        # Linux (EWMH-compliant window managers)
        try:
            self.window.attributes('-zoomed', True)
            return
        except Exception:
            pass
        # Fallback: cover the whole screen manually
        sw = self.window.winfo_screenwidth()
        sh = self.window.winfo_screenheight()
        self.window.geometry("{w}x{h}+0+0".format(w=sw, h=sh))

    def toggle_fullscreen(self, event=None):
        self.fullscreen = not self.fullscreen
        try:
            self.window.attributes("-fullscreen", self.fullscreen)
        except Exception:
            pass
        return "break"

    def change_language(self, lang):
        Translate.save_lang(lang)
        self.restart_requested = True
        self.window.destroy()

def default_language():
    # first run: start in English; the language can then be changed
    # at any time via the Menu -> Language menu
    if Translate.saved_lang() is None:
        Translate.save_lang("US")

if __name__ == '__main__':
    default_language()
    while True:
        # reload the string table on every (re)build so a language
        # change from the menu applies immediately
        Translate.load()
        start = SpringBootScanGUI()
        # destroyed on language change: rebuild the whole UI with the new table
        if not start.restart_requested:
            break
