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

class SpringBootScanGUI:
    def __init__(self):
        self.window = Tk()
        self.window.title("SpringBootScanGUI   by:13EXP")
        self.window.geometry("1230x600")
        self.window.resizable(0, 0)
        self.window.iconbitmap('./images/gui.ico')

        tabControl = ttk.Notebook(self.window)
        
        self.leakagetab = ttk.Frame(tabControl)
        self.exptab = ttk.Frame(tabControl)
        self.fofatab = ttk.Frame(tabControl)
        # self.createtab = ttk.Frame(tabControl)

        tabControl.add(self.leakagetab,text="泄露扫描")
        tabControl.add(self.exptab,text="漏洞扫描")
        tabControl.add(self.fofatab,text="Fofa资产测绘")
        # tabControl.add(self.createtab, text="PoC制作台")

        # 载入页面
        ScanPage.ScanPage(self.leakagetab)
        VulnPage.VulnPage(self.exptab)
        FofaPage.FofaPage(self.fofatab)
        # CreatePage.CreatePage(self.createtab)
        # 初始化菜单功能
        MenuTab.MenuTab(self.window)

        tabControl.pack(expand=1,fill="both")
        self.window.mainloop()
if __name__ == '__main__':
    start = SpringBootScanGUI()
    '''systype = SystemCheck.SystemType()
    if systype == 'Windows':
        if SystemCheck.is_admin():
            start = SpringBootScanGUI()
        else:
            ctypes.windll.shell32.ShellExecuteW(None,"runas", sys.executable, __file__, None, 1)
    elif systype == 'Linux':
        if SystemCheck.is_root():
            start = SpringBootScanGUI()
        else:
            print(False)
    elif systype == 'macOS':
        if SystemCheck.is_root():
            start = SpringBootScanGUI()
        else:
            print(False)
    else:
        print('Faild Start Process...Please try agine!')'''
