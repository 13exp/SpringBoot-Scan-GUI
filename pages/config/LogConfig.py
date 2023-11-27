# coding:utf-8

from tkinter import *
from tkinter import messagebox,ttk
import tkinter.font as tkFont
import os

from util import JsonMethod

class LogConfig:
    def __init__(self):
        self.logpath = './config/logs.json'
        self.configinit(self.logpath)
    def configinit(self,path):
        self.config = JsonMethod.JsonMethod()
        if not os.path.exists(path):
            data = {
                "switch": 0,
                "scanlog_path": "./logs/urls.log",
                "vulnlog_path": "./logs/vuln.log",
                "dumplog_path": "./logs/dump.log",
                "errorlog_path": "./logs/error.log"
                }
            self.config.JsonWrite(data,path)
    def page(self):
        self.configinit(self.logpath)
        # 初始化json读取
        logconfig = self.config.JsonRead(self.logpath)
        
        self.window = Toplevel(name='log')
        self.window.title("日志设置")
        self.window.geometry("400x240")
        self.window.resizable(0, 0)
        
        self.status_var = StringVar(self.window)
        self.proxy_status = ttk.Checkbutton(self.window,variable=self.status_var,text="启用",onvalue=1,offvalue=0,cursor="hand2",command=self.switchCheck)
        self.proxy_status.place(x=160,y=20)
        self.status_var.set(logconfig['switch'])

        Label(self.window, text="scanlog_path:", fg="black", font=("宋体", 12)).place(x=20, y=60)
        self.scanlog_path = Entry(self.window, width=22, font=tkFont.Font(size=12), bg='white')
        self.scanlog_path.place(x=130, y=60)

        self.scanlog_path.delete(0, 'end')
        self.scanlog_path.insert('insert', logconfig['scanlog_path'])

        Label(self.window, text="vulnlog_path:", fg="black", font=("宋体", 12)).place(x=20, y=90)
        self.vulnlog_path = Entry(self.window, width=22, font=tkFont.Font(size=12), bg='white')
        self.vulnlog_path.place(x=130, y=90)

        self.vulnlog_path.delete(0, 'end')
        self.vulnlog_path.insert('insert', logconfig['vulnlog_path'])

        Label(self.window, text="dumplog_path:", fg="black", font=("宋体", 12)).place(x=20, y=120)
        self.dumplog_path = Entry(self.window, width=22, font=tkFont.Font(size=12), bg='white')
        self.dumplog_path.place(x=130, y=120)

        self.dumplog_path.delete(0, 'end')
        self.dumplog_path.insert('insert', logconfig['dumplog_path'])

        Label(self.window, text="errorlog_path:", fg="black", font=("宋体", 12)).place(x=20, y=150)
        self.errorlog_path = Entry(self.window, width=22, font=tkFont.Font(size=12), bg='white')
        self.errorlog_path.place(x=130, y=150)

        self.errorlog_path.delete(0, 'end')
        self.errorlog_path.insert('insert', logconfig['errorlog_path'])

        # 保存与取消
        Button(self.window, text="保存", font=tkFont.Font(size=12), width=9, command=self.update,
               height=1, fg="white", bg="gray", activeforeground="white", activebackground="black",
               cursor="hand2").place(x=50, y=190)

        Button(self.window, text="取消", font=tkFont.Font(size=12), width=9, command=self.window.destroy,
               height=1, fg="white", bg="gray", activeforeground="white", activebackground="black",
               cursor="hand2").place(x=240, y=190)

        self.switchCheck()
        
        self.window.mainloop()
    def update(self):
        switch = int(self.status_var.get())
        scanlog_path = self.scanlog_path.get()
        vulnlog_path = self.vulnlog_path.get()
        dumplog_path = self.dumplog_path.get()
        errorlog_path = self.errorlog_path.get()
        data = {
                "switch": switch,
                "scanlog_path": scanlog_path,
                "vulnlog_path": vulnlog_path,
                "dumplog_path": dumplog_path,
                "errorlog_path": errorlog_path
                }
        self.config = JsonMethod.JsonMethod()
        self.config.JsonWrite(data,self.logpath)
        messagebox.showinfo("更新","更新成功！")
    def switchCheck(self):
        switch = int(self.status_var.get())
        if switch == 0:
            self.scanlog_path.config(state="disable")
            self.vulnlog_path.config(state="disable")
            self.dumplog_path.config(state='disable')
            self.errorlog_path.config(state='disable')
        else:
            self.scanlog_path.config(state="normal")
            self.vulnlog_path.config(state="normal")
            self.dumplog_path.config(state="normal")
            self.errorlog_path.config(state="normal")
if __name__ == "__main__":
    pass
    
