# coding:utf-8
import threading
from tkinter import *
from tkinter import messagebox, ttk, filedialog
import tkinter.font as tkFont
import os

from util import JsonMethod
from util import ProxyCheck
from util import SystemCheck

class ProxyConfig:
    def __init__(self):
        self.proxypath = './config/proxy.json'
        self.configinit(self.proxypath)
        self.sysType = SystemCheck.SystemType()
    def configinit(self,path):
        
        self.config = JsonMethod.JsonMethod()
        if not os.path.exists(path):
            data = {
                    "switch": 0,
                    "type": ["unkown","HTTP","SOCK5"],
                    "ip": "",
                    "port": "",
                    "user": "",
                    "passwd": ""
                }
            self.config.JsonWrite(data,path)
    def page(self):
        
        self.configinit(self.proxypath)
        
        self.window = Toplevel(name='proxy')
        self.window.title("代理设置")
        self.window.geometry("400x340")
        self.window.resizable(0, 0)

        # 初始化json读取
        proxyconfig = self.config.JsonRead(self.proxypath)

        self.status_var = StringVar(self.window)
        self.proxy_status = ttk.Checkbutton(self.window,variable=self.status_var,text="启用",onvalue=1,offvalue=0,cursor="hand2",command=self.switchCheck)
        self.proxy_status.place(x=160,y=20)
        self.status_var.set(proxyconfig['switch'])

        Label(self.window, text="type:", fg="black", font=("宋体", 12)).place(x=20, y=60)
        self.proxy_type = ttk.Combobox(self.window,width=9)
        self.proxy_type['value'] = proxyconfig['type']
        self.proxy_type.current(0)
        self.proxy_type.place(x=160,y=60)
        
        Label(self.window, text="ip:", fg="black", font=("宋体", 12)).place(x=20, y=90)
        self.ip_entry = Entry(self.window, width=22, font=tkFont.Font(size=12), bg='white')
        self.ip_entry.place(x=120, y=90)

        self.ip_entry.delete(0, 'end')
        self.ip_entry.insert('insert', proxyconfig['ip'])

        Label(self.window, text="port:", fg="black", font=("宋体", 12)).place(x=20, y=120)
        self.port_entry = Entry(self.window, width=22, font=tkFont.Font(size=12), bg='white')
        self.port_entry.place(x=120, y=120)

        self.port_entry.delete(0, 'end')
        self.port_entry.insert('insert', proxyconfig['port'])

        Label(self.window, text="user:", fg="black", font=("宋体", 12)).place(x=20, y=150)
        self.user_entry = Entry(self.window, width=22, font=tkFont.Font(size=12), bg='white')
        self.user_entry.place(x=120, y=150)

        self.user_entry.delete(0, 'end')
        self.user_entry.insert('insert', proxyconfig['user'])

        Label(self.window, text="passwd:", fg="black", font=("宋体", 12)).place(x=20, y=180)
        self.passwd_entry = Entry(self.window, width=22, font=tkFont.Font(size=12), bg='white')
        self.passwd_entry.place(x=120, y=180)

        self.passwd_entry.delete(0, 'end')
        self.passwd_entry.insert('insert', proxyconfig['passwd'])
        # 保存与取消
        self.checkBtn = Button(self.window, text="检查", font=tkFont.Font(size=12), width=9, command=self.proxycheck,
               height=1, fg="white", bg="gray", activeforeground="white", activebackground="black",
               cursor="hand2")
        self.checkBtn.place(x=50, y=210)
        
        Button(self.window, text="保存", font=tkFont.Font(size=12), width=9, command=self.update,
               height=1, fg="white", bg="gray", activeforeground="white", activebackground="black",
               cursor="hand2").place(x=150, y=210)
        
        Button(self.window, text="取消", font=tkFont.Font(size=12), width=9, command=self.window.destroy,
               height=1, fg="white", bg="gray", activeforeground="white", activebackground="black",
               cursor="hand2").place(x=250, y=210)

        Label(self.window, text="代理清洗:", fg="black", font=("宋体", 12)).place(x=20, y=260)
        self.file_entry = Entry(self.window, width=22, font=tkFont.Font(size=12), bg='Ivory',cursor="hand2")
        self.file_entry.place(x=120, y=260)
        self.file_entry.bind("<Button-1>",self.filedir)
        self.btnClear = Button(self.window, text="清洗", font=tkFont.Font(size=12), width=9, command=self.proxycheckfile,
               height=1, fg="white", bg="gray", activeforeground="white", activebackground="black",
               cursor="hand2")
        self.btnClear.place(x=150, y=290)

        self.switchCheck()
        
        self.window.mainloop()
    def update(self):
        switch = int(self.status_var.get())
        ip = self.ip_entry.get()
        port = self.port_entry.get()
        user = self.user_entry.get()
        passwd = self.passwd_entry.get()
        data = {
                "switch": switch,
                "type": ["unkown","HTTP","SOCK5"],
                "ip": ip,
                "port": port,
                "user": user,
                "passwd": passwd
                }
        self.config = JsonMethod.JsonMethod()
        self.config.JsonWrite(data,self.proxypath)
        messagebox.showinfo("更新","更新成功！")
    def filedir(self,event):
        self.dirsPath(self.file_entry)
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
        entry.delete(0, 'end')
        entry.insert('insert', path)
    def proxycheckfile(self):
        try:
            threadCheck = threading.Thread(target=self.ProxyCheckFile)
            threadCheck.setDaemon(True)
            threadCheck.start()
        except Exception as e:
            messagebox.showinfo('error', f'unkown error\n{e}')
    def ProxyCheckFile(self):
        self.btnClear.config(state="disable")
        file = self.file_entry.get()
        check = ProxyCheck.ProxyCheck()
        check.checkfile(file)
        messagebox.showinfo("提示",f"代理清洗成功已保存至 {file} ")
        self.btnClear.config(state="normal")
    def proxycheck(self):
        ip = self.ip_entry.get()
        port = self.port_entry.get()
        proxy = "{ip}:{port}".format(ip=ip,port=port)
        check = ProxyCheck.ProxyCheck()
        useful = check.checkurl(proxy)
        if useful != False:
            messagebox.showinfo("提示","代理可用！")
        else:
            messagebox.showerror("错误","代理不可用！")
    def switchCheck(self):
        switch = int(self.status_var.get())
        if switch == 0:
            self.proxy_type.config(state="disable")
            self.ip_entry.config(state="disable")
            self.port_entry.config(state="disable")
            self.user_entry.config(state="disable")
            self.passwd_entry.config(state="disable")
            self.checkBtn.config(state="disable") 
        else:
            self.proxy_type.config(state="normal")
            self.ip_entry.config(state="normal")
            self.port_entry.config(state="normal")
            self.user_entry.config(state="normal")
            self.passwd_entry.config(state="normal")
            self.checkBtn.config(state="normal")
if __name__ == "__main__":
    pass
    
