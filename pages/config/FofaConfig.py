# coding:utf-8

from tkinter import messagebox
from tkinter import *
import tkinter.font as tkFont
import os

from util import JsonMethod

class FofaConfig:
    def __init__(self):
        self.fofapath = './config/fofa.json'
        self.configinit(self.fofapath)
    def configinit(self,path):
        self.config = JsonMethod.JsonMethod()
        if not os.path.exists(path):
            data = {
                "api":"https://fofa.info",
                "email":"",
                "key":"",
                "size":""
                }
            self.config.JsonWrite(data,path)
    def page(self):
        
        self.configinit(self.fofapath)
        
        self.window = Toplevel(name='fofa')
        self.window.title("Fofa设置")
        self.window.geometry("380x210")
        self.window.resizable(0, 0)

        # 初始化json读取
        fofaconfig = self.config.JsonRead(self.fofapath)
        
        Label(self.window, text="fofa api:", fg="black", font=("宋体", 12)).place(x=20, y=30)
        self.fofa_api_entry = Entry(self.window, width=22, font=tkFont.Font(size=12), bg='white')
        self.fofa_api_entry.place(x=120, y=30)

        self.fofa_api_entry.delete(0, 'end')
        self.fofa_api_entry.insert('insert', fofaconfig['api'])

        Label(self.window, text="fofa email:", fg="black", font=("宋体", 12)).place(x=20, y=60)
        self.fofa_email_entry = Entry(self.window, width=22, font=tkFont.Font(size=12), bg='white')
        self.fofa_email_entry.place(x=120, y=60)

        self.fofa_email_entry.delete(0, 'end')
        self.fofa_email_entry.insert('insert', fofaconfig['email'])

        Label(self.window, text="fofa key:", fg="black", font=("宋体", 12)).place(x=20, y=90)
        self.fofa_key_entry = Entry(self.window, width=22, font=tkFont.Font(size=12), bg='white')
        self.fofa_key_entry.place(x=120, y=90)

        self.fofa_key_entry.delete(0, 'end')
        self.fofa_key_entry.insert('insert', fofaconfig['key'])

        Label(self.window, text="fofa size:", fg="black", font=("宋体", 12)).place(x=20, y=120)
        self.fofa_size_entry = Entry(self.window, width=22, font=tkFont.Font(size=12), bg='white')
        self.fofa_size_entry.place(x=120, y=120)

        self.fofa_size_entry.delete(0, 'end')
        self.fofa_size_entry.insert('insert', fofaconfig['size'])
        
        # 保存与取消
        Button(self.window, text="保存", font=tkFont.Font(size=12), width=9, command=self.update,
               height=1, fg="white", bg="gray", activeforeground="white", activebackground="black",
               cursor="hand2").place(x=50, y=160)

        Button(self.window, text="取消", font=tkFont.Font(size=12), width=9, command=self.window.destroy,
               height=1, fg="white", bg="gray", activeforeground="white", activebackground="black",
               cursor="hand2").place(x=240, y=160)
        self.window.mainloop()
    def update(self):
        api = self.fofa_api_entry.get()
        email = self.fofa_email_entry.get()
        key = self.fofa_key_entry.get()
        size = self.fofa_size_entry.get()
        data = {
                "api":api,
                "email":email,
                "key":key,
                "size":size
                }
        self.config = JsonMethod.JsonMethod()
        self.config.JsonWrite(data,self.fofapath)
        messagebox.showinfo("更新","更新成功！")
if __name__ == "__main__":
    pass
    
