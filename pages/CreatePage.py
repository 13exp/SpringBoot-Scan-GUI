# coding:utf-8

import requests, base64, json, yaml

from util import SystemCheck
from util import InputCheck
from util import URLMethod
from util import JsonMethod
from pages.config import FofaConfig
import tkinter.messagebox as messagebox
import tkinter.font as tkFont
import tkinter as tk
from tkinter import *

class CreatePage:
    def __init__(self,windows):
        # 操作系统类型
        self.sysType = SystemCheck.SystemType()

        # tk.Label(windows,text="id:",font=("宋体",16)).place(x=20,y=15)
        self.id = Entry(windows, width=40, bg='Ivory')
        # self.id.place(x=105,y=20)

        # tk.Label(windows,text="info",font=("宋体",16)).place(x=20,y=45)

        # tk.Label(windows,text="name:",font=("宋体",16)).place(x=20,y=75)
        self.name = Entry(windows, width=40, bg='Ivory')
        # self.name.place(x=105, y=80)

        # tk.Label(windows,text="author:",font=("宋体",16)).place(x=20,y=105)
        self.author = Entry(windows, width=40, bg='Ivory')
        # self.author.place(x=105, y=110)

        tk.Label(windows,text="severity")

        tk.Label(windows,text="description")

        tk.Label(windows,text="reference")

        self.info_classification = tk.Label(windows,text="classification")
        tk.Label(windows,text="cvss-metrics")

        tk.Label(windows,text="cvss-score")

        tk.Label(windows,text="cwe-id")

        tk.Label(windows,text="tags")

        self.metadata = tk.Label(windows,text="metadata")

        self.http = tk.Label(windows,text="http")

        tk.Label(windows,text="method")

        tk.Label(windows,text="path")

        tk.Label(windows,text="Rheader")

        tk.Label(windows,text="body")

        tk.Label(windows,text="matchers-condition")

        tk.Label(windows,text="matchers")

    def create(self):
        data = {
            "id":""
        }