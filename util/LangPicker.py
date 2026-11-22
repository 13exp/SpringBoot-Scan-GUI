# coding:utf-8
"""First-run language selection dialog."""

import tkinter as tk

from util import Translate


class LangPicker:

    @staticmethod
    def ask():
        """Show a small window and return the picked language code."""
        picked = {"lang": Translate.detect_lang()}

        root = tk.Tk()
        root.title("Language / Langue / 语言")
        root.geometry("340x150")
        root.resizable(0, 0)

        tk.Label(root, text="Please choose your language\nChoisissez votre langue\n请选择语言",
                 font=("Arial", 11)).pack(pady=15)

        def pick(lang):
            picked["lang"] = lang
            Translate.save_lang(lang)
            root.destroy()

        frame = tk.Frame(root)
        frame.pack(pady=5)
        tk.Button(frame, text="中文", width=9, height=1, command=lambda: pick("CN")).grid(row=0, column=0, padx=10)
        tk.Button(frame, text="English", width=9, height=1, command=lambda: pick("US")).grid(row=0, column=1, padx=10)
        tk.Button(frame, text="Français", width=9, height=1, command=lambda: pick("FR")).grid(row=0, column=2, padx=10)

        root.protocol("WM_DELETE_WINDOW", root.destroy)
        root.mainloop()
        return picked["lang"]
