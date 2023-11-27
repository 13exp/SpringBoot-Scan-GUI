# coding:utf-8

import os,re

class InputCheck:
    def isNull(self,check):
        if check == "":
            return True
        else:
            return False
    def FileOrUrl(self,check):
        url_regex = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
        url_pattern = re.compile(url_regex)
        ip_regex = r'(([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5])\.){3}([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5])'
        # url2_regex = r'(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
        if os.path.isfile(check):
            return "isFile"
        elif url_pattern.match(check) != None or re.match(ip_regex,check) != None:
            # or re.match(url2_regex,check) != None
            return "isURL"
        else:
            return False
    def UserAgent(self,check):
        if check == "自动":
            return True
        else:
            return False
if __name__ == "__main__":
    url = InputCheck()
    check = url.FileOrUrl('192.168.0.1')
    print(check)
