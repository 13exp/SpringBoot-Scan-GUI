# coding:utf-8

from time import strftime, localtime

from util import JsonMethod

class LogsMethod:
    def __init__(self):
        self.config = JsonMethod.JsonMethod()
        config = self.config.LogsConfigRead()
        self.scanlog_path = config['scanlog_path']
        self.vulnlog_path = config['vulnlog_path']
        self.errorlog_path = config['errorlog_path']
        self.dumplog_path = config['dumplog_path']
    def sacnlogs(self,info):
        log = info + '  ' + strftime("%Y-%m-%d %H:%M:%S", localtime())
        with open(self.scanlog_path,'a') as f:
            f.write(log)
            f.write("\n")
    def vulnlogs(self,info):
        log = info + '  ' + strftime("%Y-%m-%d %H:%M:%S",localtime())
        with open(self.vulnlog_path,'a') as f:
            f.write(log)
            f.write("\n")
    def errorlogs(self,info):
        log = "[Error]" + '  ' + info + '  ' + strftime("%Y-%m-%d %H:%M:%S", localtime())
        with open(self.errorlog_path, 'a') as f:
            f.write(log)
            f.write("\n")
    def dumplogs(self,info):
        log = info + '  ' + strftime("%Y-%m-%d %H:%M:%S", localtime())
        with open(self.dumplog_path, 'a') as f:
            f.write(log)
            f.write("\n")
if __name__ == '__main__':
    log = LogsMethod()
