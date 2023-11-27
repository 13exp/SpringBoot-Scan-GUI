# coding:utf-8

import os,ctypes,sys

def SystemType():
    if sys.platform.startswith('linux'):
        return 'Linux'
    elif sys.platform.startswith('win'):
        return 'Windows'
    elif sys.platform.startswith('darwin'):
        return 'macOS'
    else:
        return False
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False
def is_root():
    if os.geteuid() == 0:
        return True
    else:
        return False

    
if __name__ == "__main__":
    systype = SystemType()
    if systype == 'Windows':
        if is_admin():
            print('yes')
        else:
            ctypes.windll.shell32.ShellExecuteW(None,"runas", sys.executable, __file__, None, 1)
    elif systype == 'Linux':
        if is_root():
            print('root')
        else:
            print(False)
    elif systype == 'macOS':
        if is_root():
            print('root')
        else:
            print(False)
    else:
        print('Faild Start Process...Please try agine!')
