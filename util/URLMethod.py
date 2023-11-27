# coding:utf-8

class URLMethod:
    def StandURL(self,url):
        if ('://' not in url):
            url = str("http://") + str(url)
        if str(url[-1]) != "/":
            url = url + "/"
        else:
            url = url
        return url
    def FileURL(self,file):
        urls = []
        with open(file, 'r') as url_list:
            url_lists = url_list.readlines()
            for url in url_lists:
                url = url.strip()
                if ('://' not in url):
                    url = str("http://") + str(url)
                if str(url[-1]) != "/":
                    urls.append(url + "/")
                else:
                    urls.append(url)
        return urls
if __name__ == '__main__':
    url = URLMethod()
    standurl = url.StandURL("www.baidu.com")
    print(standurl)
    fileurl = url.FileURL('1.txt')
    print(fileurl)
