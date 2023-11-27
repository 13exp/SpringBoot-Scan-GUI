# coding:utf-8

import random

class RandomUA:
    def UserAgent(self):
        user_agent_app_names = [
            'Mozilla',
            'Opera',
            'Googlebot',
            'Bingbot',
            'Facebook',
        ]

        user_agent_versions = [
            '5.0 (Windows NT 10.0; Win64; x64)',
            '5.0 (Macintosh; Intel Mac OS X 10_15_7)',
            '5.0 (Linux; Android 10)'
            '9.80 (Windows NT 5.1; U; zh-sg)',
            '5.0 (Windows NT 6.2; WOW64)',
            '5.0 (Windows NT 6.1; WOW64)',
            '5.0 (Windows NT 6.1; WOW64; rv:23.0)',
            '5.0 (Windows NT 6.1; Win64; x64)',
            '5.0 (Windows; U; Windows NT 6.1; en-US)',
            '5.0 (X11; NetBSD)'
            
        ]

        user_agent_browsers = [
            'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.1234.5678 Safari/537.36',
            'AppleWebKit/537.36 (KHTML, like Gecko) Firefox/99.0',
            'AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27',
            'AppleWebKit/537.36 (KHTML like Gecko) Chrome/44.0.2403.155 Safari/537.36',
            'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36',
            'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.93 Safari/537.36',
            'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.17 Safari/537.36',
            'AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27',
            'Presto/2.9.181 Version/12.00',
            'Gecko/20130406 Firefox/23.0'
        ]
        app_name = random.choice(user_agent_app_names)
        version = random.choice(user_agent_versions)
        browser = random.choice(user_agent_browsers)

        random_user_agent = f'{app_name}/{version} {browser}'
        return random_user_agent
    def UserAgentList(self,num):
        ua_list = []
        for i in range(num):
            ua_list.append(self.UserAgent())
        return ua_list
    
if __name__ == '__main__':
    ua = RandomUA()
    uas = ua.UserAgentList(100)
    print(uas)
