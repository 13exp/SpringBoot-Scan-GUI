# coding:utf-8

import yaml
from util import JsonMethod

class YamlMethod:
    def YamlRead(self,path):
        with open(path, mode="r", encoding="utf-8") as f:
            yamlConf = yaml.load(f.read(), Loader=yaml.FullLoader)
        return yamlConf
    def YamlWrite(self,data,path):
        with open(path, mode='w', encoding='utf-8') as f:
            yaml.dump(data,f)
        return True
    def YamlToJsonFile(self,data,path):
        jsonMethod = JsonMethod.JsonMethod()
        data = jsonMethod.JsonWrite(data,path)
        return data
if __name__ == '__main__':
    YamlLoad = YamlMethod()
    data = YamlLoad.YamlRead("../vuls/CVE_2021_21234.yaml")
    print(data)
    # data = YamlLoad.YamlToJsonFile(data,"../vuls/CVE_2021_21234.json")
    # print(data)