#! python3
import requests
import re
import csv
import urllib3
import sys
import urllib
import netlas
import json
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


#change API key and download size
apikey = "SetApiKey"
size = 20


user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36"
headers = {'User-Agent':user_agent}
timeout = 1
query='((http.headers.location:/owa/ AND path:"/") AND NOT asn.organization:("MICROSOFT-CORP-MSN-AS-BLOCK"))'
fields = ["ip","port","protocol","geo.country","domain"]
source_type = "include"
datatype = "response"
indices = ""
line_count = 0

def owa_info(host, port, protocol):
    
    target = "{}://{}:{}".format(protocol,host,port)
    is_owa = 0
    endpoint = '/owa'
    r = requests.get(target + endpoint,  headers=headers, timeout=timeout, verify=False)

    if r.history and "/auth/logon.aspx" in r.url:
        is_owa = 1
    version_regex = b'owa/auth/(.*?)/themes/resources'
    try:
        version = re.findall(version_regex,r.content)[0].decode('utf-8')

    except Exception as e:
        version = False
        version_regex = b'/owa/(.*?)/themes/resources/'
        try:
            version = re.findall(version_regex,r.content)[0].decode('utf-8')
        except Exception as e:
            version = False
    return is_owa, version, r.url

def download_version(host, port, protocol):
    target = "{}://{}:{}".format(protocol,host,port)
    path_version = "/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application"
    r = requests.get(target + path_version,  headers=headers, timeout=timeout, verify=False)
    version = False
    if r.status_code ==200:
        version_regex = b'assemblyIdentity.*version="(.*?)"'
        try:
            version = re.findall(version_regex,r.content)[0].decode('utf-8')
        except Exception as e:
            version = False

    return r.status_code, version
def brute_version(host, port , protocol, version):
    target = "{}://{}:{}".format(protocol,host,port)
    if  "15.0.1497" in version:
        versionCheck = ["15.0.1497.18",
            "15.0.1497.15",
            "15.0.1497.12",
            "15.0.1497.1",
            "15.0.1497.8",
            "15.0.1497.7",
            "15.0.1497.6",
            "15.0.1497.4",
            "15.0.1497.3",
            "15.0.1497.2"]
    
    if  "15.0.1473" in version:
        versionCheck = ["15.0.1473.6",
            "15.0.1473.5",
            "15.0.1473.4",
            "15.0.1473.3"]
    
    if  "15.0.1395" in version:
        versionCheck = ["15.0.1395.12",
            "15.0.1395.10",
            "15.0.1395.8",
            "15.0.1395.7",
            "15.0.1395.4"]
    
    if  "15.0.1367" in version:
        versionCheck = ["15.0.1367.9",
            "15.0.1367.6",
            "15.0.1367.3"]
    
    if  "15.0.1365" in version:
        versionCheck = ["15.0.1365.7",
            "15.0.1365.001"]
    
    if  "15.0.1347" in version:
        versionCheck = ["15.0.1347.3",
            "15.0.1347.2"]
    
    if  "15.0.1320" in version:
        versionCheck = ["15.0.1320.7",
            "15.0.1320.6",
            "15.0.1320.4"]
    
    if  "15.0.1293" in version:
        versionCheck = ["15.0.1293.6",
            "15.0.1293.4",
            "15.0.1293.2"]
    
    if  "15.0.1263" in version:
        versionCheck = ["15.0.1263.5"]
    
    if  "15.0.1263" in version:
        versionCheck = ["15.0.1236.6",
            "15.0.1236.3"]
    
    if  "15.0.1210" in version:
        versionCheck = ["15.0.1210.6",
            "15.0.1210.3"]
    
    if  "15.0.1178" in version:
        versionCheck = ["15.0.1178.9",
            "15.0.1178.6",
            "15.0.1178.4"]
    
    if  "15.0.1156" in version:
        versionCheck = ["15.0.1156.10",
            "15.0.1156.6"]
    
    if  "15.0.1130" in version:
        versionCheck = ["15.0.1130.7"]
    
    if  "15.0.1104" in version:
        versionCheck = ["15.0.1104.5"]
    
    if  "15.0.1076" in version:
        versionCheck = ["15.0.1076.9"]
    
    if  "15.0.1044" in version:
        versionCheck = ["15.0.1044.25"]
    
    if  "15.0.995" in version:
        versionCheck = ["15.0.995.29"]
    
    if  "15.0.913" in version:
        versionCheck = ["15.0.913.22"]
    
    if  "15.0.847" in version:
        versionCheck = ["15.0.847.64",
            "15.0.847.62",
            "15.0.847.57",
            "15.0.847.55",
            "15.0.847.53",
            "15.0.847.50",
            "15.0.847.47"]
    ecp_version = "not found"
    for v in versionCheck:
        path_version = "/ecp/{}/exporttool/microsoft.exchange.ediscovery.exporttool.application".format(v)
        r = requests.get(target + path_version,  headers=headers, timeout=timeout, verify=False)
        
        if r.status_code ==200:
            return 200, v
    return "not 200", ecp_version
def netals_download(apikey, query, fields=[],source_type="include",datatype="response",size=10,indices = ""):
    netlas_connection = netlas.Netlas(api_key=apikey)
    # query_res = netlas_connection.query(query="port:7001")
    # print(netlas.helpers.dump_object(data=query_res))

    itr = netlas_connection.download(query=query, fields=fields, source_type=source_type, datatype=datatype, size=size, indices=indices)
    return itr



with open('result.csv', mode='w') as res:
    res_writer = csv.writer(res, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
    targets_itr = netals_download(apikey,query,fields, size=size)
    for target in targets_itr:
        owa = ""
        owa_theme_version = ""
        owa_full_url = ""
        ecp_status = ""
        ecp_version = ""
        target_json = json.loads(target.decode('utf8'))
        print(target_json)
        if "domain" in target_json["data"]:
            t = target_json["data"]["domain"]
        else:
            t = target_json["data"]["ip"]
        ip = target_json["data"]["ip"]
        p = target_json["data"]["port"]
        prot = target_json["data"]["protocol"]
        country = ""
        if "geo" in target_json["data"]:
            if "country" in target_json["data"]["geo"]:
                country = target_json["data"]["geo"]["country"]
        line_count += 1

        try:
            owa, owa_theme_version, owa_full_url = owa_info(t,p,prot)
            if "15.0" in owa_theme_version:
                ecp_status, ecp_version = brute_version(t, p, prot, owa_theme_version)
            else:
                ecp_status, ecp_version = download_version(t,p,prot)
        except Exception as e:
            print(e)
        if line_count%100 == 0:
            print(line_count)
        res_writer.writerow([ip,t,p,prot,country,owa,owa_theme_version,owa_full_url,ecp_status,ecp_version])