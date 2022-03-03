import ipaddress
import requests
import random
import string
import time
import nmap
import json
import re
import subprocess
import shlex
import dns.resolver
from urllib import parse
from utils.config import Config
from urllib3.util.url import get_host
from api.models import Finger
from tld import get_tld


def datetime_string_format(datetime):
    res = re.match("(\d+-\d+-\d+)\S(\d+:\d+:\d+)", datetime)
    if res:
        return res.group(1) + " " + res.group(2)
    else:
        return ""


def verify_task_target(targets):
    targets.strip()
    targets = targets.splitlines()
    cnt = 0
    target_list = []
    for target in targets:
        if not target:
            continue
        cnt += 1
        target_list.append(target)
    return cnt, target_list


def get_random_str(table_type, length=15):
    return table_type + ''.join(random.sample(string.ascii_letters + string.digits, length))


def random_choices(k=6):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=k))


def is_ip_address_format(value):
    IP_ADDRESS_REGEX = r"\b(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\b"
    if value and re.match(IP_ADDRESS_REGEX, value):
        return True
    else:
        return False


def is_url_format(value):
    URL_ADDRESS_REGEX = r"[0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*(:(0-9)*)*(\/?)([a-zA-Z0-9\-\.\?\,\'\/\\\+&%\$#_]*)?"
    if value and re.match(URL_ADDRESS_REGEX, value):
        return True
    else:
        return False


def format_convert(arg: str):
    # 1: ip; 2: http/https
    if not arg.startswith("http"):
        try:
            ipaddress.ip_network(arg, strict=False)
            return 1, arg
        except:
            return 2, "http://" + arg.split("/")[0]
    else:
        p = parse.urlparse(arg)
        return 2, "{0}://{1}".format(p[0], p[1])


def smartDate(data_tmp: float):
    sec = int(time.time() - data_tmp)
    hover = int(sec / 3600)
    if hover == 0:
        minute = int(sec / 60)
        if minute == 0:
            op = '{}秒前'.format(sec)
        else:
            op = '{}分钟前'.format(minute)
    else:
        op = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(data_tmp))
    return op


def lstrsub(s: str, sub: str):
    if s[:len(sub)] == sub:
        return s[len(sub):]
    return s


def random_str(length=10, chars=string.ascii_letters + string.digits):
    return ''.join(random.sample(chars, length))


#  ----check_http----
def check_http(url):
    timeout = (5, 3)
    if isinstance(url, str):
        url = url.strip()
    if not url:
        return url, None
    try:
        conn = http_req(url, method='head')
        if conn.status_code == 403:
            conn2 = http_req(url)
            check = b'</title><style type="text/css">body{margin:5% auto 0 auto;padding:0 18px}'
            if check in conn2.content:
                return None

        item = {
            'status': conn.status_code,
            'content-type': conn.headers.get('Content-Type', '')
        }
        return url, item
    except Exception as e:
        print(str(e))
        pass

    return url, None


def http_req(url, method='get', **kwargs):
    UA = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36"
    proxies = {
        'https': "http://127.0.0.1:8080",
        'http': "http://127.0.0.1:8080"
    }
    kwargs.setdefault('verify', False)
    kwargs.setdefault('timeout', (10.1, 30.1))
    kwargs.setdefault('allow_redirects', True)
    headers = kwargs.get('headers', {})
    headers.setdefault('User-Agent', UA)
    # 不允许缓存
    headers.setdefault('Cache-Control', 'max-age=0')

    kwargs['headers'] = headers
    # kwargs["proxies"] = proxies

    conn = getattr(requests, method)(url, **kwargs)

    return conn


#  -----web analyze-----
def web_analyze(site):
    if isinstance(site, str):
        target = site.strip()
        if not target:
            return site, None

    cmd_parameters = ['phantomjs',
                      '--ignore-ssl-errors true',
                      '--ssl-protocol any',
                      '--ssl-ciphers ALL',
                      Config.DRIVER_JS,
                      site
                      ]
    try:
        output = check_output(cmd_parameters, timeout=20)
        output = output.decode('utf-8')
        return site, json.loads(output)["applications"]
    except:
        return site, None


def check_output(cmd, **kwargs):
    cmd = " ".join(cmd)
    timeout = 4 * 60 * 60

    if kwargs.get('timeout'):
        timeout = kwargs.pop('timeout')

    if 'stdout' in kwargs:
        raise ValueError('stdout argument not allowed, it will be overridden.')

    output = subprocess.run(shlex.split(cmd), stdout=subprocess.PIPE, timeout=timeout,
                            check=False, **kwargs).stdout
    return output


#  -----port scan-----
def get_host_list(target):
    nm = nmap.PortScanner()
    # nm.scan(target, arguments='-e tun0 -sn --randomize-hosts')
    nm.scan(target, arguments='-sn --randomize-hosts')
    return nm.all_hosts()


def nmap_scan(host, ports):
    """
    -sS(TCP SYN扫描)
    -n(不用域名解析)
    -O(OS)
    -sV(service)
    -Pn(将所有主机都默认为在线，跳过主机发现)
    """
    error = {'is_error': False, 'error_msg': ''}
    alive_port = '22,80,443,843,3389,8007-8011,8443,9090,8080-8091,8093,8099,5000-5004,2222,3306,1433,21,25'
    ap = ''
    max_hostgroup = 20
    host_timeout = 60 * 14
    min_rate = 64
    if ports == '1-65535':
        ap = '--max-rtt-timeout 800ms --script-timeout 6s --max-retries 2'
        host_timeout += 60 * 2
        max_hostgroup = 1
        min_rate = 2000

    argument = '-sS -n -O -sV -PE -PS{0} -r --host-timeout {1} ' \
               '--max-hostgroup {2} --min_rate {3} --min-parallelism 32' \
               '{4}'.format(alive_port, host_timeout, max_hostgroup, min_rate, ap)
    # argument = '-e tun0 -sS -n -O -sV -PE -PS{0} -r --host-timeout {1} ' \
    #            '--max-hostgroup {2} --min_rate {3} --min-parallelism 32' \
    #            '{4}'.format(alive_port, host_timeout, max_hostgroup, min_rate, ap)
    # argument = '-sV'
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=host, arguments=argument)
    except Exception as e:
        error['is_error'] = True
        error['error_msg'] = str(e)
        return []

    ip_info_list = []
    for host in nm.all_hosts():
        port_info_list = []
        for proto in nm[host].all_protocols():
            for port in nm[host][proto]:
                port_info = nm[host][proto][port]
                item = {
                    "port_id": port,
                    "service_name": port_info["name"],
                    "version": port_info["version"],
                    "product": port_info["product"],
                    "protocol": proto
                }

                port_info_list.append(item)

        osmatch_list = nm[host].get("osmatch", [])
        os_info = os_match_by_accuracy(osmatch_list)

        ip_info = {
            "ip": host,
            "port_info": port_info_list,
            "os_info": os_info
        }
        ip_info_list.append(ip_info)

    return ip_info_list


def os_match_by_accuracy(os_match_list):
    for os_match in os_match_list:
        accuracy = os_match.get('accuracy', '0')
        if int(accuracy) > 80:
            return os_match

        return {}


#  -----fetch site----
def fetch_site(site):
    _, hostname, _ = get_host(site)
    conn = http_req(site)
    item = {
        "site": site,
        "hostname": hostname,
        "ip": "",
        "title": get_title(conn.content),
        "status": conn.status_code,
        "headers": get_headers(conn),
        "http_server": conn.headers.get("Server", ""),
        "body_length": len(conn.content),
        "finger": [],
        "favicon": fetch_favicon(site)
    }
    item = fetch_fingerprint(item, content=conn.content)
    do_par = domain_parsed(hostname)
    if do_par:
        item["fld"] = do_par["fld"]
        ips = get_ip(hostname)
        if ips:
            item["ip"] = ips[0]
    else:
        item["ip"] = hostname
    return site, item


def get_title(body):
    result = ''
    title_patten = re.compile(rb'<title>([^<]{1,200})</title>', re.I)
    title = title_patten.findall(body)
    if len(title) > 0:
        try:
            result = title[0].decode("utf-8")
        except Exception as e:
            result = title[0].decode("gbk", errors="replace")
    return result.strip()


def get_headers(conn):
    raw = conn.raw
    version = "1.1"
    if raw.version == 10:
        version = "1.0"

    first_line = "HTTP/{} {} {}\n".format(version, raw.status, raw.reason)

    headers = str(raw._fp.headers)

    headers = headers.strip()
    if not conn.headers.get("Content-Length"):
        headers = "{}\nContent-Length: {}".format(headers, len(conn.content))

    return first_line + headers


def fetch_fingerprint(item, content):
    finger_list = load_fingerprint()
    finger_name_list = []
    for finger in finger_list:
        rule = finger['rule']
        rule_name = finger['name']
        match_flag = False
        for html in rule["html"]:
            if html.encode("utf-8") in content:
                finger_name_list.append(rule_name)
                match_flag = True
                break

            try:
                if html.encode("gbk") in content:
                    finger_name_list.append(rule_name)
                    match_flag = True
                    break
            except:
                pass
        if match_flag:
            continue

        for header in rule["headers"]:
            if header in item['headers']:
                finger_name_list.append(rule_name)
                match_flag = True
                break
        if match_flag:
            continue

        for rule_title in rule["title"]:
            if rule_title in item['title']:
                finger_name_list.append(rule_name)
                match_flag = True
                break
        if match_flag:
            continue

        if isinstance(rule.get("favicon_hash"), list):
            for rule_hash in rule["favicon_hash"]:
                if rule_hash == item["favicon"].get("hash", 0):
                    finger_name_list.append(rule_name)
                    break

    finger = []
    for name in finger_name_list:
        finger_item = {
            "icon": "default.png",
            "name": name,
            "confidence": "80",
            "version": "",
            "website": "https://www.riskivy.com",
            "categories": []
        }
        finger.append(finger_item)

    if finger:
        item["finger"] = finger

    return item


def fetch_favicon(site):

    return ''


# ----finger print----
def parse_human_rule(rule):
    rule_map = {
        "html": [],
        "title": [],
        "headers": [],
        "favicon_hash": []
    }
    key_map = {
        "body": "html",
        "title": "title",
        "header": "headers",
        "icon_hash": "favicon_hash"
    }
    split_result = rule.split("||")
    empty_flag = True

    for item in split_result:
        key_value = item.split("=")
        key = key_value[0]
        key = key.strip()
        if len(key_value) == 2:
            if key not in key_map:
                continue

            value = key_value[1]
            value = value.strip()
            if len(value) <= 6:
                continue

            if value[0] != '"' or value[-1] != '"':
                continue

            empty_flag = False
            value.encode("gbk")
            value = value[1:-1]
            if key == "icon_hash":
                value = int(value)

            rule_map[key_map[key]].append(value)

    if empty_flag:
        return None

    return rule_map


def transform_rule_map(rule):
    key_map = {
        "html": "body",
        "title": "title",
        "headers": "header",
        "favicon_hash": "icon_hash"
    }
    human_rule_list = []
    for key in rule:
        if key not in key_map:
            continue

        for rule_item in rule[key]:
            human_rule_list.append('{}="{}"'.format(key_map[key], rule_item))

    return " || ".join(human_rule_list)


def load_fingerprint():
    # web_app_rules: dict
    web_app_rules = json.loads("\n".join(load_file(Config.WEB_APP_RULES)))
    items = []
    objs = Finger.objects.all()
    for obj in objs:
        rule = dict()
        try:
            rule['name'] = obj.name
            rule['rule'] = {
                'html': eval(obj.html) if obj.html != '' else '',
                'title': eval(obj.title) if obj.title != '' else '',
                'icon': eval(obj.favicon_hash) if obj.favicon_hash != '' else '',
                'headers': eval(obj.headers) if obj.headers != '' else ''
            }
        except:
            continue
        items.append(rule)
    for rule in web_app_rules:
        new_rule = dict()
        new_rule['name'] = rule
        new_rule['rule'] = web_app_rules[rule]
        items.append(new_rule)
    return items
# end


# ----domain----
def domain_parsed(domain, fail_silently=True):
    domain = domain.strip()
    try:
        res = get_tld(domain, fix_protocol=True,  as_object=True)
        item = {
            'subdomain': res.subdomain,
            'domain': res.domain,
            'fld': res.fld  # 一级域名
        }
        return item
    except:
        return None


def get_ip(domain):
    domain = domain.strip()
    ips = []
    try:
        answers = dns.resolver.query(domain, 'A')
        for rdata in answers:
            if rdata.address == '0.0.0.1':
                continue
            ips.append(rdata.address)
        return ips
    except:
        return None


def resolver_domain(domain):
    curr_domain = domain
    if isinstance(domain, dict):
        curr_domain = domain.get("domain")

    if not curr_domain:
        return curr_domain, None

    return curr_domain, get_ip(curr_domain)

# ----end----


# ----file----
def load_file(path):
    with open(path, "r+", encoding="utf-8") as f:
        return f.readlines()
# ----end----


# ----exec system----
def exec_system(cmd, **kwargs):
    cmd = " ".join(cmd)
    timeout = 4 * 60 * 60

    if kwargs.get('timeout'):
        timeout = kwargs['timeout']

    completed = subprocess.run(shlex.split(cmd), timeout=timeout, check=False, close_fds=True, **kwargs)

    return completed
# ----end----


if __name__ == '__main__':
    from concurrent.futures import ThreadPoolExecutor

    PORT_TOP1000 = '1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,68-70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-546,548,554-555,563,587,593,616-617,623,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1194,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1337,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666-1667,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2181,2190-2191,2196,2200,2222,2233,2251,2260,2288,2301,2323,2366,2375,2379,2381-2383,2393-2394,2399,2401,2443,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2888,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3520,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3772-3773,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3888-3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4369,4443-4446,4449,4550,4560,4567,4662,4848,4899-4900,4998,5000-5004,5006,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5111,5120,5151,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5355,5357,5387,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5601,5631-5633,5666,5672,5678-5679,5718,5722,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5987-5989,5998-6007,6009,6025,6059,6080,6093,6100-6101,6106,6112,6123,6129,6156,6161,6182,6346,6379,6389,6443,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7008,7019,7025,7070,7100,7103,7106,7180,7182,7200-7201,7337,7402,7435,7443,7474,7496,7512,7625,7627,7676,7680,7687,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8016,8020-8022,8025,8030-8033,8040-8042,8045,8050,8060,8069-8070,8080-8091,8093,8099-8100,8123-8124,8161,8180-8181,8188,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8480-8481,8500,8600,8649,8651-8652,8654,8701,8744,8800,8873,8888-8889,8898-8899,8983,8989,8994,9000-9003,9009-9011,9040,9043,9050,9071,9080-9083,9090-9092,9094-9095,9099-9103,9110-9111,9200,9207,9220,9222,9290,9293,9300,9389,9391-9392,9415,9418,9443,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9987-9988,9994-10004,10009-10010,10012,10020,10024-10025,10030,10033,10050-10051,10080-10082,10101,10180,10215,10243,10250-10252,10255-10256,10566,10616-10617,10621,10626,10628-10629,10666,10778,11000-11001,11080,11110-11111,11211,11443,11967,12000,12174,12234,12265,12306,12345,12669,12750,12801-12804,12999,13456,13562,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15672,15742,16000-16001,16010,16012,16016,16018,16020,16030,16080,16113,16666,16992-16993,17877,17988,18040,18080,18089,18101,18988,19101,19283,19315,19350,19780,19801,19842,19888,19890,20000,20005-20006,20031,20221-20222,20828,20880,21000,21443,21571,22939,23502,24444,24800,25672,25734-25735,26214,27000,27017-27018,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899,34451,34528,34571-34573,35500,36359,37257,37310,38243,38292,38914,39297,40193,40654,40911,41084,41414,41511,42424,42510,43761,44176,44442-44443,44501,44838,45100,46675,48080,49152-49161,49163,49165-49167,49175-49176,49400,49664-49667,49670,49692,49697,49999-50003,50006,50010,50020,50070,50075,50090-50091,50095,50100,50105,50300,50389,50470,50475,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54321,54328,54345,54485,54488,55055-55056,55555,55600,56341,56737-56738,57294,57797,58080,58316,60000,60010,60020,60030,60443,61532,61616,61900,62078,63331,64623,64680,65000,65129,65389,65512,6677,8484,8360,7080,41516,8880,8881,3505,1980,8003,8004,8006,8012,7890,86,8280,8028,9060,38501,38888,28017,8053,889,9085'
    host_list = get_host_list('10.38.26.117/24')
    print(host_list)
    thread_pool = ThreadPoolExecutor(max_workers=10)
    thread_list = [thread_pool.submit(nmap_scan, host, PORT_TOP1000) for host in host_list]
