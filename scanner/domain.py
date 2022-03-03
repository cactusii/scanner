import traceback
import django.utils.timezone as timezone
from utils.config import Config
from threading import Thread
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.util import load_file, domain_parsed, resolver_domain, get_random_str
from scanner.massdns import mass_dns
from scanner.ip import ip_task_start
from api.models import Domain, ScanTasks, IpInfo


class DomainBrute:
    """
    域名爆破
    """
    def __init__(self, base_domain,  word_file=Config.DOMAIN_DICT, concurrency=Config.CONSUMER_CONCURRENCY):
        self.base_domain = base_domain
        self.base_domain_scope = "." + base_domain.strip(".")
        self.dicts = load_file(word_file)
        self.concurrency = concurrency
        self.sub_task_thread_pool = ThreadPoolExecutor(max_workers=self.concurrency)
        self.brute_out = []
        self.resolver_map = {}  # {domain: ips[]}
        self.domain_info_list = []
        self.domain_cnames = []
        self.brute_domain_map = {}  # 保存了通过massdns获取的结果

    def run(self):
        self.brute_out = mass_dns(self.base_domain, self.dicts)
        self.resolver()

        for domain in self.resolver_map:
            ips = self.resolver_map[domain]
            if ips:
                if domain in self.domain_cnames:
                    item = {
                        'domain': domain,
                        'type': 'CNAME',
                        'record': [self.brute_domain_map[domain]],
                        'ips': ips
                    }
                else:
                    item = {
                        'domain': domain,
                        'type': 'A',
                        'record': ips,
                        'ips': ips
                    }
                self.domain_info_list.append(item)

        return self.domain_info_list

    def resolver(self):
        domains = []
        domain_cname_record = []
        for x in self.brute_out:
            current_domain = x['domain'].lower()
            if not domain_parsed(current_domain):
                continue

            if current_domain not in domains:
                domains.append(current_domain)

            self.brute_domain_map[current_domain] = x['record']

            if x['type'] == 'CNAME':
                self.domain_cnames.append(current_domain)
                current_record_domain = x['record']

                if not domain_parsed(current_record_domain):
                    continue

                if current_record_domain not in domain_cname_record:
                    domain_cname_record.append(current_record_domain)

        for domain in domain_cname_record:
            if not domain.endswith(self.base_domain_scope):
                continue
            if domain not in domains:
                domains.append(domain)

        thread_list = [self.sub_task_thread_pool.submit(resolver_domain, domain) for domain in domains]
        for future in as_completed(thread_list):
            domain, result = future.result()
            if domain in self.resolver_map:
                continue
            if result is not None:
                self.resolver_map[domain] = result


class DomainTask(Thread):
    def __init__(self, task: dict, target, concurrency=Config.CONSUMER_CONCURRENCY):
        Thread.__init__(self)
        self.task = task
        self.task['target'] = target
        self.concurrency = concurrency
        self.sub_task_thread_pool = ThreadPoolExecutor(max_workers=self.concurrency)
        self.domain_info_list = []
        self.ip_domain_dict = dict()

    def run(self):
        self.update_task_state(2)
        print('domain_brute start, task: {}'.format(self.task))
        self.domain_brute()
        print('domain_brute finished, domain_info_list: {}'.format(self.domain_info_list))
        # self.start_ip_fetch()
        print('save_domain_info_list start')
        self.save_domain_info_list()
        print('save_domain_info_list finished')
        print('handle_ip start')
        self.handle_ip()
        print('handle_ip finished, domain_info_list: {}'.format(self.domain_info_list))
        self.update_task_state(3)
        print('domain_brute finished')

    def domain_brute(self):
        b = DomainBrute(self.task.get('target', ''), word_file=Config.DOMAIN_DICT)
        self.domain_info_list = b.run()

    def save_domain_info_list(self):
        for domain_info_obj in self.domain_info_list:
            try:
                do_par = domain_parsed(domain_info_obj['domain'])
                if do_par:
                    domain_info_obj["fld"] = do_par["fld"]
                _domain = ' '.join(domain_info_obj.get('record', []))
                _ips = '; '.join(domain_info_obj.get('ips', []))
                obj = Domain(id=get_random_str('dom'), task_id=ScanTasks.objects.get(id=self.task['id']),
                             domain=domain_info_obj.get('domain', ''), type=domain_info_obj.get('type', ''),
                             record=_domain, ips=_ips)
                obj.save()
            except:
                print(traceback.format_exc())
                continue

    def update_task_state(self, status, error=''):
        try:
            obj = ScanTasks.objects.get(id=self.task['id'])
            obj.status = status
            if status == 3:
                obj.end_time = timezone.now()
            elif status == 4:
                obj.end_time = timezone.now()
                obj.error = error
            obj.save()
        except:
            print(traceback.format_exc())

    def handle_ip(self):
        for domain_info in self.domain_info_list:
            try:
                ips = domain_info.get('ips', [])
                for ip in ips:
                    domain_list = self.ip_domain_dict.get(ip, [])
                    domain_list.append(domain_info.get('domain', ''))
                    self.ip_domain_dict[ip] = domain_list
            except:
                print(traceback.format_exc())
        thread_list = [self.sub_task_thread_pool.submit(ip_task_start, self.task, ip, True) for ip in self.ip_domain_dict]
        for future in as_completed(thread_list):
            try:
                future.result()
            except:
                print(traceback.format_exc())
                continue

        for ip in self.ip_domain_dict:
            try:
                domain_list = self.ip_domain_dict[ip]
                obj = IpInfo.objects.get(ip_addr=ip)
                obj.related_domain = ' '.join(domain_list)
                obj.save()
            except:
                print(traceback.format_exc())
                continue

    # def start_ip_fetch(self):
    #     self.gen_ipv4_map()
    #
    #     '''***端口扫描开始***'''
    #     if self.options.get("port_scan"):
    #         self.update_task_field("status", "port_scan")
    #         t1 = time.time()
    #         self.port_scan()
    #         elapse = time.time() - t1
    #         self.update_services("port_scan", elapse)
    #
    # def gen_ipv4_map(self):
    #     ipv4_map = {}
    #     for domain_info in self.domain_info_list:
    #         for ip in domain_info.ip_list:
    #             old_domain = ipv4_map.get(ip, set())
    #             old_domain.add(domain_info.domain)
    #             ipv4_map[ip] = old_domain
    #             self.ip_set.add(ip)
    #
    #     self.ipv4_map = ipv4_map
    #
    #
    # def build_domain_info(self, domains):
    #     """
    #     构建domain_info_list 带去重功能
    #     """
    #     fake_list = []
    #     domains_set = set()
    #     for item in domains:
    #         domain = item
    #         if isinstance(item, dict):
    #             domain = item["domain"]
    #
    #         domain = domain.lower().strip()
    #         if domain in domains_set:
    #             continue
    #         domains_set.add(domain)
    #
    #         if utils.check_domain_black(domain):
    #             continue
    #
    #         fake = {
    #             "domain": domain,
    #             "type": "CNAME",
    #             "record": [],
    #             "ips": []
    #         }
    #         fake_info = modules.DomainInfo(**fake)
    #         if fake_info not in self.domain_info_list:
    #             fake_list.append(fake_info)
    #
    #     domain_info_list = services.build_domain_info(fake_list)
    #
    #     return domain_info_list
    #
    # def alt_dns(self):
    #     if self.task_tag == "monitor" and len(self.domain_info_list) >= 800:
    #         logger.info("skip alt_dns on monitor {}".format(self.base_domain))
    #         return
    #
    #     alt_dns_out = alt_dns(self.domain_info_list, self.base_domain)
    #     alt_domain_info_list = self.build_domain_info(alt_dns_out)
    #     if self.task_tag == "task":
    #         alt_domain_info_list = self.clear_domain_info_by_record(alt_domain_info_list)
    #         self.save_domain_info_list(alt_domain_info_list,
    #                             source=CollectSource.ALTDNS)
    #
    #     self.domain_info_list.extend(alt_domain_info_list)
    #
    # # 只是保存没有开放端口的
    # def save_ip_info(self):
    #     fake_ip_info_list = []
    #     for ip in self.ipv4_map:
    #         data = {
    #             "ip": ip,
    #             "domain": list(self.ipv4_map[ip]),
    #             "port_info": [],
    #             "os_info": {},
    #             "cdn_name": utils.get_cdn_name_by_ip(ip)
    #         }
    #         info_obj = modules.IPInfo(**data)
    #         if info_obj not in self.ip_info_list:
    #             fake_ip_info_list.append(info_obj)
    #
    #     for ip_info_obj in fake_ip_info_list:
    #         ip_info = ip_info_obj.dump_json(flag=False)
    #         ip_info["task_id"] = self.task_id
    #         utils.conn_db('ip').insert_one(ip_info)
    #
    # def site_spider(self):
    #     entry_urls_list = []
    #     for site in self.site_list:
    #         entry_urls = [site]
    #         entry_urls.extend(self.search_engines_result.get(site, []))
    #         entry_urls_list.append(entry_urls)
    #
    #     site_spider_result = services.site_spider_thread(entry_urls_list)
    #     for site in site_spider_result:
    #         target_urls = site_spider_result[site]
    #         new_target_urls = []
    #         for url in target_urls:
    #             if url in self.page_url_list:
    #                 continue
    #             new_target_urls.append(url)
    #
    #             self.page_url_list.append(url)
    #
    #         page_map = services.page_fetch(new_target_urls)
    #         for url in page_map:
    #             item = {
    #                 "site": site,
    #                 "task_id": self.task_id,
    #                 "source": CollectSource.SITESPIDER
    #             }
    #             item.update(page_map[url])
    #
    #             domain_parsed = utils.domain_parsed(site)
    #
    #             if domain_parsed:
    #                 item["fld"] = domain_parsed["fld"]
    #
    #             utils.conn_db('url').insert_one(item)


def domain_task_start(task, target):
    try:
        domain_task = DomainTask(task=task, target=target)
        domain_task.start()
    except Exception as e:
        print(traceback.format_exc())





