import traceback
from threading import Thread
from utils.config import Config
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.util import get_host_list, nmap_scan, check_http, web_analyze, fetch_site, get_random_str
from api.models import IpInfo, PortInfo, ScanTasks, SiteInfo, SiteFinger
import django.utils.timezone as timezone


class IPTask(Thread):
    def __init__(self, task: dict, target, concurrency=Config.CONSUMER_CONCURRENCY):
        Thread.__init__(self)
        self.task = task
        self.task['target'] = target
        self.concurrency = concurrency
        self.sub_task_thread_pool = ThreadPoolExecutor(max_workers=self.concurrency)
        self.ip_info_list = []
        self.site_list = []
        self.site_info_list = []
        self.web_analyze_map = {}
        self.openstack_plugin = Config.OPENSTACK_PLUGIN

    def run(self) -> None:
        try:
            print('port_scan start, task: {}'.format(self.task))
            self.update_task_state(2)
            self.port_scan()
            print('port_scan finished, {}'.format(self.ip_info_list))
            print('find_site start...')
            self.find_site()
            print('find_site finished, {}'.format(self.site_list))
            print('site_identify start...')
            self.site_identify()
            print('site_identify finished, {}'.format(self.web_analyze_map))
            print('fetch_sites start...')
            self.fetch_sites()
            print('fetch_sites finished, {}'.format(self.site_info_list))
            if self.openstack_plugin:
                self.plugin('openstack')
            self.update_task_state(3)
            print('scanner finished.')
            self.save()
        except Exception as e:
            self.update_task_state(status=4, error=str(e))

    def port_scan(self):
        try:
            host_list = get_host_list(self.task['target'])
            thread_list = [self.sub_task_thread_pool.submit(nmap_scan, host, Config.PORTS_TYPE[self.task['port_type']])
                           for host in host_list]

            for future in as_completed(thread_list):
                result = future.result()
                self.ip_info_list.extend(result)
        except Exception as e:
            print(traceback.format_exc())
            self.update_task_state(status=4, error=str(e))

    def find_site(self):
        try:
            url_temp_list = []
            for ip_info in self.ip_info_list:
                for port_info in ip_info["port_info"]:
                    curr_ip = ip_info["ip"]
                    port_id = port_info["port_id"]
                    if port_id == 80:
                        url_temp = "http://{}".format(curr_ip)
                        url_temp_list.append(url_temp)
                        continue

                    if port_id == 443:
                        url_temp = "https://{}".format(curr_ip)
                        url_temp_list.append(url_temp)
                        continue

                    url_temp1 = "http://{}:{}".format(curr_ip, port_id)
                    url_temp2 = "https://{}:{}".format(curr_ip, port_id)
                    url_temp_list.append(url_temp1)
                    url_temp_list.append(url_temp2)

            check_map = {}
            thread_list = [self.sub_task_thread_pool.submit(check_http, url) for url in url_temp_list]

            for future in as_completed(thread_list):
                url, result = future.result()
                if result is not None:
                    check_map[url] = result

            # 去除https和http相同的
            alive_site = []
            for x in check_map:
                if x.startswith("https://"):
                    alive_site.append(x)

                elif x.startswith("http://"):
                    x_temp = "https://" + x[7:]
                    if x_temp not in check_map:
                        alive_site.append(x)

            self.site_list.extend(alive_site)
        except Exception as e:
            print(traceback.format_exc())
            self.update_task_state(status=4, error=str(e))

    def site_identify(self):
        try:
            thread_list = [self.sub_task_thread_pool.submit(web_analyze, site) for site in self.site_list]
            for future in as_completed(thread_list):
                site, result = future.result()
                if result is not None:
                    self.web_analyze_map[site] = result
        except Exception as e:
            print(traceback.format_exc())
            self.update_task_state(status=4, error=str(e))

    def fetch_sites(self):
        try:
            thread_list = [self.sub_task_thread_pool.submit(fetch_site, site) for site in self.site_list]
            for future in as_completed(thread_list):
                site, result = future.result()
                if result is not None:
                    self.site_info_list.append(result)

            for i in range(len(self.site_info_list)):
                self.site_info_list[i]['task_id'] = self.task['id']
        except Exception as e:
            print(traceback.format_exc())
            self.update_task_state(status=4, error=str(e))

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

    def plugin(self, plug):
        from plugin.openstack import handler
        try:
            ip_ports_list = []
            for ip_info in self.ip_info_list:
                ip = ip_info['ip']
                ports = []
                for port_info in ip_info['port_info']:
                    port = port_info['port_id']
                    ports.append(port)
                ip_ports_list.append({
                    'ip': ip,
                    'ports': ports
                })
            thread_list = [self.sub_task_thread_pool.submit(handler, ip_ports['ip'], ip_ports['ports'])
                           for ip_ports in ip_ports_list]
            for future in as_completed(thread_list):
                result = future.result()
                if result is not None:
                    self.ip_info_list.extend(result)
        except:
            return

    def save(self):
        # --ip--
        try:
            task_obj = ScanTasks.objects.get(id=self.task['id'])
        except Exception as e:
            self.update_task_state(status=4, error=str(e))
            return
        for ip_info in self.ip_info_list:
            ip_info_id = get_random_str('ip')
            try:
                # IpInfo
                os_info = ip_info['os_info']
                if os_info is None:
                    os_info = {}
                port_num_list = ','.join([str(port_info.get('port_id', '')) for port_info in ip_info['port_info']])
                ip_obj = IpInfo(id=ip_info_id, task_id=task_obj, ip_addr=ip_info['ip'],
                                port_list=port_num_list, os_name=os_info.get('name', ''),
                                accuracy=os_info.get('accuracy', 0))
                ip_obj.save()

                # PortInfo
                port_info_list = ip_info['port_info']
                for port_info in port_info_list:
                    port_obj = PortInfo(id=get_random_str('port'), ip_id=ip_obj,
                                        ip_addr=ip_info['ip'],
                                        port_num=port_info.get('port_id', ''),
                                        service_name=port_info.get('service_name', ''),
                                        version=port_info.get('version', ''),
                                        product=port_info.get('product', ''),
                                        protocol=port_info.get('protocol', ''))
                    port_obj.save()
            except Exception as e:
                print(traceback.format_exc())
                self.update_task_state(status=4, error=str(e))
        # SiteInfo

        for site_info in self.site_info_list:
            try:
                site_id = get_random_str('site')
                obj = SiteInfo(id=site_id, task_id=task_obj, site=site_info.get('site', ''),
                               host_name=site_info.get('hostname', ''),
                               ip=site_info.get('ip', ''),
                               title=site_info.get('title', ''),
                               status=site_info.get('status', ''),
                               headers=site_info.get('headers', ''),
                               http_server=site_info.get('http_server', ''),
                               body_length=site_info.get('body_length', ''),
                               favicon=site_info.get('favicon', ''),
                               fld=site_info.get('fld', ''))
                obj.save()

            except Exception as e:
                print(traceback.format_exc())
                self.update_task_state(status=4, error=str(e))

        self.update_task_state(status=3)


def ip_task_start(task, target, is_join=False):
    try:
        ip_task = IPTask(task=task, target=target)
        ip_task.start()
        if is_join:
            ip_task.join()
    except Exception as e:
        print(traceback.format_exc())
