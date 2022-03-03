import json
import traceback
from django.http import JsonResponse, HttpRequest
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.base import View
from api.models import ScanTasks, AuthConfig, Finger, IpInfo, SiteInfo, PortInfo, Domain
from utils.util import verify_task_target, get_random_str, is_ip_address_format, is_url_format, parse_human_rule
from scanner.ip import ip_task_start
from scanner.domain import domain_task_start


@method_decorator(csrf_exempt, name='dispatch')
class DemoListView(View):

    def get(self, request):
        return JsonResponse({'test': 'success'})

    def post(self, request: HttpRequest):
        print(request.body)
        return JsonResponse({'post': 'success'})


@method_decorator(csrf_exempt, name='dispatch')
class Tasks(View):

    def get(self, request):
        ret = {'code': "200"}
        length = len(request.GET)
        data = []
        try:
            if length == 0:
                objs = ScanTasks.objects.all()
            else:
                id = request.GET.get('id', '').strip()
                name = request.GET.get('name', '').strip()
                target = request.GET.get('target', '').strip()
                port_type = request.GET.get('port_type', '').strip()
                start = int(str(request.GET.get('start', '0').strip()))
                end = int(str(request.GET.get('end', '0').strip()))

                if id == '':
                    objs = ScanTasks.objects.filter(name__icontains=name, target__icontains=target,
                                                    port_type__icontains=port_type)
                else:
                    objs = ScanTasks.objects.filter(id=id)
                cnt = objs.count()
                start, end = verify(start, end, cnt)
                objs = objs[start: end]

            for obj in objs:
                data.append({
                    'id': obj.id,
                    'name': obj.name,
                    'target': obj.target,
                    'port_type': obj.port_type,
                    'add_time': obj.add_time,
                    'end_time': obj.end_time,
                    'status': obj.status,
                })
            ret['data'] = data
        except:
            print(traceback.format_exc())
            ret["code"] = 400
        return JsonResponse(ret, safe=False)

    #  add/update
    def post(self, request):
        ret = {'status': 200, 'msg': 'success'}
        task = {
            'name': request.POST.get('name', None),
            'target': request.POST.get('target', None),
            'port_type': request.POST.get('port_type', '2')
        }
        if task['name'] is None or task['target'] is None:
            ret['msg'] = 'parameter cannot be empty'
            return JsonResponse(ret, safe=False)
        try:
            print('[api/va/scan > post] name:{} target:{} '
                  'port_type:{}'.format(task['name'], task['target'], task['port_type']))
            cnt, target_list = verify_task_target(task['target'])
            task['id'] = get_random_str('task')
            obj = ScanTasks(id=task['id'], name=task['name'], target=task['target'],
                            port_type=task['port_type'])
            obj.save()

            for target in target_list:
                if is_ip_address_format(target):
                    ip_task_start(task, target)
                elif is_url_format(target):
                    domain_task_start(task, target)

            return JsonResponse(ret)
        except Exception as e:
            print(traceback.format_exc())
            ret['status'] = 400
            ret['msg'] = str(e)

        return JsonResponse(ret)

    def delete(self, request):
        id = request.GET.get('id', None)
        ret = {
            'status': 200,
            'msg': 'success'
        }
        try:
            obj = ScanTasks.objects.get(id=id)
            obj.delete()

        except:
            ret['status'] = 400
            ret['msg'] = 'id doesn\'t exist'
        return JsonResponse(ret)


@method_decorator(csrf_exempt, name='dispatch')
class FingerList(View):

    def get(self, request):
        ret = {'code': 200}
        data = []
        length = len(request.GET)
        try:
            if length == 0:
                objs = Finger.objects.all()
            else:
                id = request.GET.get('id', '')
                name = request.GET.get('name', '')
                objs = Finger.objects.filter(id__icontains=id, name__icontains=name)

            for obj in objs:
                data.append({
                    'id': obj.id,
                    'name': obj.name,
                    'desc': obj.desc,
                    'finger_print': obj.finger_print,
                    'body': obj.html,
                    'title': obj.title,
                    'header': obj.headers,
                    'icon_hash': obj.favicon_hash,
                    'add_time': obj.add_time
                })
            ret['data'] = data
        except:
            print('[api/v1/finger > get] error {}'.format(traceback.format_exc()))
            ret['code'] = 400
        return JsonResponse(ret, safe=False)

    def post(self, request):
        ret = {'status': 200, 'msg': 'success'}
        name = request.POST.get('name', None)
        desc = request.POST.get('desc', '')
        finger_print = request.POST.get('fingerprint', None)
        if name is None or finger_print is None:
            ret['msg'] = 'parameter cannot be empty'
            return JsonResponse(ret, safe=False)

        rule_map = parse_human_rule(finger_print)
        print(rule_map)
        print('[api/v1/finger > post] name:{} desc:{} finger_print:{}'.format(name, desc, finger_print))
        try:
            finger_id = get_random_str('fig')
            obj = Finger(id=finger_id, name=name, desc=desc, finger_print=finger_print,
                         html=rule_map.get('html', ''), title=rule_map.get('title', ''),
                         headers=rule_map.get('headers', ''), favicon_hash=rule_map.get('favicon_hash'))
            obj.save()
        except Exception as e:
            ret['status'] = 400
            ret['msg'] = str(e)

        return JsonResponse(ret)

    def delete(self, request):
        ret = {'status': 200, 'msg': 'success'}
        id = request.GET.get('id', None)
        if id is None:
            ret['msg'] = 'id cannot be empty'
        print('[api/v1/finger > delete] name:{}'.format(id))
        try:
            obj = Finger.objects.get(id=id)
            obj.delete()
        except:
            ret['status'] = 400
            ret['msg'] = 'id doesn\'t exist'
        return JsonResponse(ret)


@method_decorator(csrf_exempt, name='dispatch')
class IP(View):

    def get(self, request):
        ret = {'code': '200'}
        data = []
        length = len(request.GET)
        try:
            if length == 0:
                objs = IpInfo.objects.all()[0:20]
            else:
                task_id = request.GET.get('task_id', '').strip()
                ip_addr = request.GET.get('ip', '').strip()
                port_list = request.GET.get('port', '').strip()
                os = request.GET.get('os', '').strip()
                start = int(str(request.GET.get('start', '0').strip()))
                end = int(str(request.GET.get('end', '0').strip()))
                if task_id == '':
                    objs = IpInfo.objects.filter(ip_addr__icontains=ip_addr, port_list__icontains=port_list,
                                                 os_name__icontains=os)
                else:
                    try:
                        task_obj = ScanTasks.objects.get(id=task_id)
                        objs = IpInfo.objects.filter(task_id=task_obj, ip_addr__icontains=ip_addr,
                                                     port_list__icontains=port_list, os_name__icontains=os)
                    except:
                        ret['data'] = []
                        return JsonResponse(ret, safe=False)
                cnt = objs.count()
                start, end = verify(start, end, cnt)
                objs = objs[start: end]

            for obj in objs:
                item = {
                    'id': obj.id,
                    'task_id': obj.task_id.id,
                    'ip_addr': obj.ip_addr,
                    'os_name': obj.os_name,
                    'port_list': [],
                    'accuracy': obj.accuracy,
                    'related_domain': [],
                }
                if obj.port_list is not None:
                    item['port_list'] = eval('[' + obj.port_list + ']')
                if obj.related_domain is not None:
                    item['related_domain'] = eval('[' + obj.related_domain + ']')
                data.append(item)

            ret['data'] = data
        except:
            print(traceback.format_exc())
            ret["code"] = 400
        return JsonResponse(ret, safe=False)


@method_decorator(csrf_exempt, name='dispatch')
class Service(View):

    def get(self, request):
        ret = {'code': "200"}
        length = len(request.GET)
        data = []
        try:
            if length == 0:
                objs = PortInfo.objects.all()[0:20]
            else:
                ip_addr = request.GET.get('ip', '').strip()
                port = request.GET.get('port', '').strip()
                name = request.GET.get('name', '').strip()
                product = request.GET.get('product', '').strip()
                protocol = request.GET.get('protocol', '').strip()
                start = int(str(request.GET.get('start', '0').strip()))
                end = int(str(request.GET.get('end', '0').strip()))
                objs = PortInfo.objects.filter(port_num__icontains=port, service_name__icontains=name,
                                               product__icontains=product, protocol__icontains=protocol,
                                               ip_addr__icontains=ip_addr)
                cnt = objs.count()
                start, end = verify(start, end, cnt)
                objs = objs[start: end]
            for obj in objs:
                data.append({
                    'id': obj.id,
                    'ip_id': obj.ip_id.id,
                    'ip_addr': obj.ip_id.ip_addr,
                    'port_num': obj.port_num,
                    'service_name': obj.service_name,
                    'version': obj.version,
                    'product': obj.product,
                    'protocol': obj.protocol
                })
            ret['data'] = data
        except:
            print(traceback.format_exc())
            ret["code"] = 400
        return JsonResponse(ret, safe=False)


@method_decorator(csrf_exempt, name='dispatch')
class Site(View):

    def get(self, request):
        ret = {'code': "200"}
        length = len(request.GET)
        data = []
        try:
            if length == 0:
                objs = SiteInfo.objects.all()[0:20]
            else:
                task_id = request.GET.get('task_id', '').strip()
                ip = request.GET.get('ip', '').strip()
                site = request.GET.get('site', '').strip()
                title = request.GET.get('title', '').strip()
                start = int(str(request.GET.get('start', '0').strip()))
                end = int(str(request.GET.get('end', '0').strip()))
                if task_id == '':
                    objs = SiteInfo.objects.filter(ip__icontains=ip, site__icontains=site,
                                                   title__icontains=title)
                else:
                    try:
                        task_obj = ScanTasks.objects.get(id=task_id)
                        objs = SiteInfo.objects.filter(task_id=task_obj, ip__icontains=ip, site__icontains=site,
                                                       title__icontains=title)
                    except:
                        ret['data'] = []
                        return JsonResponse(ret, safe=False)
                cnt = objs.count()
                start, end = verify(start, end, cnt)
                objs = objs[start: end]
            for obj in objs:
                data.append({
                    'id': obj.id,
                    'task_id': obj.task_id.id,
                    'site': obj.site,
                    'host_name': obj.host_name,
                    'ip': obj.ip,
                    'title': obj.title,
                    'state': obj.status,
                    'headers': obj.headers,
                    'http_server': obj.http_server,
                    'body_length': obj.body_length,
                    'favicon': obj.favicon,
                    'fld': obj.fld,
                })
            ret['data'] = data
        except:
            print(traceback.format_exc())
            ret["code"] = 400
        return JsonResponse(ret, safe=False)


@method_decorator(csrf_exempt, name='dispatch')
class SubDomain(View):

    def get(self, request):
        ret = {'code': "200"}
        length = len(request.GET)
        data = []
        try:
            if length == 0:
                objs = Domain.objects.all()[0:20]
            else:
                task_id = request.GET.get('task_id', '').strip()
                domain = request.GET.get('domain', '').strip()
                _type = request.GET.get('type', '').strip()
                record = request.GET.get('record', '').strip()
                ip = request.GET.get('ip', '').strip()
                start = int(str(request.GET.get('start', '0').strip()))
                end = int(str(request.GET.get('end', '0').strip()))
                if task_id == '':
                    objs = Domain.objects.filter(domain__icontains=domain, type__icontains=_type,
                                                 record__icontains=record, ips__icontains=ip)
                    cnt = objs.count()
                    start, end = verify(start, end, cnt)
                    objs = objs[start: end]
                else:
                    task_obj = ScanTasks.objects.get(id=task_id)
                    objs = Domain.objects.filter(task_id=task_obj, domain__icontains=domain, type__icontains=_type,
                                                 record__icontains=record, ips__icontains=ip)

                cnt = objs.count()
                start, end = verify(start, end, cnt)
                objs = objs[start: end]
            for obj in objs:
                data.append({
                    'id': obj.id,
                    'task_id': obj.task_id.id,
                    'domain': obj.domain,
                    'type': obj.type,
                    'record': obj.record,
                    'ip': obj.ips,
                })
            ret['data'] = data
        except:
            print(traceback.format_exc())
            ret["code"] = 400
        return JsonResponse(ret, safe=False)


@method_decorator(csrf_exempt, name='dispatch')
class Configuration(View):
    def get(self, request):
        try:
            objs = AuthConfig.objects.all()
            data = []
            for obj in objs:
                data.append({
                    'config_id': obj.id,
                    'service_name': obj.service_name,
                    'userid': obj.userid,
                    'password': obj.password,
                    'add_time': obj.add_time
                })
            return JsonResponse(data, safe=False)
        except Exception as e:
            print('[api/v1/configuration > get] error {}'.format(traceback.format_exc()))
            return JsonResponse(None)

    def post(self, request):
        config_id = get_random_str('conf')
        name = request.POST.get('name', None)
        userid = request.POST.get('userid', None)
        password = request.POST.get('password', None)
        ret = {'status': 200, 'msg': 'success'}
        print('[api/v1/configuration > post] name:{} userid:{} password:{}'.format(name, userid, password))
        try:
            obj = AuthConfig(id=config_id, service_name=name, userid=userid, password=password)
            obj.save()
        except Exception as e:
            print('[api/v1/configuration > post] error: {}'.format(traceback.format_exc()))
            ret['status'] = 400
            ret['msg'] = str(e)

        return JsonResponse(ret)

    def delete(self, request):
        id = request.GET.get('id', None)
        ret = {
            'status': 200,
            'msg': 'success'
        }
        print('[api/v1/config > delete] name:{}'.format(id))
        try:
            obj = AuthConfig.objects.get(id=id)
            obj.delete()
        except:
            ret['status'] = 400
            ret['msg'] = 'id doesn\'t exist'
        return JsonResponse(ret)


def verify(start, end, cnt):
    if end == -1:
        end = cnt
    if start == 0 and end == 0 or start < 0 or end < 0 or start > end:
        return 0, 20
    if cnt == 0:
        return 0, 0
    if start > cnt:
        start = cnt - 20
        end = cnt
        if start < 0:
            start = 0
        return start, end
    if start == end:
        return start, start + 1
    return start, end


