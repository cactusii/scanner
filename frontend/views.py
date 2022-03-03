from __future__ import unicode_literals
import traceback
from django.shortcuts import render
from api.models import ScanTasks, Finger, IpInfo, PortInfo, SiteInfo, AuthConfig, Domain


def index(request):
    active = {
        'ip': 'nav-link',
        'service': 'nav-link',
        'site': 'nav-link',
        'sub_domain': 'nav-link',
        'tab_ip': 'tab-pane fade',
        'tab_service': 'tab-pane fade',
        'tab_site': 'tab-pane fade',
        'tab_sub_domain': 'tab-pane fade'
    }
    if request.path_info == '/':
        ip_info_list = IpInfo.objects.all()
        port_info_list = PortInfo.objects.all()
        site_info_list = SiteInfo.objects.all()
        sub_domain_list = Domain.objects.all()
        active['ip'] += ' active'
        active['tab_ip'] += ' show active'
    else:
        try:
            head = request.path_info.split('/')[1]
            if head == 'ip':
                ip = request.GET.get('ip-ip', '').strip()
                port = request.GET.get('ip-port', '').strip()
                os = request.GET.get('ip-os', '').strip()
                ip_info_list = IpInfo.objects.filter(ip_addr__icontains=ip,
                                                     port_list__icontains=port, os_name__icontains=os)
                port_info_list = PortInfo.objects.all()
                site_info_list = SiteInfo.objects.all()
                sub_domain_list = Domain.objects.all()
            elif head == 'service':
                ip = request.GET.get('service-ip', '').strip()
                port = request.GET.get('service-port', '').strip()
                service = request.GET.get('service-service', '').strip()
                product = request.GET.get('service-product', '').strip()
                protocol = request.GET.get('service-protocol', '').strip()
                ip_info_list = IpInfo.objects.all()
                port_info_list = PortInfo.objects.filter(ip_addr__icontains=ip, port_num__icontains=port,
                                                         service_name__icontains=service, product__icontains=product,
                                                         protocol__icontains=protocol)
                site_info_list = SiteInfo.objects.all()
                sub_domain_list = Domain.objects.all()
            elif head == 'site':
                site = request.GET.get('site-site', '').strip()
                host_name = request.GET.get('site-hostname', '').strip()
                ip = request.GET.get('site-ip', '').strip()
                ip_info_list = IpInfo.objects.all()
                port_info_list = PortInfo.objects.all()
                site_info_list = SiteInfo.objects.filter(site__icontains=site, host_name__icontains=host_name,
                                                         ip__icontains=ip)
                sub_domain_list = Domain.objects.all()
            else:
                domain = request.GET.get('sub_domain-domain', '').strip()
                record = request.GET.get('sub_domain-record', '').strip()
                _type = request.GET.get('sub_domain-type', '').strip()
                ip = request.GET.get('sub_domain-ip', '').strip()
                ip_info_list = IpInfo.objects.all()
                port_info_list = PortInfo.objects.all()
                site_info_list = SiteInfo.objects.all()
                sub_domain_list = Domain.objects.filter(domain__icontains=domain, record__icontains=record,
                                                        type__icontains=_type, ips__icontains=ip)
            active[head] += ' active'
            active['tab_' + head] += ' show active'
        except:
            ip_info_list = []
            port_info_list = []
            site_info_list = []
            sub_domain_list = []
            active['ip'] += ' active'
            active['tab_ip'] += ' show active'
            print(traceback.format_exc())
    return render(request, 'frontend/home.html',
                  {
                      'active': active,
                      'ip_info_list': ip_info_list,
                      'port_info_list': port_info_list,
                      'site_info_list': site_info_list,
                      'sub_domain_list': sub_domain_list
                  })


def dashboard(request):
    # task
    tasks = ScanTasks.objects.all()
    return render(request, 'frontend/dashboard.html',
                  {
                      'tasks': tasks,
                  })


def faq(request):
    return render(request, "frontend/faq.html")


def configuration(request):
    config_list = AuthConfig.objects.all()
    return render(request, 'frontend/configuration.html',
                  {
                      'config_list': config_list
                  })


def finger(request):
    finger_list = Finger.objects.all()
    return render(request, 'frontend/finger.html',
                  {
                      'finger_list': finger_list
                  })
