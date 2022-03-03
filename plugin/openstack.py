import traceback

from keystoneauth1.identity import v3
from keystoneauth1 import session
from keystoneclient.v3 import client as ksclient
# from glanceclient.v2 import client as glclient
# from novaclient import client as noclient
# from neutronclient.v2_0 import client as neclient


# try:
#     for auth_info in AUTH_LIST:
#         if auth_info.get('name', None) == 'Openstack':
#             username = auth_info.get('userid', None)
#             password = auth_info.get('password', None)
#             break
# except:
#     username = 'admin'
#     password = 'admin'
username = 'admin'
password = '9937b32c76714b39'
project_name = 'admin'
user_domain_name = 'Default'
project_domain_name = 'Default'
identity_api_version = '3'


def handler(ip, ports):
    ret = []
    for port in ports:
        auth_url = "http://{0}:{1}/v{2}".format(ip, port, identity_api_version)
        try:
            # create keystone session, get keystone client
            sess = get_keystone_session(auth_url)
            kss = get_keystone_client(sess)
            service_list = kss.services.list()
        except Exception as e:
            continue
        try:
            # get service to url dic
            ip_info_dic = {}
            for service in service_list:
                service_info = {}
                service_dic = service.to_dict()
                for endpoint in kss.endpoints.list():
                    endpoint_dic = endpoint.to_dict()
                    if service_dic['id'] == endpoint_dic['service_id']:
                        endpoint = endpoint_dic['url'].split('/')[2]
                        ip, port = endpoint.split(':')
                        service_info['service_name'] = service_dic['name']
                        service_info['port_id'] = port
                        service_info['product'] = service_dic['description']
                        service_info['protocol'] = 'http'
                        service_info['version'] = ''
                        if ip_info_dic.get(ip, None) is None:
                            ip_info_dic[ip] = []
                        ip_info_dic[ip].append(service_info)
                        break

            for ip, service_info in ip_info_dic.items():
                ret.append({
                    'ip': ip,
                    'port_info': service_info,
                    'os_info': {}
                })
            return ret
        except Exception as e:
            print(traceback.format_exc())
            continue
    return None


def get_keystone_session(auth_url):
    auth = v3.Password(
        auth_url=auth_url, username=username, password=password,
        project_name=project_name, user_domain_name=user_domain_name,
        project_domain_name=project_domain_name
    )
    sess = session.Session(auth=auth)
    return sess


def get_keystone_client(sess):
    kss = ksclient.Client(session=sess)
    return kss


if __name__ == '__main__':
    ret = handler('10.210.11.244', ['5000'])
    print(ret)
