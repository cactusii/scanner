import random

from django.db import models


class ScanTasks(models.Model):
    id = models.CharField(max_length=128, primary_key=True)
    name = models.CharField(max_length=128)
    target = models.TextField(default='')
    port_type = models.IntegerField(default=2)  # 1: all, 2: top100, 3:top1000
    add_time = models.DateTimeField(auto_now=True)
    end_time = models.DateTimeField(null=True)
    status = models.IntegerField(default=1)  # 1:waiting, 2:scanning, 3:finished
    error = models.TextField(default='')


class IpInfo(models.Model):
    id = models.CharField(max_length=20, primary_key=True)
    task_id = models.ForeignKey(ScanTasks, on_delete=models.CASCADE)
    ip_addr = models.CharField(max_length=20, default='')
    port_list = models.TextField(default='')
    os_name = models.TextField(default='')
    accuracy = models.IntegerField(default=0)
    related_domain = models.TextField(default='')


class PortInfo(models.Model):
    id = models.CharField(max_length=20, primary_key=True)
    ip_id = models.ForeignKey(IpInfo, on_delete=models.CASCADE)
    ip_addr = models.TextField(default='')
    port_num = models.IntegerField(null=True)
    service_name = models.TextField(default='')
    version = models.TextField(default='')
    product = models.TextField(default='')
    protocol = models.TextField(default='')


class SiteInfo(models.Model):
    id = models.CharField(max_length=20, primary_key=True)
    task_id = models.ForeignKey(ScanTasks, on_delete=models.CASCADE)
    site = models.TextField(default='')
    host_name = models.TextField(default='')
    ip = models.CharField(max_length=20)
    title = models.TextField(default='')
    status = models.TextField(default='')
    headers = models.TextField(default='')
    http_server = models.TextField(default='')
    body_length = models.IntegerField(null=True)
    favicon = models.TextField(default='')
    fld = models.TextField(default='')


class SiteFinger(models.Model):
    id = models.CharField(max_length=20, primary_key=True)
    siteinfo_id = models.ForeignKey(SiteInfo, on_delete=models.CASCADE)
    icon = models.TextField(default='')
    name = models.TextField(default='')
    confidence = models.IntegerField(null=True)
    version = models.TextField(default='')
    website = models.TextField(default='')
    finger = models.TextField(default='')


class AuthConfig(models.Model):
    id = models.CharField(max_length=20, primary_key=True, default='0')
    service_name = models.CharField(max_length=20, null=True)
    userid = models.CharField(max_length=128, null=True)
    password = models.CharField(max_length=128, null=True)
    add_time = models.DateTimeField(auto_now=True)


class Finger(models.Model):
    id = models.CharField(max_length=20, primary_key=True)
    name = models.CharField(max_length=128, null=True)
    desc = models.TextField(default='')
    finger_print = models.TextField(default='')
    html = models.TextField(default='')
    title = models.TextField(default='')
    headers = models.TextField(default='')
    favicon_hash = models.TextField(default='')
    add_time = models.DateTimeField(auto_now=True)


class Domain(models.Model):
    id = models.CharField(max_length=20, primary_key=True)
    task_id = models.ForeignKey(ScanTasks, on_delete=models.CASCADE)
    domain = models.TextField(default='')
    type = models.TextField(default='')
    record = models.TextField(default='')
    ips = models.TextField(default='')
