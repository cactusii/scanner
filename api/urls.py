# -*- coding: utf-8 -*-

import api.views as views
from django.conf.urls import url

urlpatterns = [
    url(
        regex=r'^test$',
        view=views.DemoListView.as_view(),
    ),
    url(
        regex=r'^tasks$',
        view=views.Tasks.as_view()
    ),
    url(
        regex=r'^ipinfo$',
        view=views.IP.as_view()
    ),
    url(
        regex=r'^site$',
        view=views.Site.as_view()
    ),
    url(
        regex=r'^service$',
        view=views.Service.as_view()
    ),
    url(
        regex=r'^config$',
        view=views.Configuration.as_view()
    ),
    url(
        regex=r'^finger$',
        view=views.FingerList.as_view()
    ),
    url(
        regex=r'^sub_domain$',
        view=views.SubDomain.as_view()
    ),

]
