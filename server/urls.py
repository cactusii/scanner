from django.urls import include
from django.conf.urls import url
from frontend import views as frontend


urlpatterns = [
    url(r'^api/v1/', include("api.urls")),
    url(r'^ip/', frontend.index, name='home'),
    url(r'^site/', frontend.index, name='home'),
    url(r'^service/', frontend.index, name='home'),
    url(r'^sub_domain/', frontend.index, name='home'),
    url(r'^$', frontend.index, name='home'),
    url(r'^dashboard/$', frontend.dashboard, name='dashboard'),
    url(r'^faq/$', frontend.faq, name='faq'),
    url(r'^configuration$', frontend.configuration, name='configuration'),
    url(r'^finger$', frontend.finger, name='finger'),
]
