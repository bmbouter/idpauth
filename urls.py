from django.conf.urls.defaults import *

urlpatterns = patterns('idpauth.views',
    url(r'^login/$', 'determine_login', name='login_url'),
    url(r'^openid_login/$', 'openid_login'),
    url(r'^openid_login_complete/$', 'openid_login_complete'),
    url(r'^ldap_login/$', 'ldap_login'),
    url(r'^local_login/$', 'local_login'),
    url(r'^shibboleth_login/$', 'shibboleth_login'),
    url(r'^logout/$', 'logout_view', name='logout_url'),
)
