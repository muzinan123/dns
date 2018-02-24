from django.conf.urls import patterns, url
from rest_framework.urlpatterns import format_suffix_patterns
from cdns import api, views

urlpatterns = patterns('',
    url(r'^api/record/$', api.RecordList.as_view()),
    url(r'^api/record/(?P<name>[a-zA-Z0-9\-]+)/$', api.RecordDetail.as_view()),
    url(r'^api/record/(?P<name>[a-zA-Z0-9\-]+)/(?P<value>[0-9\.]+)/$', api.RecordDetail.as_view()),
    
    url(r'^$', 'cdns.views.index'),
    url(r'^modify_zone/$', 'cdns.views.modify_zone'),
    url(r'^create_record/$', 'cdns.views.create_record'),
    url(r'^modify_record/$', 'cdns.views.modify_record'),
    url(r'^delete_record/$', 'cdns.views.delete_record'),
    url(r'^confirm_delete/$', 'cdns.views.confirm_delete'),
    url(r'^show_record/$', 'cdns.views.show_record'),
    url(r'^activate_record/$', 'cdns.views.activate_record'),
    url(r'^create_tag/$', 'cdns.views.create_tag'),
    url(r'^modify_tag/$', 'cdns.views.modify_tag'),
    url(r'^delete_tag/$', 'cdns.views.delete_tag'),
    url(r'^activate_tag/$', 'cdns.views.activate_tag'),
    url(r'^sync_data/$', 'cdns.views.sync_data'),
    url(r'^diff_dns_server/$', 'cdns.views.diff_dns_server'),
    url(r'^check_diff_pb/$', 'cdns.views.check_diff_pb'),
    url(r'^tree/$', 'cdns.views.tree'),
    url(r'^tree_json/$', 'cdns.views.all_record_tree_json'),
    
    url(r'^data/(?P<dtype>[a-z]+)/$', 'cdns.views.data'),
    
    url(r'^rdList/$', 'cdns.views.record_list'),
    url(r'^addRd/$', 'cdns.views.add_record'),
    url(r'^rdComp/$', 'cdns.views.record_comparison'),
    url(r'^audit/$', 'cdns.views.operation_audit'),
    
)

urlpatterns = format_suffix_patterns(urlpatterns)
