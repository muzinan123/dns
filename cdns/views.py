#!/usr/bin/env python
#coding: utf-8

from django.shortcuts import render_to_response, get_object_or_404
from django.http import HttpResponse, Http404, HttpResponseRedirect
from rest_framework.response import Response
from django.template import RequestContext
from django.core.paginator import QuerySetPaginator, InvalidPage
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate
from django.db import connections as db_connect
from django.db.models import Q
import re, commands, datetime, os, time
import json, httplib
from crms.config import API_HOST, API_PORT
from cdns.models import *
from cdns import dns_server
from cdns.config import DNS_SERVER, DNS_PORT
from cldap.config import SHADOW_WARNING, SGROUP_LIST
from cldap.api import get_shadow_max, get_shadow_warning, get_random_passwd
import crypt, random, string, operator
'''日志'''
from crms.logger import logger
'''缓存'''
from django.views.decorators.cache import cache_page
'''分页'''
from django.core.paginator import Paginator, InvalidPage, EmptyPage

import cserver, capp


@login_required
#@cache_page(60 * 5)
def index(request, success=None, error=None):
    #print request.method
    tag_obj = Tag.objects.all()
    zone_obj = Zone.objects.all()
    nameserver_obj = NameServer.objects.all()

    searchHostname = ''
    searchIP = ''
    searchDns = ''
    searchZone = ''

    QList = []

    if request.GET.has_key('searchHostname'):
        value = request.GET['searchHostname']
        if value:
            QList.append( 'Q(name__icontains="%s")' %value )
            searchHostname = value

    if request.GET.has_key('searchIP'):
        value = request.GET['searchIP']
        if value:
            QList.append( 'Q(value__icontains="%s")' %value )
            searchIP = value

    if request.GET.has_key('searchDns'):
        value = request.GET['searchDns']
        if value:
            QList.append( 'Q(nameserver__icontains="%s")' %value )
            searchDns = value

    if request.GET.has_key('searchZone'):
        value = request.GET['searchZone']
        if value:
            QList.append( 'Q(zone__icontains="%s")' %value )
            searchZone = value

    if QList:
        QListStr = '&'.join( QList )
        CMD = "record_obj = Record.objects.filter( %s ).exclude(status=2).order_by('-id')" % QListStr
        exec( CMD )
    else:
        record_obj = Record.objects.all().exclude(status=2).order_by('-id')

    paginator = Paginator(record_obj, 12)
    try:
        page = int(request.GET.get('page', '1'))
    except ValueError:
        page = 1
    try:
        contacts = paginator.page(page)
    except (EmptyPage, InvalidPage):
        contacts = paginator.page(paginator.num_pages)
    #print contacts[0]
    return render_to_response('cdns/index.html', {
        "username": request.user.username,
        "user_groups": request.user.ldap_user.group_names,
        "record_obj": contacts,
        "tag_obj": tag_obj,
        "zone_obj": zone_obj,
        "nameserver_obj": nameserver_obj,
        "searchHostname": searchHostname,
        "searchIP": searchIP,
        "searchZone": searchZone,
        "searchDns": searchDns,
        "success": success,
        "error": error,
    })



@login_required
#@cache_page(60 * 5)
def record_list(request, success=None, error=None):
    #print request.method
    zone_obj = Zone.objects.values('name').distinct()
    tag_obj = Tag.objects.all()
    nameserver_obj = NameServer.objects.all()

    searchHostname = ''
    searchIP = ''
    searchDns = ''
    searchZone = ''

    QList = []

    if request.GET.has_key('searchHostname'):
        value = request.GET['searchHostname']
        if value:
            QList.append( 'Q(name__icontains="%s")' %value )
            searchHostname = value

    if request.GET.has_key('searchIP'):
        value = request.GET['searchIP']
        if value:
            QList.append( 'Q(value__icontains="%s")' %value )
            searchIP = value

    if request.GET.has_key('searchDns'):
        value = request.GET['searchDns']
        if value:
            QList.append( 'Q(nameserver__icontains="%s")' %value )
            searchDns = value

    if request.GET.has_key('searchZone'):
        value = request.GET['searchZone']
        if value:
            QList.append( 'Q(zone__icontains="%s")' %value )
            searchZone = value

    if QList:
        QListStr = '&'.join( QList )
        CMD = "record_obj = Record.objects.filter( %s ).exclude(status=2).order_by('-id')" % QListStr
        exec( CMD )
    else:
        record_obj = Record.objects.all().exclude(status=2).order_by('-id')

    paginator = Paginator(record_obj, 12)
    try:
        page = int(request.GET.get('page', '1'))
    except ValueError:
        page = 1
    try:
        contacts = paginator.page(page)
    except (EmptyPage, InvalidPage):
        contacts = paginator.page(paginator.num_pages)
    #print contacts[0]
    return render_to_response('cdns/record_list.html', {
        "username": request.user.username,
        "user_groups": request.user.ldap_user.group_names,
        "record_obj": contacts,
        "tag_obj": tag_obj,
        "zone_obj": zone_obj,
        "nameserver_obj": nameserver_obj,
        "searchHostname": searchHostname,
        "searchIP": searchIP,
        "searchZone": searchZone,
        "searchDns": searchDns,
        "success": success,
        "error": error,
    })


def data(request, dtype):
    if dtype == 'search':
        cursor = db_connect['default'].cursor()
        if request.GET['p'] == 'host':
            sql = "SELECT DISTINCT name FROM cdns_record WHERE status <> 2"
        elif request.GET['p'] == 'ip':
            sql = "SELECT DISTINCT value FROM cdns_record WHERE status <> 2"
        elif request.GET['p'] == 'zone':
            sql = "SELECT DISTINCT zone FROM cdns_record WHERE status <> 2"
        elif request.GET['p'] == 'dns':
            sql = "SELECT DISTINCT nameserver FROM cdns_record WHERE status <> 2"

        cursor.execute(sql)
        result = cursor.fetchall()
        value_list = []
        for item in result:
            value_list.append(item[0])
        result = {"data": value_list}
        #result_dict = {"data": ["public-p-o", "pub-puppet01-p-o"]}
    elif dtype == 'zone':
        zone_obj = Zone.objects.all()
        result = {}
        if zone_obj:
            result['name'] = zone_obj[0].name
            result['server'] = zone_obj[0].server
            result['ip'] = zone_obj[0].ip
            result['ttl'] = zone_obj[0].ttl
            result['serial'] = zone_obj[0].serial
            result['refresh'] = zone_obj[0].refresh
            result['retry'] = zone_obj[0].retry
            result['expire'] = zone_obj[0].expire
            result['minimum'] = zone_obj[0].minimum
        else:
            connection = httplib.HTTPSConnection(API_HOST, API_PORT)
            connection.connect()
            connection.request('GET', '/dns/api/record/', '', {})
            result = json.loads(connection.getresponse().read())
            #Get DNS Master Server
            for r in result:
                if r.has_key('server'):
                    zone = Zone(name=r['name'],ttl=r['ttl'],serial=r['serial'],refresh=r['refresh'],\
                                expire=r['expire'],retry=r['retry'],minimum=r['minimum'],server=r['server'])
                    result['name'] = r['name']
                    result['server'] = r['server']
                    result['ttl'] = r['ttl']
                    result['serial'] = r['serial']
                    result['refresh'] = r['refresh']
                    result['retry'] = r['retry']
                    result['expire'] = r['expire']
                    result['minimum'] = r['minimum']
                elif r['name'] == zone.server:
                    zone.ip = r['value']
                    result['ip'] = r['value']
                    break
            try:
                zone.save()
                logger.debug("Write zone info of %s into database" % zone.name)
            except:
                logger.error("Write zone info of %s into database FAILED" % zone.name)
    elif dtype == 'historys':

        origin_date = datetime.datetime.now()

        if origin_date.month < 7:
            origin_date = origin_date.replace(year=origin_date.year-1, month=origin_date.month +6)
        else:
            origin_date = origin_date.replace(month=origin_date.month-6)

        date_str = origin_date.strftime("%Y-%m-%d %H:%M:%S")

        history_obj = History.objects.filter(time__gte = date_str).order_by('-time')
        result = []
        for item in history_obj:
            history_dict = {}
            history_dict['time'] = item.time
            history_dict['user'] = item.user
            history_dict['action'] = item.action
            history_dict['old'] = item.old
            history_dict['new'] = item.new
            result.append(history_dict)

    return HttpResponse(json.dumps(result))


@login_required
def modify_zone(request):
    ## deprecated
    return index(request, 'modify_zone deprecated')



def add_record_to_dns_server( dnsServer, rdzone, rdname, rdttl, rdtype, rdvalue, userName ):
    INFO = ""
    try:
        valuesList = dns_server.do_query( rdname, rdzone, dnsServer )
    except Exception,e:
        return (1, '[ DNS服务器 %s，%s.%s -> %s ] DNS server 查询失败！未操作。'%(dnsServer, rdname, rdzone, rdvalue)   )

    if rdvalue in valuesList :
        INFO = '[ DNS服务器 %s，%s.%s -> %s ] DNS server 上已存在相同解析记录，未操作。'%(dnsServer, rdname, rdzone, rdvalue)
    else:
        try:
            dns_server.add_record( dnsServer, rdzone, rdname, rdttl, rdtype, rdvalue )
        except Exception,e:
            return (2, '向 DNS server %s 添加解析记录失败：</br>%s'%(dnsServer,e) )
        logger.debug("Add record to dns server %s by %s: %s.%s -> %s" % (dnsServer, userName, rdname, rdzone, rdvalue)  )
        INFO = '[ DNS服务器 %s，%s.%s -> %s ] 向 DNS server 添加解析记录成功。'%(dnsServer, rdname, rdzone, rdvalue)

    return (0, INFO)


def add_record_to_crms_db( rdname, rdtype, rdttl, rdvalue, rdmark, rdzone, userName, ACTION, rdtagname_list, dnsServer ):
    INFO = ''
    currTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    record_obj = Record.objects.filter( name=rdname, status=0, zone=rdzone, value=rdvalue, nameserver=dnsServer )
    #print record_obj
    if record_obj:
        INFO = '[ DNS服务器 %s，%s.%s -> %s ] CRMS数据库已存在相同记录，未操作。'% (dnsServer, rdname, rdzone, rdvalue )
    else:
        record = Record(name=rdname,rdtype=rdtype,ttl=rdttl,value=rdvalue,mark=rdmark,status=0,zone=rdzone, nameserver=dnsServer, create_by=userName, create_time=currTime )
        try:
            record.save()
            logger.debug("Add record to database by %s:  %s  %s.%s -> %s" % ( userName, dnsServer, rdname, rdzone, rdvalue)  )
            ## FIXME - 此处逻辑有漏洞：如果数据库保存成功而 logger 失败抛异常...
            INFO = '[ DNS服务器 %s，%s.%s -> %s ] 存入 CRMS 数据库成功。'% ( dnsServer, rdname, rdzone, rdvalue )
        except:
            logger.error("Failed to add record to database by %s:  %s  %s.%s -> %s" % ( userName, dnsServer, rdname, rdzone, rdvalue)  )
            INFO = '[ DNS服务器 %s，%s.%s -> %s ] 存入 CRMS 数据库失败，请手动同步。'% (dnsServer, rdname, rdzone, rdvalue )

        for tagname in rdtagname_list:
            tag = Tag.objects.get(name=tagname)
            record.tags.add(tag)
        #history_new = '%s IN %s %s %s</br>Tag: %s</br>Mark: %s</br>DNS server: %s' % (rdname, rdtype, rdvalue, rdzone, ' '.join([each.encode('utf8') for each in rdtagname_list]), rdmark, dnsServer)
        #history = History(user=userName, time=currTime, action=ACTION, old='N/A', new=history_new)
        #history.save()
        #record.history.add(history)
        #record.save()
    return (0, INFO)


def is_valid( rdNameValueList, rdtagname_list ):
    error_info = []
    host_regex = re.compile("^[a-zA-Z0-9\-\.]+$")
    ip_regex = re.compile("^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)){3}$")

    if not rdNameValueList:
        error_info.append('请至少输入一条有效记录！')

    for eachNV in rdNameValueList:
        if not host_regex.findall(eachNV['name']):
            error_info.append( '%s %s ： 记录名不正确！只允许使用 字母 或 数字 或 “-” 或 “.” 。' %(eachNV['name'], eachNV['value']) )

        if not ip_regex.findall( eachNV['value'] ):
            error_info.append('%s %s ： IP 不是合法的 IPv4 地址！' %(eachNV['name'], eachNV['value']) )

    #if not rdtagname_list:
    #    error_info.append('请至少选择一个标签！')

    return error_info


@login_required
def create_record(request):
    rdNameValueList = []
    recordNameValues = str( request.POST['recordNameValues'] )
    for eachLine in recordNameValues.split('\n'):
        tmpLine = eachLine.strip('\r \n \t')
        if tmpLine:
            lineList = tmpLine.split()
            if len(lineList) == 2:
                rdNameValueList.append( {'name':lineList[0], 'value':lineList[1] } )

    rdtagname_list = []
    tag_obj = Tag.objects.all()
    for tag in tag_obj:
        tag_key = 'tag' + str(tag.id)
        if request.POST.has_key(tag_key):
            rdtagname_list.append(tag.name)

    rdmark = str( request.POST['recordMark'].encode('utf8') )
    rdzone = str( request.POST['recordZone'] )
    rdnameserver = str( request.POST['recordDnsServer'] )

    rdtype = 'A'

    ## FIXME - 此处有待优化
    zone_obj = Zone.objects.all()
    rdttl = str( zone_obj[0].ttl )

    error_info = []
    error_info += is_valid( rdNameValueList, rdtagname_list )

    if error_info:
        return HttpResponse( '</br>'.join(error_info) )


    infoList = []
    for eachNV in rdNameValueList:
        #print eachNV

        rdname = eachNV['name']
        rdvalue = eachNV['value']

        STAT1, INFO1 = add_record_to_dns_server( rdnameserver, rdzone, rdname, rdttl, rdtype, rdvalue, request.user.username )
        infoList.append( INFO1 )

        STAT2, INFO2 = add_record_to_crms_db( rdname, rdtype, rdttl, rdvalue, rdmark, rdzone, request.user.username, '新增记录', rdtagname_list, rdnameserver )
        infoList.append( INFO2 )

    currTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    for each in infoList:
        history = History(user=request.user.username, time=currTime, action='新增记录', old='', new=each)
        history.save()

    return render_to_response('cdns/response.html', {
        "username": request.user.username,
        "user_groups": request.user.ldap_user.group_names,
        "success_info": infoList,
        "caller": "create_record"
    })



@login_required
def add_record(request, success=None, error=None):
    #print request.method
    tag_obj = Tag.objects.all()
    zone_obj = Zone.objects.values('name').distinct()
    nameserver_obj = NameServer.objects.all()

    return render_to_response('cdns/add_record.html', {
        "username": request.user.username,
        "user_groups": request.user.ldap_user.group_names,

        "tag_obj": tag_obj,
        "zone_obj": zone_obj,
        "nameserver_obj": nameserver_obj,

        "success": success,
        "error": error,
    })


def del_record_from_dns_server( dnsServer, rdzone, rdname, rdtype, rdvalue, userName ):
    INFO = ""
    try:
        valuesList = dns_server.do_query( rdname, rdzone, dnsServer )
    except Exception,e:
        return (1, '[ DNS服务器 %s，%s.%s -> %s ] DNS server 查询失败！未操作。'%( dnsServer, rdname, rdzone, rdvalue )  )

    if rdvalue not in valuesList :
        INFO = '[ DNS服务器 %s，%s.%s -> %s ] 解析记录在 DNS server 上不存在，未操作。'%(dnsServer, rdname, rdzone, rdvalue )
    else:
        try:
            dns_server.del_record( dnsServer, rdzone, rdname , rdtype, rdvalue  )
        except Exception,e:
            return (2, '[ DNS服务器 %s，%s.%s -> %s ] DNS server 删除解析记录失败！'%(dnsServer, rdname, rdzone, rdvalue ) )
        logger.debug("Delete record from dns server %s by %s: %s.%s -> %s" % (dnsServer, userName, rdname, rdzone, rdvalue)  )
        INFO = '[ DNS服务器 %s，%s.%s -> %s ] DNS server 删除解析记录成功。'%(dnsServer, rdname, rdzone, rdvalue )

    return (0, INFO)


def del_record_from_crms_db( theRecord, userName ):
    rdzone = str( theRecord.zone )
    rdname = str( theRecord.name )
    rdtype = str( theRecord.rdtype )
    rdvalue = str( theRecord.value )
    rdnameserver = str( theRecord.nameserver )

    INFO = ''
    currTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())

    theRecord.status = 2
    try:
        theRecord.save()
        logger.debug("Delete record from database by %s:  %s  %s.%s -> %s" % ( userName, rdnameserver, rdname, rdzone, rdvalue)  )
        INFO = '[ DNS服务器 %s，%s.%s -> %s ] CRMS 数据库删除记录成功。'% ( rdnameserver, rdname, rdzone, rdvalue )
    except:
        logger.error("Failed to delete record from database by %s:  %s  %s.%s -> %s" % ( userName, rdnameserver, rdname, rdzone, rdvalue)  )
        INFO = '[ DNS服务器 %s，%s.%s -> %s ] CRMS 数据库删除记录失败，请手动同步。'% ( rdnameserver, rdname, rdzone, rdvalue )

    #History
    #tags = ' '.join([tag.name for tag in theRecord.tags.all()])
    #history_old = '%s IN %s %s %s</br>Tag: %s</br>Mark: %s</br>DNS server: %s' % (rdname, rdtype, rdvalue, rdzone, tags, theRecord.mark, rdnameserver)
    #history = History(user=userName, time=currTime, action='删除记录', old=history_old, new='N/A')
    #history.save()
    #theRecord.history.add(history)
    #theRecord.save()

    return (0, INFO)


@login_required
def delete_record(request):
    rdIdStr = str(request.GET['id'])
    rdIdList = rdIdStr.strip('\n \r \t').split(',')

    infoList = []
    for rdid in rdIdList:
        #print rdid
        if rdid:
            record_obj = Record.objects.filter( id=rdid, status=0 )
            #print record_obj
            if not record_obj:
                infoList.append( '[ id = %s ] 数据库查询失败，未操作。'% rdid )
            else:
                record = record_obj[0]
                rdzone = str( record.zone )
                rdname = str( record.name )
                rdtype = str( record.rdtype )
                rdvalue = str( record.value )
                rdnameserver = str( record.nameserver )

                STAT1, INFO1 = del_record_from_dns_server( rdnameserver, rdzone, rdname, rdtype, rdvalue, request.user.username )
                infoList.append( INFO1 )

                STAT2, INFO2 = del_record_from_crms_db( record, request.user.username )
                infoList.append( INFO2 )

    currTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    for each in infoList:
        history = History(user=request.user.username, time=currTime, action='删除记录', old='', new=each)
        history.save()

    return render_to_response('cdns/response.html', {
        "username": request.user.username,
        "user_groups": request.user.ldap_user.group_names,
        "success_info": infoList,
        "caller": "delete_record"
    })


@login_required
def confirm_delete(request):
    rdIdList = request.REQUEST.getlist('recordCheckbox')
    record_obj = Record.objects.filter(id__in=rdIdList).exclude(status=2).order_by('-id')
    #print record_obj
    return render_to_response('cdns/confirm_delete.html', {
        "username": request.user.username,
        "user_groups": request.user.ldap_user.group_names,
        "record_obj": record_obj,
    })


def modify_record(request):
    recordId = request.POST.get('recordId','')
    rdnameserver = str(request.POST.get('recordDnsServer',''))
    rdzone = str(request.POST.get('recordZone',''))
    rdname = str(request.POST.get('recordName',''))
    rdvalue = str(request.POST.get('recordValue',''))
    rdtag_list = request.POST.getlist('recordTag')
    recordMark = str(request.POST.get('recordMark','').encode('utf8'))

    theRecord = Record.objects.get(id=recordId)

    infoList = []
    STAT2, INFO2 = del_record_from_dns_server( str(theRecord.nameserver), str(theRecord.zone), str(theRecord.name), str(theRecord.rdtype), str(theRecord.value), str(theRecord.create_by) )
    infoList.append( INFO2 )
    STAT1, INFO1 = add_record_to_dns_server( rdnameserver, rdzone, rdname, str(theRecord.ttl), str(theRecord.rdtype), rdvalue, str(theRecord.create_by) )
    infoList.append( INFO1 )


    theRecord.mark = recordMark
    theRecord.value = rdvalue
    theRecord.zone = rdzone
    theRecord.name = rdname
    theRecord.nameserver = rdnameserver
    try:
        theRecord.save()
        logger.debug("Update record from database by %s:  %s  %s.%s -> %s" % ( str(theRecord.create_by), rdnameserver, rdname, rdzone, rdvalue)  )
        INFO = '[ DNS服务器 %s，%s.%s -> %s ] CRMS 数据库修改记录成功。'% ( rdnameserver, rdname, rdzone, rdvalue )
    except:
        logger.error("Failed to update record from database by %s:  %s  %s.%s -> %s" % ( str(theRecord.create_by), rdnameserver, rdname, rdzone, rdvalue)  )
        INFO = '[ DNS服务器 %s，%s.%s -> %s ] CRMS 数据库修改记录失败，请手动同步。'% ( rdnameserver, rdname, rdzone, rdvalue )
    infoList.append( INFO )

    theRecord.tags.clear()
    for tagname in rdtag_list:
        tag = Tag.objects.get(name=tagname)
        theRecord.tags.add(tag)

    currTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    for each in infoList:
        history = History(user=theRecord.create_by, time=currTime, action='修改记录', old='', new=each)
        history.save()

    return render_to_response('cdns/response.html', {
        "username": request.user.username,
        "user_groups": request.user.ldap_user.group_names,
        "success_info": infoList,
        "caller": "delete_record"
    })

def show_record(request):
    ## deprecated
    recordId = request.POST.get('recordId','')
    theRecord = Record.objects.get(id=recordId)

    result_dict = {}
    result_dict['name'] = theRecord.name
    result_dict['value'] = theRecord.value
    result_dict['mark'] = theRecord.mark
    result_dict['zone'] = theRecord.zone
    result_dict['nameserver'] = theRecord.nameserver
    result_dict['tags'] = []
    for tag in theRecord.tags.all():
        result_dict['tags'].append(tag.name)

    return HttpResponse(json.dumps(result_dict, ensure_ascii=False))

@login_required
def activate_record(request):
    ## deprecated
    return index(request, '' )


@login_required
def create_tag(request):
    error_info = []
    tagname = request.POST['tagName']
    if tagname == '':
        error_info.append('标签名不能为空！')
        return index(request, '\n'.join(error_info))
    tag_obj = Tag.objects.filter(name=tagname)
    if tag_obj:
        error_info.append('该标签已存在，请检查！')
        return index(request, '\n'.join(error_info))

    #History
    history = History(user=request.user.username, time=time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()), \
                      action='新建标签', old='N/A', new=tagname)
    try:
        history.save()
        logger.debug("Write history info for create tag %s" % tagname)
    except:
        logger.error("Write history info for create tag %s FAILED" % tagname)

    #Create tag
    tag = Tag(name=tagname, status=0)
    try:
        tag.save()
        tag.history.add(history)
        tag.save()
        logger.debug("CREATE tag %s" % tagname)
    except:
        logger.error("CREATE tag %s FAILED" % tagname)

    return index(request)


@login_required
def modify_tag(request):
    error_info = []
    tagid = request.GET['id']
    tag = get_object_or_404(Tag, pk=tagid)
    tagname = request.POST['tagName']
    if tagname == '':
        error_info.append('标签名不能为空！')
        return index(request, '\n'.join(error_info))
    tag_obj = Tag.objects.filter(name=tagname)
    if tag_obj:
        error_info.append('该标签已存在，请检查！')
        return index(request, '\n'.join(error_info))

    #History
    history = History(user=request.user.username, time=time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()), \
                      action='修改标签', old=tag.name, new=tagname)
    try:
        history.save()
        logger.debug("Write history info to MODIFY tag %s to %s" % (tag.name, tagname))
    except:
        logger.error("Write history info to MODIFY tag %s to %s FAILED" % (tag.name, tagname))

    #Modify tag
    tag.name = tagname
    tag.history.add(history)
    try:
        tag.save()
        logger.debug("MODIFY tag %s to %s" % (tag.name, tagname))
    except:
        logger.error("MODIFY tag %s to %s FAILED" % (tag.name, tagname))

    return index(request)


@login_required
def delete_tag(request):
    tagid = request.GET['id']
    tag = get_object_or_404(Tag, pk=tagid)

    #History
    history = History(user=request.user.username, time=time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()), \
                      action='删除标签', old=tag.name, new='N/A')
    try:
        history.save()
        logger.debug("Write history info for DELETE tag %s" % tag.name)
    except:
        logger.error("Write history info for DELETE tag %s FAILED" % tag.name)

    #Change tag status to delete
    tag.status = 1
    tag.history.add(history)
    try:
        tag.save()
        logger.debug("Change record status to DELETE tag %s" % tag.name)
    except:
        logger.error("Change record status to DELETE tag %s FAILED" % tag.name)

    return index(request)


@login_required
def activate_tag(request):
    tagid = request.GET['id']
    tag = get_object_or_404(Tag, pk=tagid)

    #History
    history = History(user=request.user.username, time=time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()), \
                      action='恢复标签', old='N/A', new=tag.name)
    try:
        history.save()
        logger.debug("Write history info to activate %s" % tag.name)
    except:
        logger.error("Write history info to activate %s FAILED" % tag.name)

    #Change tag status to activate
    tag.status = 0
    tag.history.add(history)
    try:
        tag.save()
        logger.debug("Change tag status to ACTIVATE %s" % tag.name)
    except:
        logger.error("Change tag status to ACTIVATE %s FAILED" % tag.name)

    return index(request)


def check_diff_between_dns_and_crmsdb(dnsServer, zoneList):
    dnsCount = 0
    crmsCount = 0
    onlyInDns = []
    onlyInCrms = []
    for eachZone in zoneList:
    #for eachZone in []:
        all_records_in_dns_server = dns_server.get_all_records( dnsServer, eachZone.name )
        ## [ {'name':'', 'type':'', 'ttl':'', 'value':'', }, ... ]
        rdDictDns = {}
        for eachRd in all_records_in_dns_server:
            if eachRd['type'] == 'A':
                key = eachRd['name'] + eachRd['value']
                eachRd['zone'] = str(eachZone.name)
                rdDictDns[key] = eachRd
        dnsCount += len(rdDictDns)

        all_records_in_crms = Record.objects.filter(status=0, zone=eachZone.name , nameserver=dnsServer )
        recordCrmsDict = {}
        for rd in all_records_in_crms:
            key = rd.name + rd.value
            recordCrmsDict[key] = {'name':str(rd.name), 'type':str(rd.rdtype), 'ttl':str(rd.ttl), 'value':str(rd.value), 'zone':str(eachZone.name) }
        crmsCount += len(recordCrmsDict)

        set1 = set( rdDictDns.keys() )
        set2 = set( recordCrmsDict.keys() )
        for each in set1-set2:
            onlyInDns.append( rdDictDns[each] )
        for each in set2-set1:
            onlyInCrms.append( recordCrmsDict[each] )

    diff_list = []
    for each in onlyInDns:
        each['category'] = 'DNS'
        diff_list.append( each )
    for each in onlyInCrms:
        each['category'] = 'CRMS'
        diff_list.append( each )

    diff_list = sorted( diff_list, key=lambda x:x['name']+x['zone'] )

    """
    aaa = '''
    172.18.9.75 allinone-cab02-v-o
    172.18.9.76 allinone-bss01-v-o
    172.18.9.77 allinone-bss02-v-o
    172.18.9.78 allinone-report01-v-o
    172.18.9.87 allinone-doc01-v-o
    172.18.9.88 allinone-doc02-v-o
    172.18.9.28 allinone-nginx01-v-o
    172.18.9.29 allinone-nginx02-v-o
    172.18.9.82 allinone-storelog01-v-o
    172.18.9.86 allinone-storelog02-v-o
    172.18.9.25 allinone-portals01-v-o
    172.18.9.26 allinone-portals02-v-o
    '''
    L = []
    for eachLine in aaa.split('\n'):
        lll = eachLine.strip('\n \r \t').split()
        if lll:
            L.append( {'name':lll[1], 'value':lll[0], 'ttl':'600', 'type':'A', 'zone':'XXXXXX.com' , 'category':'DNS'} )

    diff_list += L
    """

    return ( diff_list, dnsCount, crmsCount )



@login_required
def sync_data(request, error=None):

    if request.method == 'GET':
        syncDnsServer = str( request.GET['syncDnsServer'] )
        #print syncDnsServer

        allZone = Zone.objects.filter(ip=syncDnsServer)
        diff_list, dnsCount, crmsCount = check_diff_between_dns_and_crmsdb( syncDnsServer, allZone )

        return render_to_response('cdns/sync.html', {
            "username": request.user.username,
            "user_groups": request.user.ldap_user.group_names,
            "diff_list": diff_list,
            "syncDnsServer": syncDnsServer,
            "dnsCount": dnsCount,
            "crmsCount": crmsCount,
            })

    elif request.method == 'POST':
        syncDnsServer = syncDnsServer = str( request.POST['syncDnsServer'] )
        allZone = Zone.objects.filter(ip=syncDnsServer)

        diff_list, dnsCount, crmsCount = check_diff_between_dns_and_crmsdb(syncDnsServer, allZone)

        infoList = []
        for rd in diff_list:
            if rd['category'] == 'CRMS':
                STAT1, INFO1 = add_record_to_dns_server( syncDnsServer, rd['zone'], rd['name'], rd['ttl'], rd['type'], rd['value'], request.user.username )
                infoList.append( INFO1 )
            elif rd['category'] == 'DNS':
                STAT2, INFO2 = add_record_to_crms_db( rd['name'],  rd['type'], rd['ttl'], rd['value'], '', rd['zone'], request.user.username, '同步数据', [], syncDnsServer )
                infoList.append( INFO2 )

        currTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        for each in infoList:
            history = History(user=request.user.username, time=currTime, action='同步数据', old='', new=each)
            history.save()

        return render_to_response('cdns/response.html', {
            "username": request.user.username,
            "user_groups": request.user.ldap_user.group_names,
            "success_info": infoList,
            "caller": "sync_data"
             })


def check_diff_between_dns_and_dns(dnsServer1, dnsServer2, zoneList):
    dnsCount1 = 0
    dnsCount2 = 0
    onlyIn1 = []
    onlyIn2 = []
    for eachZone in zoneList.values('name' ).distinct():
    #for eachZone in []:
        zone_name = eachZone['name']
        rdDict1 = {}
        rdDict2 = {}

        if len(zoneList.filter(ip=dnsServer1,name=zone_name))>0:
            all_records_in_dns_server1 = dns_server.get_all_records( dnsServer1, zone_name )
            for eachRd in all_records_in_dns_server1:
                if eachRd['type'] == 'A':
                    key = eachRd['name'] + eachRd['value']
                    eachRd['zone'] = str(zone_name)
                    rdDict1[key] = eachRd
            dnsCount1 += len(rdDict1)
        if len(zoneList.filter(ip=dnsServer2,name=zone_name))>0:
            all_records_in_dns_server2 = dns_server.get_all_records( dnsServer2, zone_name )
            for eachRd in all_records_in_dns_server2:
                if eachRd['type'] == 'A':
                    key = eachRd['name'] + eachRd['value']
                    eachRd['zone'] = str(zone_name)
                    rdDict2[key] = eachRd
            dnsCount2 += len(rdDict2)
        ## convert to dict

        set1 = set( rdDict1.keys() )
        set2 = set( rdDict2.keys() )
        for each in set1-set2:
            onlyIn1.append( rdDict1[each] )
        for each in set2-set1:
            onlyIn2.append( rdDict2[each] )

    """
    aaa = '''
    172.18.9.75 allinone-cab02-v-o
    172.18.9.76 allinone-bss01-v-o
    172.18.9.77 allinone-bss01-v-o
    172.18.9.78 allinone-bss01-v-o
    172.18.9.87 allinone-bss01-v-o
    172.18.9.88 allinone-doc02-v-o
    172.18.9.28 BBBinone-nginx01-v-o
    172.18.9.29 VVVinone-nginx02-v-o
    172.18.9.82 CCCinone-storelog01-v-o
    172.18.9.86 hhhinone-storelog02-v-o
    172.18.9.25 eeeinone-portals01-v-o
    172.18.9.26 allinone-portals02-v-o
    '''
    L = []
    for eachLine in aaa.split('\n'):
        lll = eachLine.strip('\n \r \t').split()
        if lll:
            L.append( {'name':lll[1], 'value':lll[0], 'ttl':'600', 'type':'A', 'zone':'XXXXXX.com' , 'category':'DNS'} )

    onlyIn1 = L
    onlyIn2 = L
    """

    return ( onlyIn1, onlyIn2, dnsCount1, dnsCount2 )



def diff_dns_server( request ):
    allZone = Zone.objects.all()

    if request.method == 'GET':
        dnsServer1 = str( request.GET['dnsServer1'] )
        dnsServer2 = str( request.GET['dnsServer2'] )

        onlyIn1, onlyIn2, dnsCount1, dnsCount2 = check_diff_between_dns_and_dns( dnsServer1, dnsServer2, allZone )

        diffDict = {}
        for each in onlyIn1:
            theKey = each['name']+'.'+each['zone']
            if not diffDict.has_key( theKey ):
                diffDict[theKey] = { 'domainName':theKey, 'dns1':[], 'dns2':[] }
            diffDict[theKey]['dns1'].append( each['value'] )
        for each in onlyIn2:
            theKey = each['name']+'.'+each['zone']
            if not diffDict.has_key( theKey ):
                diffDict[theKey] = { 'domainName':theKey, 'dns1':[], 'dns2':[] }
            diffDict[theKey]['dns2'].append( each['value'] )

        diffList = sorted( diffDict.values(), key=lambda x:x['domainName'] )

        return render_to_response('cdns/diff_dns2.html', {
            "username": request.user.username,
            "user_groups": request.user.ldap_user.group_names,
            "dnsServer1": dnsServer1,
            "dnsServer2": dnsServer2,
            "dnsCount1": dnsCount1,
            "dnsCount2": dnsCount2,
            "diffList": diffList,
            })



@login_required
def record_comparison(request, success=None, error=None):
    #print request.method
    nameserver_obj = NameServer.objects.all()

    return render_to_response('cdns/record_comparison.html', {
        "username": request.user.username,
        "user_groups": request.user.ldap_user.group_names,

        "nameserver_obj": nameserver_obj,

        "success": success,
        "error": error,
    })




@login_required
def operation_audit(request, success=None, error=None):

    return render_to_response('cdns/operation_audit.html', {
        "username": request.user.username,
        "user_groups": request.user.ldap_user.group_names,

        "success": success,
        "error": error,
    })




def check_diff_pb(request):
    '''Get data from CDNS'''
    result_cdns = Record.objects.filter(status=0)
    '''Get data from puppet'''
    cursor = db_connect['puppet'].cursor()
    sql = "SELECT group_concat(value) FROM fact_values a LEFT JOIN fact_names b ON a.fact_name_id = b.id \
    WHERE name = 'hostname' OR (name LIKE 'network_%%' AND name <> 'network_lo') GROUP BY host_id"
    cursor.execute(sql)
    result_puppet = cursor.fetchall()
    puppet_data_dict = {}
    for item in result_puppet:
        item0_list_sorted = sorted(item[0].split(','), reverse=True)
        key = item0_list_sorted[0].lower()      #key: hostname
        value = item0_list_sorted[1:]           #value: ip list
        puppet_data_dict[key] = value
    '''Check different with bind and puppet'''
    diff_list = []
    for item in result_cdns:
        hostname = item.name.lower()
        if hostname in puppet_data_dict.keys():
            puppet_data_dict.pop(hostname)
        elif item.rdtype == 'A':
            diff_list.append({'name': hostname, 'value': item.value, 'category': 'cdns', 'id': item.id})
    for key in puppet_data_dict:
        diff_list.insert(0, {'name': key, 'value': puppet_data_dict[key], 'category': 'Puppet'})

    return HttpResponse(json.dumps(diff_list))




def all_record_tree_json(request):
    allRD = Record.objects.all().exclude(status=2).order_by('zone', 'name')
    l = []
    for each in allRD:
        l.append( { 'name':'-'.join( [ str(each.zone) , str(each.name) ] ) , 'value':str(each.value) } )

    L = []
    for eachrd in l:
        nameSplit = eachrd['name'].split('-')
        tmpL = L
        for i in range(len(nameSplit)):
            if i == len(nameSplit)-1:
                tmpL.append( { 'name':'-'.join(nameSplit[1:])+'.'+nameSplit[0]+'_'+eachrd['value'] } )
            else:
                fl = filter( lambda x: x['name'] == nameSplit[i], tmpL )
                if not fl:
                    tmpD = { 'name':nameSplit[i], 'children':[] }
                    tmpL.append( tmpD )
                    tmpL = tmpD['children']
                else:
                    tmpL = fl[0]['children']

    #print L

    return HttpResponse(json.dumps(L))




def tree(request):
    return render_to_response('cdns/tree.html', {
        "username": request.user.username,
        "user_groups": request.user.ldap_user.group_names,

    })

def menu(request):

    type2 = request.GET.get('type','domain')

    L = []

    if type2 == 'domain':
        allRD = Record.objects.exclude(status=2).values('zone', 'name', 'value').order_by('zone', 'name','value').distinct()
        l = []
        for each in allRD:
            l.append({'name': '-'.join([str(each['zone']), str(each['name'])]), 'value': str(each['value'])})

        L = []
        for eachrd in l:
            nameSplit = eachrd['name'].split('-')
            tmpL = L
            for i in range(len(nameSplit)):
                if i == len(nameSplit)-1:
                    #tmpL.append( { 'text':'-'.join(nameSplit[1:]), 'leaf':True ,'ip':eachrd['value']} )
                    rdname = '-'.join(nameSplit[1:])
                    tmpL.append( { 'text':rdname +' ('+eachrd['value']+')', 'leaf':True ,'ip':eachrd['value'], 'rdname':rdname, 'type2':type2 } )
                else:
                    fl = filter( lambda x: x['text'] == nameSplit[i] and x.has_key('children'), tmpL )
                    #添加x.has_key('children')
                    if fl:

                        tmpL = fl[0]['children']
                    else:
                        tmpD = { 'text':nameSplit[i], 'children':[], 'type2':type2  }
                        tmpL.append( tmpD )
                        tmpL = tmpD['children']

    if type2 == 'position':

        l = []
        for each in cserver.models.physicalMachine.objects.all():
            if each.idc:
                IDC = str( each.idc.encode('utf8') )
            else:
                IDC = '(空)'
            if each.rack:
                RACK = str( each.rack.encode('utf8') )
            else:
                RACK = '(空)'
            if each.shelf:
                SHELF = str( each.shelf.encode('utf8') )
            else:
                SHELF = '(空)'

            l.append( { 'name':[ '全部机房', IDC, RACK, SHELF ] , 'value':str(each.sn) } )
        L = []
        for eachrd in l:
            nameSplit = eachrd['name']
            tmpL = L
            for i in range(len(nameSplit)):
                if i == len(nameSplit)-1:
                    #tmpL.append( { 'text':'-'.join(nameSplit[1:]), 'leaf':True ,'ip':eachrd['value']} )
                    rdname = ' # '.join(nameSplit[1:])
                    tmpL.append( { 'text':rdname +' ('+eachrd['value']+')', 'leaf':True ,'ip':eachrd['value'], 'rdname':rdname, 'type2':type2 } )
                else:
                    fl = filter( lambda x: x['text'] == nameSplit[i] and x.has_key('children'), tmpL )
                    #添加x.has_key('children')
                    if fl:

                        tmpL = fl[0]['children']
                    else:
                        tmpD = { 'text':nameSplit[i], 'children':[], 'type2':type2  }
                        tmpL.append( tmpD )
                        tmpL = tmpD['children']

    if type2 == 'serverModel':

        grid_results = cserver.models.physicalMachine.objects.all()

        l = []
        for each in grid_results:
            if each.vendor:
                VENDOR = str( each.vendor.encode('utf8') )
            else:
                VENDOR = '(空)'

            if each.model:
                MODEL = str( each.model.encode('utf8') )
            else:
                MODEL = '(空)'

            l.append( { 'name':[ '全部机型', VENDOR, MODEL, ''  ] , 'value':str(each.sn) } )

        L = []
        for eachrd in l:
            nameSplit = eachrd['name']
            tmpL = L
            for i in range(len(nameSplit)):
                if i == len(nameSplit)-1:
                    #tmpL.append( { 'text':'-'.join(nameSplit[1:]), 'leaf':True ,'ip':eachrd['value']} )
                    rdname = ' # '.join(nameSplit[1:])
                    tmpL.append( { 'text':rdname +' ('+eachrd['value']+')', 'leaf':True ,'ip':eachrd['value'], 'rdname':rdname, 'type2':type2 } )
                else:
                    fl = filter( lambda x: x['text'] == nameSplit[i] and x.has_key('children'), tmpL )
                    #添加x.has_key('children')
                    if fl:

                        tmpL = fl[0]['children']
                    else:
                        tmpD = { 'text':nameSplit[i], 'children':[], 'type2':type2  }
                        tmpL.append( tmpD )
                        tmpL = tmpD['children']

    if type2 == 'app':


        allRD = capp.models.appProject.grid_data.showMenu()

        L = []
        for eachrd in allRD:
            leaf = {'text':eachrd['sn'], 'leaf':True , 'ip':eachrd['sn'], 'rdname':'', 'type2':type2 }

            fl = filter( lambda x: x['text'] == eachrd['deploy_type'] and x.has_key('children'), L )
            if (fl):
                fl2 = filter( lambda x: x['text'] == eachrd['production'] and x.has_key('children'), fl[0]['children'] )

                if (fl2):
                    fl3 = filter( lambda x: x['text'] == eachrd['app_type'] and x.has_key('children'), fl2[0]['children'] )

                    if (fl3):
                        fl4 = filter( lambda x: x['text'] == eachrd['app_name'] and x.has_key('children'), fl3[0]['children'] )

                        if (fl4):
                            fl4[0]['children'].append( leaf )
                        else:
                            fl3[0]['children'].append( { 'text':eachrd['app_name'], 'children':[leaf], 'type2':type2  } )
                    else:
                        fl2[0]['children'].append( { 'text':eachrd['app_type'], 'children':[{ 'text':eachrd['app_name'], 'children':[leaf], 'type2':type2  }], 'type2':type2  } )
                else:
                    fl[0]['children'].append( { 'text':eachrd['production'], 'children':[{ 'text':eachrd['app_type'], 'children':[{ 'text':eachrd['app_name'], 'children':[leaf], 'type2':type2  }], 'type2':type2  }], 'type2':type2 } )
            else:
                L.append({ 'text':eachrd['deploy_type'], 'children':[{ 'text':eachrd['production'], 'children':[{ 'text':eachrd['app_type'], 'children':[{ 'text':eachrd['app_name'], 'children':[leaf], 'type2':type2  }], 'type2':type2  }], 'type2':type2  }], 'type2':type2  })


 #   print L
    if type2 == 'user':

        allRD = cserver.models.physicalMachine.objects.all()

        L = []
        for eachrd in allRD:
            leaf = {'text':eachrd.sn, 'leaf':True , 'ip':eachrd.sn, 'rdname':'physicalMachine', 'type2':type2 }

            fl = filter( lambda x: x['text'] == eachrd.mac_user and x.has_key('children'), L )
            if (fl):
                fl[0]['children'].append( leaf )

            else:
                L.append({ 'text':eachrd.mac_user, 'children':[leaf], 'type2':type2   })

        allRD2 = cserver.models.virtualMachine.objects.all()
        for eachrd in allRD2:
            leaf = {'text':eachrd.sn, 'leaf':True , 'ip':eachrd.sn, 'rdname':'virtualMachine', 'type2':type2 }

            fl = filter( lambda x: x['text'] == eachrd.mac_user and x.has_key('children'), L )
            if (fl):
                fl[0]['children'].append( leaf )
            else:
                L.append({ 'text':eachrd.mac_user, 'children':[leaf], 'type2':type2   })
    return HttpResponse(json.dumps(L))


def showComment(request):
    zone = request.POST.get('zone','')
    domain = request.POST.get('domain','')
    ip = request.POST.get('ip','')

    comment = Record.objects.exclude(status=2).filter(zone=zone, name=domain, value=ip)

    result = []

    for item in comment:
        comment_dict = {}
        comment_dict['nameserver'] = item.nameserver
        comment_dict['mark'] = item.mark

        result.append(comment_dict)

    return HttpResponse(json.dumps(result, ensure_ascii=False))

def saveComment(request):
    zone = request.POST.get('zone','')
    domain = request.POST.get('domain','')
    ip = request.POST.get('ip','')
    dns = request.POST.get('dns','')
    comment = request.POST.get('comment','')

    Record.objects.exclude(status=2).filter(zone=zone, name=domain, value=ip, nameserver=dns).update(mark=comment)

    return HttpResponse({'success': True})

def showServerIp(request):
    result = []
    results = []
    obj = cserver.models.IP.objects.all()
    for item in obj:
        result.append(item.ip_addr)

    obj = Record.objects.exclude(status=2)
    for item in obj:
        result.append(item.value)

    result = list(set(result))

    for item in result:
        results.append({ 'ip_addr': item })

    return HttpResponse(json.dumps(results, ensure_ascii=False))
