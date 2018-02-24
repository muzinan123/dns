#!/usr/bin/env python
#coding: utf-8

from django.db import models

'''
class Record(models.Model):
    name = models.CharField(max_length=128, unique=True)
    remark = models.CharField(max_length=1024, default='')
    tag = models.CharField(max_length=256, default='')
    
    def __unicode__(self):
        return ", ".join(map(str, [self.name, self.remark, self.tag]))

class History(models.Model):
    name = models.CharField(max_length=128)
    user = models.CharField(max_length=20)
    time = models.CharField(max_length=19)
    action = models.CharField(max_length=10)
    old = models.CharField(max_length=1024, default='N/A')
    new = models.CharField(max_length=1024, default='N/A')
    
    def __unicode__(self):
        return ", ".join(map(str, [self.name, self.user, self.time, self.action, self.old, self.new]))

class Suspend(models.Model):
    name = models.CharField(max_length=128)
    ttl = models.IntegerField()
    rdtype = models.CharField(max_length=5, default='A')
    value = models.CharField(max_length=15)
    
    def __unicode__(self):
        return ", ".join(map(str, [self.name, self.ttl, self.rdtype, self.value]))

class Tag(models.Model):
    name = models.CharField('Tag Name', max_length=20)
    
    def __unicode__(self):
        return ", ".join(map(str, [self.tag]))
'''


class History(models.Model):
    user = models.CharField('操作用户', max_length=20)
    time = models.CharField('操作时间', max_length=19)
    action = models.CharField('操作', max_length=10)
    old = models.CharField('原纪录', max_length=1024, default='N/A')
    new = models.CharField('新纪录', max_length=1024, default='N/A')
    
    def __unicode__(self):
        return ", ".join(map(str, [self.name, self.user, self.time, self.action, self.old, self.new]))


class Tag(models.Model):
    name = models.CharField('标签名', max_length=20, unique=True)
    status = models.BooleanField('状态', default=0)
    history = models.ManyToManyField(History)
    
    def __unicode__(self):
        return ", ".join(map(str, [self.name, self.history]))


class Zone(models.Model):
    name = models.CharField('', max_length=128)
    ttl = models.IntegerField('TTL')
    serial = models.IntegerField()
    refresh = models.IntegerField()
    retry = models.IntegerField()
    expire = models.IntegerField()
    minimum = models.IntegerField()
    server = models.CharField('Master Server', max_length=128)
    ip = models.CharField('Master IP', max_length=15)
    
    def __unicode__(self):
        return ", ".join(map(str, [self.name, self.ttl, self.serial, self.refresh, self.retry, \
                                   self.expire, self.minimum, self.server, self.ip]))    


class Record(models.Model):
    name = models.CharField('记录名称', max_length=128)
    rdtype = models.CharField('记录类型', max_length=5)
    ttl = models.IntegerField('TTL')
    value = models.CharField('记录值', max_length=15)
    mark = models.CharField('备注', max_length=1024, default='')
    tags = models.ManyToManyField(Tag)
    status = models.IntegerField('状态', default=0)
    history = models.ManyToManyField(History)
    zone = models.CharField('zone', max_length=127, default='')
    nameserver = models.CharField('nameserver', max_length=15, default='')
    create_by = models.CharField('create_by', max_length=63, default='')
    create_time = models.DateTimeField('create_time', default='2000-01-01')
    
    def __unicode__(self):
        return ", ".join(map(str, [self.name, self.rdtype, self.ttl, self.value, \
                                   self.mark, self.tags, self.status, self.history, self.zone, self.nameserver, self.create_by, self.create_time, ]))


class NameServer(models.Model):
    ip = models.CharField('DNS服务器ip', max_length=15, unique=True)
    idc = models.CharField('DNS服务器所在机房', max_length=128)
    comment = models.CharField('备注', max_length=128)
    
    def __unicode__(self):
        return ", ".join(map(str, [self.ip, self.idc, self.comment, ]))    
