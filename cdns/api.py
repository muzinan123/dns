#!/usr/bin/env python
# encoding: utf-8

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.renderers import JSONRenderer
from rest_framework.parsers import JSONParser
import dns.exception, dns.name, dns.query, dns.rcode, dns.rdata, dns.rdataclass, \
       dns.rdataset, dns.rdatatype, dns.rdtypes, dns.resolver, \
       dns.tsigkeyring, dns.update, dns.zone
import logging
from cdns.config import DNS_SERVER, DNS_PORT, DOMAIN
import json, os


logging.basicConfig(filename = '/var/log/crms.log', level = logging.INFO, \
                    format = '%(asctime)s %(levelname)s %(name)s: %(message)s')
log = logging.getLogger('cdns.api')

#log.info('This is a test!')


class RecordList(APIView):
    """
    List or Add a new record.
    """
    '''
    def __init__(self, addr, domain, view=False, port=53, source=None, source_port=0):
        self.addr = addr
        self.port = port
        self.source = source
        self.source_port = source_port
        self.domain = dns.name.from_text(domain)
        self.view = view
        self.tsigkey = {'zhaowei': {'zhaowei': 'xGeFTyTjO3L0XBWpiP/JVg=='}, 'ufpark': {'ufpark': 'lmtXka7QKGnv+WC5BoGxKw=='}}
        self.domain_info = self._get_domain_info()
        self.keyring = dns.tsigkeyring.from_text(self.tsigkey[view]) if view != False else None
        self.update_msg = dns.update.Update(self.domain, keyring=self.keyring)
        
    def _get_domain_info(self):
        """
        Get full domain for xfr, for checking before add/remove/update records.
        """
        try:
            domain_info = dns.zone.from_xfr(dns.query.xfr(self.addr, self.domain, keyring=self.keyring))
        except dns.query.BadResponse:
            log.error("DOMAIN XFR ERROR: Bad Response.")
        except dns.zone.NoSOA:
            log.error("DOMAIN XFR ERROR: No SOA.")
        except dns.zone.NoNS:
            log.error("DOMAIN XFR ERROR: No NS.")
        except dns.exception.FormError:
            log.error("DOMAIN XFR ERROR: Form Error.")
        return domain_info
    '''
    def get(self, request):
        zone = dns.zone.from_xfr(dns.query.xfr(DNS_SERVER, DOMAIN))
        records = zone.nodes.keys()
        result = []
        for record in records:
            record_str = zone[record].to_text(record)
            for rstr in record_str.split('\n'):
                record_list = rstr.split(' ')
                record_dict = {}
                record_dict['ttl'] = record_list[1]
                record_dict['class'] = record_list[2]
                record_dict['type'] = record_list[3]            
                if record_dict['type'] == 'SOA':
                    record_dict['name'] = DOMAIN
                    record_dict['server'] = record_list[4]
                    record_dict['admin'] = record_list[5]
                    record_dict['serial'] = record_list[6]
                    record_dict['refresh'] = record_list[7]
                    record_dict['retry'] = record_list[8]
                    record_dict['expire'] = record_list[9]
                    record_dict['minimum'] = record_list[10]
                else:
                    record_dict['name'] = record_list[0]
                    record_dict['value'] = record_list[4]
                result.append(record_dict)
        #return Response(json.dumps(result, separators=(',',':'), encoding='utf-8'))
        return Response(result)
    
    def post(self, request):
        """
        generate an update message for adding record.
        """
        if isinstance(request.DATA, list):
            for record in request.DATA:
                #RecordList.post(self, record)
                update = dns.update.Update(DOMAIN)
                rdname = str(record['name'])
                rdttl = int(record['ttl'])
                rdtype = str(record['type'])
                rdvalue = str(record['value'])
                update.add(rdname, rdttl, rdtype, rdvalue)
                try:
                    response = dns.query.tcp(update, DNS_SERVER)
                    log.info("ADD RDATA %s %d IN %s %s" % (rdname, rdttl, rdtype, rdvalue))
                except:
                    log.error("ADD RDATA FAIL.")                
        else:
            update = dns.update.Update(DOMAIN)
            rdname = str(request.DATA['name'])
            rdttl = int(request.DATA['ttl'])
            rdtype = str(request.DATA['type'])
            rdvalue = str(request.DATA['value'])
            update.add(rdname, rdttl, rdtype, rdvalue)
            try:
                dns.query.tcp(update, DNS_SERVER)
                log.info("ADD RDATA %s %d IN %s %s" % (rdname, rdttl, rdtype, rdvalue))
            except:
                log.error("ADD RDATA FAIL.")
        return Response() #RecordDetail.get()


class RecordDetail(APIView):
    """
    GET / PUT / DELETE a record.
    """
    def get(self, request, name, rdtype='A', usetcp=True, timeout=10, rdclass='IN', *arg):
        """
        query a record though the specified NS server.
        if view == False, no view will be specified.
        """
        qname = name + '.' + DOMAIN
        resolv = dns.resolver.Resolver()
        resolv.nameservers = [DNS_SERVER]
        resolv.port = DNS_PORT
        resolv.lifetime = timeout
        try:
            result_set = resolv.query(qname, dns.rdatatype.from_text(rdtype), dns.rdataclass.from_text(rdclass), tcp=usetcp)
        except dns.resolver.Timeout:
            log.error("RESOLVER ERROR: Query Timeout.")
        except dns.resolver.NXDOMAIN:
            log.error("RESOLVER ERROR: Name Not Exist.")
        except dns.resolver.NoAnswer:
            log.error("RESOLVER ERROR: No Answer.")
        except dns.resolver.NoNameservers:
            log.error("RESOLVER ERROR: No Nameservers.")
        result = {'name': name, 'ttl': result_set.rrset.ttl, 'class': rdclass, \
                  'type': rdtype, 'value': result_set.rrset[0].address}
        return Response(result)
    
    def put(self, request, name, *arg):
        """
        generate an update message for replace record.
        """
        rdttl = int(request.DATA['ttl'])
        rdtype = str(request.DATA['type'])
        rdvalue = str(request.DATA['value'])
        update = dns.update.Update(DOMAIN)
        update.replace(name, rdttl, rdtype, rdvalue)
        try:
            result = dns.query.tcp(update, DNS_SERVER)
            log.info("REPLACE RDATA %s" % name)
        except:
            log.error("REPLACE RDATA FAIL.")
        return Response()
    
    def delete(self, request, name, value):
        """
        generate an update message for removing record.
        """
        '''Delete record though name
        update = dns.update.Update(DOMAIN)
        update.delete(name)
        try:
            result = dns.query.tcp(update, DNS_SERVER)
            log.info("DELETE RDATA %s" % name)
        except:
            log.error("DELETE RDATA FAIL.")
        return Response()
        '''
        '''Delete record though name and value'''
        #value = arg[0]
        update_file = "/tmp/nsupdate.txt"
        update_info = []
        update_info.append("server %s %d\n" % (DNS_SERVER, DNS_PORT))
        update_info.append("update delete %s.%s A %s\n" % (name, DOMAIN, value))
        update_info.append("send\n")
        writefile_nsupdate(update_file, update_info)
        try:
            result = os.system("nsupdate %s" % update_file)
            log.info("DELETE RDATA %s IN A %s" % (name, value))
        except:
            log.error("DELETE RDATA %s IN A %s FAILED: %s" % (name, value, result))
        os.system("rm -f %s" % update_file)
        return Response()


def writefile_nsupdate(file_name, info):
    FILE = open(file_name, "w")
    FILE.writelines(info)
    FILE.close()
    return True


def update_wrapper(func, record_list):
    for name, ttl, rdclass, rdtype, token in record_list:
        rdata_list = []
        for token_str in token:
            rdata_list.append(dns.rdata.from_text(
                dns.rdataclass.from_text(rdclass),
                dns.rdatatype.from_text(rdtype),
                token_str,
                origin=DOMAIN
            ))
            log.debug("ADD RDATA: %s, %d, %s, %s, %s" % (name, ttl, rdclass, rdtype, token))
        record_set = dns.rdataset.from_rdata_list(ttl, rdata_list)
        func(name, record_set)
