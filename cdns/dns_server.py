#!/usr/bin/env python
# encoding: utf-8


import json, os

import dns.exception, dns.name, dns.query, dns.rcode, dns.rdata, dns.rdataclass, \
       dns.rdataset, dns.rdatatype, dns.rdtypes, dns.resolver, \
       dns.tsigkeyring, dns.update, dns.zone


def get_all_records( dnsServer, zoneName  ):
    zone = dns.zone.from_xfr(dns.query.xfr(dnsServer, zoneName))
    allKeys = zone.keys()
    result = []
    for eachKey in allKeys:
        record_str = zone[eachKey].to_text(eachKey)
        #print '\n\n', record_str, '\n\n'
        for rstr in record_str.split('\n'):
            record_list = rstr.split(' ')
            record_dict = {}
            record_dict['ttl'] = record_list[1]
            record_dict['class'] = record_list[2]
            record_dict['type'] = record_list[3]
            if record_dict['type'] == 'SOA':
                record_dict['name'] = zoneName
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
    return result


def do_query(name, zone, dnsServer, dnsPort=53, rdtype='A', usetcp=True, timeout=3, rdclass='IN' ):
    """
    query a record though the specified NS server.
    if view == False, no view will be specified.
    """
    qname = name + '.' + zone
    resolv = dns.resolver.Resolver()
    resolv.nameservers = [dnsServer]
    resolv.port = dnsPort
    resolv.lifetime = timeout
    
    valuesList = []
    try:
        result_set = resolv.query(qname, dns.rdatatype.from_text(rdtype), dns.rdataclass.from_text(rdclass), usetcp)
        valuesList = [ str(eee) for eee in result_set ]
    except dns.resolver.NXDOMAIN:
        pass
    #except Exception, e:
    #    print e
    
    return valuesList


def add_record( dnsServer, zone, name, rdttl, rdtype, rdvalue ):
    uuu = dns.update.Update( zone )
    uuu.add( name, rdttl, rdtype, rdvalue )
    #print uuu.to_text()
    res = dns.query.tcp(uuu, dnsServer, timeout=3)
    #print res.to_text()
    return res


def del_record( dnsServer, zone, name, rdtype, rdvalue ):
    uuu = dns.update.Update( zone )
    uuu.delete( name, rdtype, rdvalue )
    #print uuu.to_text()
    res = dns.query.tcp(uuu, dnsServer, timeout=3)
    #print res.to_text()
    return res
