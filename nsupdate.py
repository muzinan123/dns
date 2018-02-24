#!/usr/bin/env python

import dns.tsigkeyring
import dns.update
import dns.query

key = dns.tsigkeyring.from_text({'example.com':'dLEdguf7yRdCg5rGUpX6bIo9Pm+tcUdJ5gyesQl2UZbBCzhvcsJDCaTA mocTo0lv9D4YPXGPx+Yv6gIuCjcsRA=='})

up = dns.update.Update('example.com', keyring=key)

rr = ['192.168.20.20', '192.168.20.21', '192.168.20.22']
rdata_list = [dns.rdata.from_text(dns.rdataclass.IN,dns.rdatatype.A,i) for i in rr]
ttl = 60
rdata_set = dns.rdataset.from_rdata_list(ttl,rdata_list)

up.replace('s.db',rdata_set)
print "#"*30
q = dns.query.tcp(up,'127.0.0.1')

print q
/Users/linan/Desktop/code/dns/pythondns.py
