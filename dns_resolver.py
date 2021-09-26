#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Sep 21 14:10:37 2021

@author: parasmalik
"""


import dns.resolver
import dns.query
import sys
from datetime import datetime

res = []

# Using https://www.iana.org/domains/root/servers as mentioned in the assignment
root_servers ={}
root_servers['a'] = '198.41.0.4'
root_servers['b'] = '199.9.14.201'
root_servers['c'] = '192.33.4.12'
root_servers['d'] = '199.7.91.13'
root_servers['e'] = '192.203.230.10'
root_servers['f'] = '192.5.5.241'
root_servers['g'] = '192.112.36.4'
root_servers['h'] = '198.97.190.53'
root_servers['i'] = '192.36.148.17'
root_servers['j'] = '192.58.128.30'
root_servers['k'] = '193.0.14.129'
root_servers['l'] = '199.7.83.42'
root_servers['m'] = '202.12.27.33'

def SendUDPQuery(domain, rdtype, where, breakout = 1):
    try:
        query = dns.message.make_query(domain, rdtype)
        return dns.query.udp(query, where, breakout)
    except:
        return None

def recursive_new(hostname,rdtype,response):
    if len(response.answer)>0 or (len(response.authority) > 0 and (response.authority[0].rdtype == dns.rdatatype.SOA)) >0:
        return response
    
    elif len(response.additional)>0:
        for rrset in response.additional:
            if "IN A " in rrset.to_text():
                next_ip = rrset[0].to_text()
                try:
                    response2 = SendUDPQuery(hostname, rdtype, next_ip, 0.5)
                    if response2:
                        response = response2
                        return recursive_new(hostname,rdtype,response)
                    else:
                        continue
                except Exception as e:
                    pass
            else:
                continue
    elif len(response.authority)>0:
        for rrSet in response.authority[0]:
            k = output2(rrSet.to_text(),dns.rdatatype.A)
            if k:
                response = SendUDPQuery(hostname,rdtype,k,0.5)
                if response:
                    return recursive_new(hostname,rdtype,response)
                else:
                    continue
            else:
                    pass
        
    else:
        return None 
    


def start(hostname, rdtype):
    for server in root_servers.values():
        response = SendUDPQuery(hostname,rdtype,server,0.5)
        if response == None:
            continue
        elif len(response.answer)>0 or (len(response.authority) > 0 and (response.authority[0].rdtype == dns.rdatatype.SOA)) >0:
            return response
        elif len(response.additional)>0:
            return recursive_new(hostname,rdtype,response)
        elif len(response.authority)>0:
            for rrSet in response.authority[0]:
                k = output2(rrSet.to_text(),dns.rdatatype.A)
                if k:
                    response = SendUDPQuery(hostname,rdtype,k,0.5)
                    if response:
                        return recursive_new(hostname,rdtype,response)
                    else:
                        continue
                else:
                    pass
                    
        else:
            continue
    return None


def output2(hostname,rdtype):
    response = start(hostname,rdtype)
    res = response
    #print(response)
    if response:
        if len(response.answer)>0:
            for rrSet in response.answer:
                if "IN CNAME" in rrSet.to_text():
                    #res += sys.getsizeof(response)
                    #res.append(response)
                    return output(rrSet[0].to_text(),rdtype) 
                else:
                    #res.append(response)
                    return rrSet[0].to_text()
        elif (len(response.authority) > 0 and (response.authority[0].rdtype == dns.rdatatype.SOA)):
            return response.authority[0].to_text()
    else:
        return "Cannot resolve DNS"

def output(hostname,rdtype):
    response = start(hostname,rdtype)
    #print(response)
    res= response
    if response:
        if len(response.answer)>0:
            for rrSet in response.answer:
                if "IN CNAME" in rrSet.to_text():
                    print(rrSet.to_text())
                    #res = sys.getsizeof(response)
                    return output(rrSet[0].to_text(),rdtype) 
                else:
                    print(rrSet.to_text())
                    #res.append(response)
                    return rrSet[0].to_text()
        elif (len(response.authority) > 0 and (response.authority[0].rdtype == dns.rdatatype.SOA)):
            #res.append(response)
            return response.authority[0].to_text()
    else:
        return "Cannot resolve DNS"
    
    
if __name__ == "__main__":
    hostname = sys.argv[1]
    rdtype = sys.argv[2]
    
    #hostname = "www.paypal.com"
    #rdtype = "A"
    
    print("QUESTION SECTION:") 
    print("{} IN {}". format(hostname, rdtype))
    print("")
    print("ANSWER SECTION:")
    start1 = datetime.now()
    print(output(hostname,rdtype))
    end1 = datetime.now()
    difference = end1-start1
    print("")
    print("")
    print("Query time : {} ms". format(int(difference.total_seconds()*1000)))
    print("WHEN:")
    currentDT = datetime.now()
    print(currentDT.strftime("%a %b %d %Y %H:%M:%S \n"))
    print(" ")
    print(" ")
    print("MESSAGE SIZE RECEIVED : {} ".format(sys.getsizeof(res)))
    
    