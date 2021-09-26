import dns.message as dm
import dns.rdataclass as dclass
import dns.rdatatype as dtype
import dns.query as dq
import dns.name as dn
import dns.dnssec as ds
import dns

import time
from datetime import datetime
import sys


# Using https://www.iana.org/domains/root/servers as mentioned in the assignment
root_serverss ={}
root_serverss['a'] = '198.41.0.4'
root_serverss['b'] = '199.9.14.201'
root_serverss['c'] = '192.33.4.12'
root_serverss['d'] = '199.7.91.13'
root_serverss['e'] = '192.203.230.10'
root_serverss['f'] = '192.5.5.241'
root_serverss['g'] = '192.112.36.4'
root_serverss['h'] = '198.97.190.53'
root_serverss['i'] = '192.36.148.17'
root_serverss['j'] = '192.58.128.30'
root_serverss['k'] = '193.0.14.129'
root_serverss['l'] = '199.7.83.42'
root_serverss['m'] = '202.12.27.33'

# Adding the root server to a list:
root_servers = []
for root_server in root_serverss.values():
    root_servers.append(root_server)
    
rdtype_dic = {2:"SHA256",1:"SHA1"}
    
# Values for hash of root is also provided in piazza
#http://data.iana.org/root-anchors/root-anchors.xml
    
root_hash=['49aac11d7b6f6446702e54a1607371607a1a41855200fd2ce1cdde32f24e8fb5',
           'e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d']
   
def ParseAdditionalSection(response):
    next_level_servers = []
    for rrset in response.additional:
        if "IN A " in rrset.to_text():
            next_level_servers.append(rrset[0].to_text())
    
    return next_level_servers

def ParseAuthoritySection(response):
    server_list =[]
    for rrSet in response.authority[0]:
        a1 = recursive(root_servers, rrSet.to_text(),".", "A", root_hash,global_variable)
        if a1 == None:
            return None
        elif type(a1) ==str:
            return a1
        for ans in a1.answer:
            server_list.append(ans[0].to_text())
    return server_list

def recursive(r_servers, domain, domainprev, rdtype, hash_map, global_variable):
    q_n = dn.from_text(domain)
    d_list = []
    for i in range(len(r_servers)):
        r_server = r_servers[i]
        
        try:
            q = dm.make_query(q_n, rdtype, want_dnssec = True)
            q_prev = dm.make_query(domainprev, 'DNSKEY', want_dnssec = True)
            response = dq.udp(q, r_server, timeout=10)
            response1 = dq.udp(q_prev, r_server, timeout = 10)
        except:
            response = None
            response1 = None
        
        if response == None or response1 == None:
            continue
        try:
            validation_check = response.authority[1].to_text().split(" ")[3]
        except:
            if global_variable >1:
                return "DNSSec verification failed"
            else:
                return "DNSSec not supported"
                
        
        if response.authority[1].to_text().split(" ")[3] == "DS":
  
            #validating Level1
            try:
                set1= set()
                for ans in response1.answer[0]:
                    arr = ans.to_text().split(" ")
                    if "257" in arr:
                        set1.add(ds.make_ds(domainprev, ans, rdtype_dic[int(2)], origin=None).to_text().split(" ")[3])
                        set1.add(ds.make_ds(domainprev, ans, rdtype_dic[int(1)], origin=None).to_text().split(" ")[3])
            
                flag = 1
                for id,element in enumerate(set1):
                    if element in hash_map:
                        flag = 0
                    
                if(flag==1):
                    if global_variable>1:
                        return "DNSSec verification failed"
                    else:
                        return "DNSSec not supported"
                    return None
            except:
                return "DNSSec verification failed"

            hash_map=[]
            value_to_append = response.authority[1].to_text().split(" ")[7]
            hash_map.append(response.authority[1].to_text().split(" ")[7])
        
            #Validating Level2
            try:
                key=dn.from_text(domainprev)
                value = ds.validate(response1.answer[0], response1.answer[1], {key:response1.answer[0]})
                if value is not None:
                    if global_variable>1:
                        return "DNSSec verification failed"
                    else:
                        return "DNSSec not supported"
            except:
                if global_variable>1:
                    return "DNSSec verification failed"
                else:
                    return "DNSSec not supported"  

            #validating Level3
            try:
                key=dn.from_text(domainprev)
                value = ds.validate(response.authority[1], response.authority[2], {key:response1.answer[0]})
                if value is not None:
                    if global_variable>1:
                        return "DNSSec verification failed"
                    else:
                        return "DNSSec not supported"
                global_variable +=1
            except:
                if global_variable>1:
                    return "DNSSec verification failed"
                else:
                    return "DNSSec not supported"     
        
        domainprev = response.authority[0].to_text().split(" ")[0]  
        d_list.append(domainprev)
        #if (len(response.authority) > 0 and (response.authority[0].rdtype == dns.rdatatype.SOA)):
            #return response
            
        #Parsing Answer section
        if len(response.answer)>0:
            iter1=0
            while (iter1<len(response.answer)):
                rrSet = response.answer[iter1]
                if "IN CNAME" not in rrSet.to_text():
                    return response
                else:
                    return recursive(root_servers, rrSet[0].to_text(), ".", rdtype, root_hash,global_variable)
        
        #Parsing Additional section
        elif len(response.additional)>0:
            server_list = ParseAdditionalSection(response) 
            response = recursive(server_list, domain,domainprev, rdtype,hash_map,global_variable)
            return response
        
        #Parsing Authori section
        elif len(response.authority) > 0:
                server_list = ParseAuthoritySection(response)
                if server_list == None:
                    return "DNSSec not supported"
                response = recursive(server_list, domain,domainprev,rdtype,hash_map, global_variable)
        
        if response:
            break
        else:
            pass

def ParseHostName(hostname):
    a = hostname.split(".")
    a2 = []
    for i in a:
        if i !="www":
            a2.append(i)
    return ".".join(a2)
    
    

    
if __name__ == '__main__':
    global_variable =0
    
    hostname1 = sys.argv[1]
    rdtype = sys.argv[2]
    
    hostname = ParseHostName(hostname1)
    
    
    print("")
    print("")
    print("QUESTION SECTION:") 
    print("{} IN {}". format(hostname, rdtype))
    print("")
    print("ANSWER SECTION:")
    start1 = datetime.now()
    response = recursive(root_servers, hostname, ".", rdtype, root_hash,global_variable)
    
    if response == None:
        pass
    elif type(response) == str:
        print(response)
    elif len(response.answer) ==0:
        print(response.authority[0])
    else:
        print(response.answer[0])
        print(response.answer[1])
        
    end1 = datetime.now()
    difference = end1-start1
    print("")
    print("")
    print("Query time : {} ms". format(int(difference.total_seconds()*1000)))
    print("")
    print("")
    print("WHEN:")
    currentDT = datetime.now()
    print(currentDT.strftime("%a %b %d %Y %H:%M:%S \n"))
    print("Message Size Received : {}".format(sys.getsizeof(response)))
    