#!/usr/local/bin/python2.7

import dpkt

counter=0
ipcounter=0
ethcounter=0
ipv6counter=0
icmpcounter=0
tcpcounter=0
udpcounter=0

filename='tests/test2.pcap'

for ts, pkt in dpkt.pcap.Reader(open(filename,'r')):

    counter+=1
    eth=dpkt.ethernet.Ethernet(pkt) 
    if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
       print('Ethernet Type: %d\n' % eth.type )
       continue

    ip=eth.data
    ipcounter+=1

    if ip.p==dpkt.ip.IP_PROTO_TCP: 
       tcpcounter+=1

    if ip.p==dpkt.ip.IP_PROTO_UDP:
       udpcounter+=1
   
    if ip.p==dpkt.ip.IP_PROTO_IP6: 
       ipv6counter+=1
       
    if ip.p==dpkt.ip.IP_PROTO_ICMP: 
       icmpcounter+=1

    if ip.p==dpkt.ip.IP_PROTO_ETHERIP: 
       ethcounter+=1

print "Total number of packets in the pcap file: ", counter
print "Total number of ip packets: ", ipcounter
print "Total number of ipv6 packets: ", ipv6counter
print "Total number of icmp packets: ", icmpcounter
print "Total number of tcp packets: ", tcpcounter
print "Total number of udp packets: ", udpcounter
print "Total number of eth packets: ", ethcounter