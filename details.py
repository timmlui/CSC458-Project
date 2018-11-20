#!/usr/bin/env python
"""
Use DPKT to read in a pcap file and print out the contents of the packets
This example is focused on the fields in the Ethernet Frame and IP packet
"""
import dpkt
import datetime
import socket
from dpkt.compat import compat_ord


def mac_addr(address):
    """Convert a MAC address to a readable/printable string
       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)


def inet_to_str(inet):
    """Convert inet object to a string
        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def print_packets(pcap):
    """Print out information about each packet in a pcap
       Args:
           pcap: dpkt pcap reader object (dpkt.pcap.Reader)
    """

    counter=0

    eth_counter=0
    arp_counter=0

    ipv4_counter=0
    ipv6_counter=0
    icmp_counter=0
    network_other_counter=0

    tcp_counter=0
    udp_counter=0
    transport_other_counter=0

    not_ip=0

    # For each packet in the pcap process the contents
    for timestamp, buf in pcap:

        # Total count of packets
        counter+=1

        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        #print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)

        eth_counter+=1

        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            ipv4_counter+=1
        elif eth.type == dpkt.ethernet.ETH_TYPE_IP6:
            ipv6_counter+=1
        elif eth.type == dpkt.ethernet.ETH_TYPE_ARP:
            arp_counter+=1
            continue
        else:
            network_other_counter+=1
            continue

        # Make sure the Ethernet data contains an IP packet
        # if not isinstance(eth.data, dpkt.ip.IP):
        #     print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
        #     not_ip+=1
        #     continue

        # Now unpack the data within the Ethernet frame (the IP packet)
        # Pulling out src, dst, length, fragment info, TTL, and Protocol
        ip = eth.data

        # Now check if this is an ICMP packet
        if isinstance(ip.data, dpkt.icmp.ICMP):
            icmp_counter+=1

        # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
        # do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        # more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        # fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

        # Print out the info
        # print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % \
        #       (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset))        

        if ip.p == dpkt.ip.IP_PROTO_TCP: 
            tcp_counter+=1
        elif ip.p == dpkt.ip.IP_PROTO_UDP:
            udp_counter+=1
        else:
            transport_other_counter+=1
    

    print "Total number of packets in the pcap file: ", counter

    print "-- Data Link Layer --"
    print "Total number of eth packets: ", eth_counter
    print "Total number of arp packets: ", arp_counter

    print "-- Network Layer --"
    print "Total number of ipv4 packets: ", ipv4_counter
    print "Total number of ipv6 packets: ", ipv6_counter
    print "Total number of icmp packets: ", icmp_counter
    print "Total number of other packets:", network_other_counter
    
    print "-- Transport Layer --"
    print "Total number of tcp packets: ", tcp_counter
    print "Total number of udp packets: ", udp_counter
    print "Total number of other packets:", transport_other_counter
    
    # total_equal = other_counter + arp_counter
    # equal = total_equal == not_ip
    # print("Are protocols Other and not Ethernet/ARP equal? %d vs %d: %s" % (total_equal, not_ip, equal))

    # equal2 = icmp_counter == icmp_counter2
    # print("Are ICMP counters equal? %d vs %d: %s" % (icmp_counter, icmp_counter2, equal2))


def test():
    """Open up a test pcap file and print out the packets"""
    with open('univ1_trace/univ1_pt8', 'rb') as f: #univ1_pt8.pcap
        pcap = dpkt.pcap.Reader(f)
        print_packets(pcap)


if __name__ == '__main__':
    test()