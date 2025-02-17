#!/usr/bin/env python
"""
Use DPKT to read in a pcap file and print out the contents of the packets
This example is focused on the fields in the Ethernet Frame and IP packet
"""

from pcap import Reader
import dpkt.ethernet
import dpkt.ip
import datetime
import socket
from dpkt.compat import compat_ord

import numpy as np   
import matplotlib.pyplot as plt

ip_hdr_list = []
tcp_hdr_list = []
udp_hdr_list = []

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
    eth_bytes=0

    arp_counter=0
    arp_bytes=0

    ipv4_counter=0
    ipv4_bytes=0
    
    ipv6_counter=0
    ipv6_bytes=0

    icmp_counter=0
    icmp_bytes=0

    network_other_counter=0
    network_other_bytes=0

    tcp_counter=0
    tcp_bytes=0

    udp_counter=0
    udp_bytes=0

    transport_other_counter=0
    transport_other_bytes=0

    # For each packet in the pcap process the contents
    for timestamp, buf, hdr_len in pcap:

        # Total count of packets
        counter+=1

        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        #print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)

        eth_counter += 1
        eth_bytes += hdr_len

        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            ipv4_counter += 1
            ip_hdr_list.append(20)
        elif eth.type == dpkt.ethernet.ETH_TYPE_IP6:
            ipv6_counter += 1
            ipv6_bytes += hdr_len
            ip_hdr_list.append(40)
        elif eth.type == dpkt.ethernet.ETH_TYPE_ARP:
            arp_counter += 1
            arp_bytes += hdr_len
            continue
        else:
            network_other_counter += 1
            network_other_bytes += hdr_len
            continue

        # Make sure the Ethernet data contains an IP packet
        # if not isinstance(eth.data, dpkt.ip.IP):
        #     print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
        #     not_ip+=1
        #     continue

        # Now unpack the data within the Ethernet frame (the IP packet)
        # Pulling out src, dst, length, fragment info, TTL, and Protocol
        ip = eth.data

        # Calculating ethernet frame length (eth hdr is 18 bytes)
        # eth_bytes += ip.len + 18 if ip.len + 18 >= 64 else 64

        # Now check if this is an ICMP packet
        if isinstance(ip.data, dpkt.icmp.ICMP):
            icmp_counter += 1
            icmp_bytes += hdr_len

        # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
        # do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        # more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        # fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

        # Print out the info
        # print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % \
        #       (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset))        

        if ip.p == dpkt.ip.IP_PROTO_TCP: 
            tcp_counter += 1
            if ip.data.data:
                tcp_bytes += hdr_len
            tcp_hdr = hdr_len - 18 - 20 - len(ip.data.data)
            if tcp_hdr <= 20:
                tcp_hdr_list.append(20)
            else:
                tcp_hdr_list.append(tcp_hdr)
        elif ip.p == dpkt.ip.IP_PROTO_UDP:
            udp_counter += 1
            if ip.data.data:
                udp_bytes += hdr_len
            udp_hdr_list.append(8)
        else:
            transport_other_counter += 1
            if ip.p == dpkt.ip.IP_PROTO_SCPS or ip.p == dpkt.ip.IP_PROTO_EGP:
                ipv4_bytes += hdr_len
            else:
                transport_other_bytes += hdr_len

    print("Total number of packets in the trace file: ", counter)

    print("===== Data Link Layer =====")
    print("Ethernet \t packets: %d | eth/total percentage: %s | bytes: %d" % (eth_counter, percentage(eth_counter, counter), eth_bytes))

    print("===== Network Layer =====")
    print("IPv4 \t packets: %d | ipv4/eth percentage: %s | bytes: %d" % (ipv4_counter, percentage(ipv4_counter, eth_counter), ipv4_bytes))
    print("IPv6 \t packets: %d | ipv6/eth percentage: %s | bytes: %d" % (ipv6_counter, percentage(ipv6_counter, eth_counter), ipv6_bytes))
    print("ICMP \t packets: %d | icmp/eth percentage: %s | bytes: %d" % (icmp_counter, percentage(icmp_counter, eth_counter), icmp_bytes))
    print("ARP \t packets: %d | arp/eth percentage: %s | bytes: %d" % (arp_counter, percentage(arp_counter, eth_counter), arp_bytes))
    print("Other \t packets: %d | other/eth percentage: %s | bytes: %d" % (network_other_counter, percentage(network_other_counter, eth_counter), network_other_bytes))
    
    print("===== Transport Layer =====")
    print("TCP \t packets: %d | tcp/(ipv4+ipv6) percentage: %s | bytes: %d" % (tcp_counter, percentage(tcp_counter, ipv4_counter+ipv6_counter), tcp_bytes))
    print("UDP \t packets: %d | udp/(ipv4+ipv6) percentage: %s | bytes: %d" % (udp_counter, percentage(udp_counter, ipv4_counter+ipv6_counter), udp_bytes))
    print("Other \t packets: % d | other/(ipv4+ipv6) percentage: %s | bytes: %d" % \
        (transport_other_counter, percentage(transport_other_counter, ipv4_counter+ipv6_counter), transport_other_bytes))

    show_cdf_graphs()

def show_cdf_graphs():
    # IP Hdr
    ip_hdr_data = np.sort(ip_hdr_list)
    yvals_all =  np.arange(len(ip_hdr_data))/float(len(ip_hdr_data)-1)
    plt.ylabel('Cumulivitive Probability')
    plt.xlabel('IP hdr size')
    plt.title("CDF of IP Hdr Size")
    plt.plot(ip_hdr_data, yvals_all)
    plt.show()
    # TCP Hdr
    tcp_hdr_data = np.sort(tcp_hdr_list)
    yvals_all =  np.arange(len(tcp_hdr_data))/float(len(tcp_hdr_data)-1)
    plt.ylabel('Cumulivitive Probability')
    plt.xlabel('TCP hdr size')
    plt.title("CDF of TCP Hdr Size")
    plt.plot(tcp_hdr_data, yvals_all)
    plt.show()
    # UDP Hdr
    udp_hdr_data = np.sort(udp_hdr_list)
    yvals_all =  np.arange(len(udp_hdr_data))/float(len(udp_hdr_data)-1)
    plt.ylabel('Cumulivitive Probability')
    plt.xlabel('UDP hdr size')
    plt.title("CDF of UDP Hdr Size")
    plt.plot(udp_hdr_data, yvals_all)
    plt.show()

def test():
    """Open up a test pcap file and print out the packets"""
    with open('univ1_pt8.pcap', 'rb') as f:
        pcap = Reader(f)
        print_packets(pcap)

def percentage(x, y):
    return '{:.6%}'.format(x/float(y))

if __name__ == '__main__':
    test()