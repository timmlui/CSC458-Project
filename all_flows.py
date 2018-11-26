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
from flow import Flow
from packet import Packet

import numpy as np   
import matplotlib.pyplot as plt
import operator


all_flows = {}
tcp_flows = {}
udp_flows = {}
tcp_host_pairs = {}

all_flow_dur = []
tcp_flow_dur = []
udp_flow_dur = []

all_flow_size_pkt = []
tcp_flow_size_pkt = []
udp_flow_size_pkt = []

all_flow_size_byte = []
tcp_flow_size_byte = []
tcp_flow_size_overhead = []
udp_flow_size_byte = []

all_flow_time = []
tcp_flow_time = []
udp_flow_time = []

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

    # For each packet in the pcap process the contents
    for timestamp, buf, hdr_len in pcap:
        
        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        # print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)

        # Make sure the Ethernet data contains an IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            # print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
            continue

        # Now unpack the data within the Ethernet frame (the IP packet)
        # Pulling out src, dst, length, fragment info, TTL, and Protocol
        ip = eth.data

        # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
        # do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        # more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        # fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

        # Print out the info
        # print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % \
        #       (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset))        

        pkt = Packet(timestamp, buf, hdr_len)

        if ip.p == dpkt.ip.IP_PROTO_TCP or ip.p == dpkt.ip.IP_PROTO_UDP: 
            # all flow
            flow = Flow(ip.src, ip.dst, ip.data.sport, ip.data.dport, ip.p)
            if flow not in all_flows:
                all_flows[flow] = [pkt]
            else:
                x = len(all_flows[flow]) - 1
                if x < 0:
                    all_flows[flow].append(pkt)
                else:
                    if time_diff(all_flows[flow][x].timestamp, timestamp) <= 5400: #90mins
                        all_flows[flow].append(pkt)

        if ip.p == dpkt.ip.IP_PROTO_TCP: 
            # TCP flow
            flow = Flow(ip.src, ip.dst, ip.data.sport, ip.data.dport, ip.p)
            if flow not in tcp_flows:
                tcp_flows[flow] = [pkt]
            else:
                x = len(tcp_flows[flow]) - 1
                if x < 0:
                    tcp_flows[flow].append(pkt)
                else:
                    if time_diff(tcp_flows[flow][x].timestamp, timestamp) <= 5400:
                        tcp_flows[flow].append(pkt)
            all_host_pairs(pkt, ip)
        elif ip.p == dpkt.ip.IP_PROTO_UDP:
            # UDP flow
            flow = Flow(ip.src, ip.dst, ip.data.sport, ip.data.dport, ip.p)
            if flow not in udp_flows:
                udp_flows[flow] = [pkt]
            else:
                x = len(udp_flows[flow]) - 1
                if x < 0:
                    udp_flows[flow].append(pkt)
                else:
                    if time_diff(udp_flows[flow][x].timestamp, timestamp) <= 5400:
                        udp_flows[flow].append(pkt)
        else:
            continue

    print("Number of All flows: %d | Number of TCP flows: %d | Number of UDP flows: %d" % (len(all_flows), len(tcp_flows), len(udp_flows)))

    # -- Flow Duration
    for f in all_flows:
        size = len(all_flows[f])
        if size >= 2:
            all_flow_dur.append(time_diff(all_flows[f][0].timestamp, all_flows[f][size-1].timestamp))
    
    for f in tcp_flows:
        size = len(tcp_flows[f])
        if size >= 2:
            tcp_flow_dur.append(time_diff(tcp_flows[f][0].timestamp, tcp_flows[f][size-1].timestamp))
    
    for f in udp_flows:
        size = len(udp_flows[f])
        if size >= 2:
            udp_flow_dur.append(time_diff(udp_flows[f][0].timestamp, udp_flows[f][size-1].timestamp))

    print "lens: ", len(all_flow_dur), len(tcp_flow_dur), len(udp_flow_dur)

    # -- Flow Size
    for f in all_flows:
        f_bytes = 0
        size = len(all_flows[f])
        all_flow_size_pkt.append(size)
        for p in all_flows[f]:
            f_bytes += p.length
        all_flow_size_byte.append(f_bytes)
    
    for f in tcp_flows:
        f_bytes = 0
        f_overhead = 0
        size = len(tcp_flows[f])
        tcp_flow_size_pkt.append(size)
        for p in tcp_flows[f]:
            f_bytes += p.length
            f_overhead += 18 + 20 #+ tcp_hdr
        tcp_flow_size_byte.append(f_bytes)
        if f_bytes == 0:
            f_bytes = 9999
        tcp_flow_size_overhead.append(f_overhead/float(f_bytes))
    
    for f in udp_flows:
        f_bytes = 0
        size = len(udp_flows[f])
        udp_flow_size_pkt.append(size)
        for p in udp_flows[f]:
            f_bytes += p.length
        udp_flow_size_byte.append(f_bytes)

    # -- Inter-packet Arrival time
    for f in all_flows:
        for i in range(len(all_flows[f])-1):
            all_flow_time.append(time_diff(all_flows[f][i].timestamp, all_flows[f][i+1].timestamp))

    for f in tcp_flows:
        for i in range(len(tcp_flows[f])-1):
            tcp_flow_time.append(time_diff(tcp_flows[f][i].timestamp, tcp_flows[f][i+1].timestamp))

    for f in udp_flows:
        for i in range(len(udp_flows[f])-1):
            udp_flow_time.append(time_diff(udp_flows[f][i].timestamp, udp_flows[f][i+1].timestamp))

    # -- TCP State
    for f in tcp_flows:
        size = len(tcp_flows[f])
        last_pkt = tcp_flows[f][size-1]
        tcp = dpkt.ethernet.Ethernet(last_pkt.buf).data.data
        
        if (tcp.flags & dpkt.tcp.TH_SYN) != 0:
            f.state = 'Request'
        elif (tcp.flags & dpkt.tcp.TH_RST) != 0:
            f.state = 'Reset'
        elif (tcp.flags & dpkt.tcp.TH_FIN) != 0 and (tcp.flags & dpkt.tcp.TH_ACK) != 0:
            f.state = 'Finished'
        elif time_diff(tcp_flows[f][0].timestamp, tcp_flows[f][size-1].timestamp) <= 300:
            f.state = 'Ongoing'
        elif time_diff(tcp_flows[f][0].timestamp, tcp_flows[f][size-1].timestamp) > 300 \
            and (tcp.flags & dpkt.tcp.TH_RST) == 0 and (tcp.flags & dpkt.tcp.TH_FIN) == 0:
            f.state = 'Failed'

    show_cdf_graphs()
    

# === CDF Plot Graphs ===

def show_cdf_graphs():
    # Flow Duration - All Flow
    all_flow_dur_data = np.sort(all_flow_dur)
    yvals_all =  np.arange(len(all_flow_dur_data))/float(len(all_flow_dur_data)-1)
    plt.ylabel('Cumulivitive Probability')
    plt.xlabel('All flow duration')
    plt.title("CDF of All Flow - Flow Duration")
    plt.plot(all_flow_dur_data, yvals_all)
    plt.show()
    # Flow Duration - TCP Flow
    tcp_flow_dur_data = np.sort(tcp_flow_dur)
    yvals_tcp =  np.arange(len(tcp_flow_dur_data))/float(len(tcp_flow_dur_data)-1)
    plt.ylabel('Cumulivitive Probability')
    plt.xlabel('TCP flow duration')
    plt.title("CDF of TCP Flow - Flow Duration")
    plt.plot(tcp_flow_dur_data, yvals_tcp)
    plt.show()
    # Flow Duration - UDP Flow
    udp_flow_dur_data = np.sort(udp_flow_dur)
    yvals_udp =  np.arange(len(udp_flow_dur_data))/float(len(udp_flow_dur_data)-1)
    plt.ylabel('Cumulivitive Probability')
    plt.xlabel('UDP flow duration')
    plt.title("CDF of UDP Flow - Flow Duration")
    plt.plot(udp_flow_dur_data, yvals_udp)
    plt.show()

    # Flow Size: Packet - All Flow
    all_flow_size_data = np.sort(all_flow_size_pkt)
    yvals_all =  np.arange(len(all_flow_size_data))/float(len(all_flow_size_data)-1)
    plt.ylabel('Cumulivitive Probability')
    plt.xlabel('All flow size - packets')
    plt.title("CDF of All Flow - Flow Size: Packets")
    plt.plot(all_flow_size_data, yvals_all)
    plt.show()
    # Flow Size: Packet - TCP Flow
    tcp_flow_size_data = np.sort(tcp_flow_size_pkt)
    yvals_tcp =  np.arange(len(tcp_flow_size_data))/float(len(tcp_flow_size_data)-1)
    plt.ylabel('Cumulivitive Probability')
    plt.xlabel('TCP flow size - packets')
    plt.title("CDF of TCP Flow - Flow Size: Packets")
    plt.plot(tcp_flow_size_data, yvals_tcp)
    plt.show()
    # Flow Size: Packet - UDP Flow
    udp_flow_size_data = np.sort(udp_flow_size_pkt)
    yvals_udp =  np.arange(len(udp_flow_size_data))/float(len(udp_flow_size_data)-1)
    plt.ylabel('Cumulivitive Probability')
    plt.xlabel('UDP flow size - packets')
    plt.title("CDF of UDP Flow - Flow Size: Packets")
    plt.plot(udp_flow_size_data, yvals_udp)
    plt.show()

    # Flow Size: Bytes - All Flow
    all_flow_sizeb_data = np.sort(all_flow_size_byte)
    yvals_all =  np.arange(len(all_flow_sizeb_data))/float(len(all_flow_sizeb_data)-1)
    plt.ylabel('Cumulivitive Probability')
    plt.xlabel('All flow size - bytes')
    plt.title("CDF of All Flow - Flow Size: Bytes")
    plt.plot(all_flow_sizeb_data, yvals_all)
    plt.show()
    # Flow Size: Bytes - TCP Flow
    tcp_flow_sizeb_data = np.sort(tcp_flow_size_byte)
    yvals_tcp =  np.arange(len(tcp_flow_sizeb_data))/float(len(tcp_flow_sizeb_data)-1)
    plt.ylabel('Cumulivitive Probability')
    plt.xlabel('TCP flow size - bytes')
    plt.title("CDF of TCP Flow - Flow Size: Bytes")
    plt.plot(tcp_flow_sizeb_data, yvals_tcp)
    plt.show()
    # Flow Size: Bytes - UDP Flow
    udp_flow_sizeb_data = np.sort(udp_flow_size_byte)
    yvals_udp =  np.arange(len(udp_flow_sizeb_data))/float(len(udp_flow_sizeb_data)-1)
    plt.ylabel('Cumulivitive Probability')
    plt.xlabel('UDP flow size - bytes')
    plt.title("CDF of UDP Flow - Flow Size: Bytes")
    plt.plot(udp_flow_sizeb_data, yvals_udp)
    plt.show()

    # TCP Flow Size: Overhead ratio 
    tcp_flow_overhead_data = np.sort(tcp_flow_size_overhead)
    yvals_tcp =  np.arange(len(tcp_flow_overhead_data))/float(len(tcp_flow_overhead_data)-1)
    plt.ylabel('Cumulivitive Probability')
    plt.xlabel('TCP flow size - overhead ratio')
    plt.title("CDF of TCP Flow - Overhead Ratio")
    plt.plot(tcp_flow_overhead_data, yvals_tcp)
    plt.show()

    # Flow Inter-Packet Arrival Time - All Flow
    all_flow_time_data = np.sort(all_flow_time)
    yvals_all =  np.arange(len(all_flow_time_data))/float(len(all_flow_time_data)-1)
    plt.ylabel('Cumulivitive Probability')
    plt.xlabel('All flow time')
    plt.title("CDF of All Flow - Inter-Packet Arrival Time")
    plt.plot(all_flow_time_data, yvals_all)
    plt.show()
    # Flow Inter-Packet Arrival Time - TCP Flow
    tcp_flow_time_data = np.sort(tcp_flow_time)
    yvals_all =  np.arange(len(tcp_flow_time_data))/float(len(tcp_flow_time_data)-1)
    plt.ylabel('Cumulivitive Probability')
    plt.xlabel('TCP flow time')
    plt.title("CDF of TCP Flow - Inter-Packet Arrival Time")
    plt.plot(tcp_flow_time_data, yvals_all)
    plt.show()
    # Flow Inter-Packet Arrival Time - UDP Flow
    udp_flow_time_data = np.sort(udp_flow_time)
    yvals_all =  np.arange(len(udp_flow_time_data))/float(len(udp_flow_time_data)-1)
    plt.ylabel('Cumulivitive Probability')
    plt.xlabel('UDP flow time')
    plt.title("CDF of UDP Flow - Inter-Packet Arrival Time")
    plt.plot(udp_flow_time_data, yvals_all)
    plt.show()

def time_diff(timestamp1, timestamp2):
    ts1 = datetime.datetime.utcfromtimestamp(timestamp1)
    ts2 = datetime.datetime.utcfromtimestamp(timestamp2)
    return (ts2 - ts1).total_seconds()

# -- RTT - Three top 3 TCP flows
def top_flows():
    top_flows1 = []
    top_flows2 = []
    top_flows3 = []
    
    sorted_tcp_flow_pkt = sorted(tcp_flows, key=lambda k: len(tcp_flows[k]), reverse = True)
    top_flows1.append((sorted_tcp_flow_pkt[0], tcp_flows[sorted_tcp_flow_pkt[0]]))
    top_flows1.append((sorted_tcp_flow_pkt[1], tcp_flows[sorted_tcp_flow_pkt[1]]))
    top_flows1.append((sorted_tcp_flow_pkt[2], tcp_flows[sorted_tcp_flow_pkt[2]]))

    for f in tcp_flows:
        f.total_bytes = 0
        f.duration = 0
        for p in tcp_flows[f]:
            f.total_bytes += p.length
            size = len(tcp_flows[f])
            f.duration += time_diff(tcp_flows[f][0].timestamp, tcp_flows[f][size-1].timestamp)

    sorted_tcp_flow_byte = sorted(tcp_flows, key=operator.attrgetter('total_bytes'), reverse=True)
    top_flows2.append((sorted_tcp_flow_byte[0], tcp_flows[sorted_tcp_flow_byte[0]]))
    top_flows2.append((sorted_tcp_flow_byte[1], tcp_flows[sorted_tcp_flow_byte[1]]))
    top_flows2.append((sorted_tcp_flow_byte[2], tcp_flows[sorted_tcp_flow_byte[2]]))

    sorted_tcp_flow_dur = sorted(tcp_flows, key=operator.attrgetter('duration'), reverse=True)
    top_flows3.append((sorted_tcp_flow_dur[0], tcp_flows[sorted_tcp_flow_dur[0]]))
    top_flows3.append((sorted_tcp_flow_dur[1], tcp_flows[sorted_tcp_flow_dur[1]]))
    top_flows3.append((sorted_tcp_flow_dur[2], tcp_flows[sorted_tcp_flow_dur[2]]))

    return [top_flows1, top_flows2, top_flows3]

# -- RTT - Host pairs
def all_host_pairs(pkt, ip):
    flow = Flow(ip.src, ip.dst, ip.data.sport, ip.data.dport, ip.p)
    if flow not in tcp_host_pairs:
        tcp_host_pairs[flow] = [pkt]
    else:
        x = len(tcp_host_pairs[flow]) - 1
        if x < 0:
            tcp_host_pairs[flow].append(pkt)
        else:
            if time_diff(tcp_host_pairs[flow][x].timestamp, pkt.timestamp) <= 5400:
                tcp_host_pairs[flow].append(pkt)

def host_pairs():
    top_3_pairs = []
    sorted_tcp_flow_pkt = sorted(tcp_host_pairs, key=lambda k: len(tcp_host_pairs[k]), reverse = True)
    top_3_pairs.append((sorted_tcp_flow_pkt[0], tcp_host_pairs[sorted_tcp_flow_pkt[0]]))
    top_3_pairs.append((sorted_tcp_flow_pkt[2], tcp_host_pairs[sorted_tcp_flow_pkt[2]]))
    top_3_pairs.append((sorted_tcp_flow_pkt[4], tcp_host_pairs[sorted_tcp_flow_pkt[4]]))

    for flow in top_3_pairs:
        print "tcp pkt: ", inet_to_str(flow[0].src_ip), inet_to_str(flow[0].dst_ip), flow[0].src_port, flow[0].dst_port

def test():
    """Open up a test pcap file and print out the packets"""
    with open('univ1_pt8.pcap', 'rb') as f: #univ1_trace/univ1_pt8
        pcap = Reader(f)
        print_packets(pcap)
        # top_flows()
        host_pairs()


if __name__ == '__main__':
    test()