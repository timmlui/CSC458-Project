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

        # Print out the timestamp in UTC
        # print('Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp)))

        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        
        print('Ethernet Frame: ', eth.data, mac_addr(eth.src), mac_addr(eth.dst), eth.type)
        print("len(eth): %d | len(eth.data): %d | hdr_len: %d" % (len(eth), len(eth.data), hdr_len))

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
        if not isinstance(ip.data, str):
            print "Transport Layer: ", ip.p, len(ip.data.data), len(ip.data)
            # print "ip.data.data.len: ", ip.data.payload
        else:
            print "Transport Lyaer2: ", ip.p, len(ip.data)

        # print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % \
        #     (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset))


def test():
    """Open up a test pcap file and print out the packets"""
    with open('tests/test2.pcap1', 'rb') as f:
        pcap = Reader(f)
        print_packets(pcap)


if __name__ == '__main__':
    test()