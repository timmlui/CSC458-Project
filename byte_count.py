import csv
import numpy as np   
import matplotlib.pyplot as plt


# Initialize variables globally so it can be used for per-packet as well as CDF plotting
eth_total = 0
arp_total = 0
ipv4_total = 0
ipv6_total = 0
icmp_total = 0
tcp_total = 0
udp_total = 0
other_total = 0

# List of protocols
protocol_list = ["TCP", "UDP", "IPv4", "ICMPv6", "DHCPv6"]

# Keep track of headers

# Keep tract of the length
ip_length_list = []
non_ip_length_list = []
tcp_length_list = []
udp_length_list = []
all_length_list = []

with open('./tracefile8.csv', mode='r') as csv_file:
    csv_reader = csv.DictReader(csv_file)
    line_count = 0


    for row in csv_reader:
        # if line_count == 0:
        #     print(f'Column names are {", ".join(row)}')
        #     line_count += 1
        
        eth_total += int(row["Length"])
        all_length_list.append(int(row["Length"]))
        
        if row["Protocol"] == "IPv4" :
            ipv4_total += int(row["Length"])
            ip_length_list.append(int(row["Length"]))
        if row["Protocol"] == "ICMPv6" :
            ipv6_total += int(row["Length"])
            ip_length_list.append(int(row["Length"]))
        if row["Protocol"] == "DHCPv6" :
            ipv6_total += int(row["Length"])
            ip_length_list.append(int(row["Length"]))
        
        if row["Protocol"] == "ICMP" :
            icmp_total += int(row["Length"])
            non_ip_length_list.append(int(row["Length"]))

        if row["Protocol"] == "ARP" :
            arp_total += int(row["Length"])
            non_ip_length_list.append(int(row["Length"]))

        if row["Protocol"] == "TCP" :
            tcp_total += int(row["Length"])
            tcp_length_list.append(int(row["Length"]))
        if row["Protocol"] == "UDP" :
            udp_total += int(row["Length"])
            udp_length_list.append(int(row["Length"]))

        if row["Protocol"] not in protocol_list:
            other_total += int(row["Length"])
            non_ip_length_list.append(int(row["Length"]))

        
        # print(f'Source : {row["Source"]} Dest : {row["Destination"]} Length : {row["Length"]}.')

        line_count += 1

    print("Processed lines: ", line_count)
    print("===== Data Link Layer =====")
    print("Ethernet total bytes: ", eth_total)

    print("===== Network Layer =====")
    print("IPv4 total bytes: ", ipv4_total)
    print("IPv6 total bytes: ", ipv6_total)
    print("ICMP total bytes: ", icmp_total)
    print("ARP total bytes: ", arp_total)

    print("===== Transport Layer =====")
    print("TCP total bytes: ", tcp_total)
    print("UDP total bytes: ", udp_total)

    print("===== Others =====")
    print("Others total bytes: ", other_total)

    #print(f'IPv6 List : {ipv4_length_list}')

ip_data = np.sort(ip_length_list)
yvals_ip =  np.arange(len(ip_data))/float(len(ip_data)-1)
plt.plot(ip_data, yvals_ip)
plt.show()

non_ip_data = np.sort(non_ip_length_list)
yvals_non_ip =  np.arange(len(non_ip_data))/float(len(non_ip_data)-1)
plt.plot(non_ip_data, yvals_non_ip)
plt.show()

tcp_data = np.sort(tcp_length_list)
yvals_tcp =  np.arange(len(tcp_data))/float(len(tcp_data)-1)
plt.plot(tcp_data, yvals_tcp)
plt.show()

udp_data = np.sort(udp_length_list)
yvals_udp =  np.arange(len(udp_data))/float(len(udp_data)-1)
plt.plot(udp_data, yvals_udp)
plt.show()

all_data = np.sort(all_length_list)
yvals_all =  np.arange(len(all_data))/float(len(all_data)-1)
plt.plot(all_data, yvals_all)
plt.show()


# for q in [5, 25, 50, 75, 90, 100]:
#   print ("{}%% percentile: {}".format (q, np.percentile(ip_length_list, q)))
