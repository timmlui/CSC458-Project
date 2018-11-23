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

ipv6_length_list = []
ipv4_length_list = []

with open('./trace8.csv', mode='r') as csv_file:
    csv_reader = csv.DictReader(csv_file)
    line_count = 0


    for row in csv_reader:
        if line_count == 0:
            print(f'Column names are {", ".join(row)}')
            line_count += 1

        if row["Protocol"] == "TCP" :
          tcp_total += int(row["Length"])
        if row["Protocol"] == "UDP" :
          udp_total += int(row["Length"])
        if row["Protocol"] == "IPv4" :
          ipv4_length_list.append(int(row["Length"]))
          ipv4_total += int(row["Length"])

        if row["Protocol"] == "ICMPv6" :
          ipv6_length_list.append(int(row["Length"]))
          ipv6_total += int(row["Length"])
        if row["Protocol"] == "DHCPv6" :
          ipv6_length_list.append(int(row["Length"]))
          ipv6_total += int(row["Length"])

        if row["Protocol"] == "ARP" :
          arp_total += int(row["Length"])

        # if row["Protocol"] == "ETH" :
        #   eth_total += int(row["Length"])

        if row["Protocol"] == "ICMP" :
          icmp_total += int(row["Length"])
        

        eth_total += int(row["Length"])
        
        
        
        # print(f'Source : {row["Source"]} Dest : {row["Destination"]} Length : {row["Length"]}.')

        line_count += 1
    print(f'Processed {line_count} lines.\n TCP total : {tcp_total}\n')
    print(f'UDP total : {udp_total}\n IPV4 total : {ipv4_total}\n')
    print(f'IPV6 total : {ipv6_total}\n ICMP total : {icmp_total}\n')
    print(f'Ethernet total : {eth_total}\n ARP total: {arp_total}\n')
    print(f'IPv6 List : {ipv4_length_list}')

sorted_data = np.sort(ipv4_length_list)
yvals=np.arange(len(sorted_data))/float(len(sorted_data)-1)
plt.plot(sorted_data,yvals)
plt.show()

# for q in [5, 25, 50, 75, 90, 100]:
#   print ("{}%% percentile: {}".format (q, np.percentile(ipv4_length, q)))
