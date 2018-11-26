
import all_flows
import dpkt
import socket

SRTT = 0
RTTVAR = 0
RTO = 1
K = 4
alpha = 1/8
beta = 1/4
G = 1

top_flows1 = []
top_flows2 = []
top_flows3 = []

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

def first_RTT(R) :
  """
    When the first RTT measurement R is made, make such modifications.
  """
  global SRTT 
  SRTT =  R
  global RTTVAR 
  RTTVAR = R/2
  global RTO 
  RTO = SRTT + max (G, K * RTTVAR)
  print("RTO :", RTO, " SRTT :", SRTT, " RTTVAR:", RTTVAR)


def subsequent_RTT(R1) :
  """
   The value of SRTT used in the update to RTTVAR is its value
         before updating SRTT itself using the second assignment.  That
         is, updating RTTVAR and SRTT MUST be computed in the above
         order.

         The above SHOULD be computed using alpha=1/8 and beta=1/4 (as
         suggested in [JK88]).

         After the computation, a host MUST update
         RTO 
  """
  global RTTVAR
  global SRTT
  RTTVAR = (1 - beta) * RTTVAR + beta * abs(SRTT - R1)
  SRTT = (1 - alpha) * SRTT + alpha * R1
  global RTO
  RTO = SRTT + max(G, K* RTTVAR)
  if RTO < 1 :
    RTO = 1

# def write_pcap():
#     # Open a file to store our capture
#     f = open("this.pcap", "a+")
#     writer = dpkt.pcap.Writer(f)
 
#     while True:
#         dpkt.pcap.Writer.writepkt(pkt, ts)
         
#         # Start analyzing our packet
#         eth_packet = dpkt.ethernet.Ethernet(packet)
 
#         # Print packets to screen
#         print repr(eth_packet)
         
#         writer.writepkt(packet)
         
#         f.flush()
         
#     f.close()




if __name__ == "__main__" :
  first_RTT(0.005)
  print("RTO :", RTO, " SRTT :", SRTT, " RTTVAR:", RTTVAR)
  subsequent_RTT(.001)
  print("Sub RTO :", RTO, " SRTT :", SRTT, " RTTVAR:", RTTVAR)

  all_flows.test()
  top_flows1 = all_flows.top_flows()[0]
  top_flows2 = all_flows.top_flows()[1]
  top_flows3 = all_flows.top_flows()[2]

  for flow in top_flows1:
    print "tcp pkt: ", inet_to_str(flow[0].src_ip), inet_to_str(flow[0].dst_ip), flow[0].src_port, flow[0].dst_port

  for flow in top_flows2:
    print "tcp total bytes: ", inet_to_str(flow[0].src_ip), inet_to_str(flow[0].dst_ip), flow[0].src_port, flow[0].dst_port

  for flow in top_flows3:
    print "tcp duration: ", inet_to_str(flow[0].src_ip), inet_to_str(flow[0].dst_ip), flow[0].src_port, flow[0].dst_port


