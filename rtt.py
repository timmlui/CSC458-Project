SRTT = 0
RTTVAR = 0
RTO = 1
K = 4
alpha = 1/8
beta = 1/4
G = 1


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

# def manage_RTO_timer() :
#   """
#   An implementation MUST manage the retransmission timer(s) in such a
#    way that a segment is never retransmitted too early, i.e., less than
#    one RTO after the previous transmission of that segment.
#   """




if __name__ == "__main__" :
  first_RTT(0.005)
  print("RTO :", RTO, " SRTT :", SRTT, " RTTVAR:", RTTVAR)
  subsequent_RTT(.001)
  print("Sub RTO :", RTO, " SRTT :", SRTT, " RTTVAR:", RTTVAR)

