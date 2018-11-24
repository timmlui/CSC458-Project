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
  global RTTVAR
  global SRTT
  RTTVAR = (1 - beta) * RTTVAR + beta * abs(SRTT - R1)
  SRTT = (1 - alpha) * SRTT + alpha * R1
  global RTO
  RTO = SRTT + max(G, K* RTTVAR)



if __name__ == "__main__" :
  first_RTT(.005)
  print("RTO :", RTO, " SRTT :", SRTT, " RTTVAR:", RTTVAR)
  subsequent_RTT(.001)
  print("Sub RTO :", RTO, " SRTT :", SRTT, " RTTVAR:", RTTVAR)

