
SRTT = 0
RTTVAR = 0
RTO = 1
K = 4


def first_RTT(R, G) :
  """
    When the first RTT measurement R is made, make such modifications.
  """
  SRTT =  R
  RTTVAR = R/2
  RTO = SRTT + max (G, K * RTTVAR)
  print("RTO :", RTO, " SRTT :", SRTT, " RTTVAR:", RTTVAR)


if __name__ == "__main__" :
  first_RTT(.5, 1)