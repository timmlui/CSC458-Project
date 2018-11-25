

class Packet:

    def __init__(self, timestamp, buf, length):
        self.timestamp = timestamp
        self.buf = buf
        self.length = length

    def __str__(self):
        return str(self.__dict__)

    def __eq__(self, other): 
        # to support both direction flow
        return self.__dict__ == other.__dict__

    # def __hash__(self):
    #     return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.p))