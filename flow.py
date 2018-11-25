

class Flow:

    def __init__(self, src_ip, dst_ip, src_port, dst_port, p):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.p = p

    def __str__(self):
        return str(self.__dict__)

    def __eq__(self, other): 
        # to support both direction flow
        return \
            ((self.src_ip == other.src_ip and self.src_port == other.src_port and \
            self.dst_ip == other.dst_ip and self.dst_port == other.dst_port) or \
            (self.src_ip == other.dst_ip and self.src_port == other.dst_port and \
            self.dst_ip == other.src_ip and self.dst_port == other.src_port))

    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.p))