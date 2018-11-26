

class Flow:

    def __init__(self, src_ip, dst_ip, src_port, dst_port, p):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.p = p
        self.state = None

    def __str__(self):
        return str(self.__dict__)

    def __eq__(self, other): 
        # to support both direction flow
        return \
            ((self.src_ip == other.src_ip and self.dst_ip == other.dst_ip) or \
            (self.src_ip == other.dst_ip and self.dst_ip == other.src_ip)) and \
            self.src_port == other.src_port and self.dst_port == other.dst_port

    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.p))

    def eq2(self, other):
        return ((self.src_ip == other.src_ip and self.dst_ip == other.dst_ip) or \
            (self.src_ip == other.dst_ip and self.dst_ip == other.src_ip))

    @property
    def state(self):
        return self.state

    @state.setter
    def state(self, value):
        self.state = value

    @property
    def total_bytes(self):
        return self.total_bytes

    @total_bytes.setter
    def total_bytes(self, value):
        self.total_bytes = value

    @property
    def duration(self):
        return self.duration

    @duration.setter
    def duration(self, value):
        self.duration = value