import struct
import socket
import enum

class PORT(enum.Enum):

    CLOSED = 1
    OPEN_OR_FILTERED = 2
    OPEN = 3

class Header:

    def __init__(self, byte_str):

        if len(byte_str) < 56:
            self.ip_header = None
            return
        
        # - B: Version + IHL (8 bits)
        # - B: Type of Service (8 bits)
        # - H: Total Length (16 bits)
        # - H: Identification (16 bits)
        # - H: Flags + Fragment Offset (16 bits)
        # - B: Time to Live (8 bits)
        # - B: Protocol (8 bits)
        # - H: Header Checksum (16 bits)
        # - 4s: Source (IP) Address (32 bits as-is)
        # - 4s: Dest (IP) Address (32 bits as-is)
        self.ip_header = struct.unpack('!BBHHHBBH4s4s', byte_str[:20])

        # - B: Type (3 for ICMP destination unreachable)
        # - B: Code (3 for port unreachable)
        # - H: Header Checksum (16 bits)
        # - 4s: Padding
        self.icmp_header = struct.unpack('!BBH4s', byte_str[20:28])

        # - Pseudo IP header - skipping
        # self.pseudo_ip_header = struct.unpack('!BBHHHBBH4s4s', byte_str[28:48])

        # - H: Source port (16 bits)
        # - H: Dest port (16 bits)
        # - H: Length (16 bits)
        # - H: Checksum (16 bits)
        self.pseudo_udp_header = struct.unpack('!HHHH', byte_str[48:56])

    def __repr__(self):
        return str(f"IP header: {self.ip_header}\n" +
                    f"ICMP header: {self.icmp_header}\n" +
                    f"Pseudo UDP header: {self.pseudo_udp_header}\n")

    def get_protocol(self):
        return self.ip_header[6]
    
    def get_saddr(self):
        return socket.inet_ntoa(self.ip_header[8])
    
    def get_daddr(self):
        return socket.inet_ntoa(self.ip_header[9])
    
    def get_sport(self):
        return self.pseudo_udp_header[0]
    
    def get_dport(self):
        return self.pseudo_udp_header[1]

    def get_icmp_type(self):
        return self.icmp_header[0]

    def get_icmp_code(self):
        return self.icmp_header[1] 