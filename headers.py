import struct
import socket
import random

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
        # pseudo_ip_header = struct.unpack('!BBHHHBBH4s4s', byte_str[28:48])

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

# Not used as of now. Was implemented for manual packet generation during half-handshake
class Packet:

    random.seed()
    seq_no = 0
    id = 0

    def __init__(self, src_ip, dest_ip, dest_port, sport):

        ############
        # IP segment
        self.version = 0x4
        self.ihl = 0x5
        self.type_of_service = 0x0
        self.total_length = 0x28
        Packet.id = random.randint(1,65535) 
        self.identification = Packet.id
        self.flags = 0x0
        self.fragment_offset = 0x0
        self.ttl = 0x40
        self.protocol = 0x6
        self.header_checksum = 0x0
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.src_addr = socket.inet_aton(src_ip)
        self.dest_addr = socket.inet_aton(dest_ip)
        self.v_ihl = (self.version << 4) + self.ihl
        self.f_fo = (self.flags << 13) + self.fragment_offset
        
        #############
        # TCP segment
        self.src_port = sport
        self.dest_port = dest_port   
        Packet.seq_no = random.randint(1,4294967296)   
        self.seq_no = Packet.seq_no
        self.ack_no = 0x0
        self.data_offset = 0x5
        self.reserved = 0x0
        self.ns, self.cwr, self.ece, self.urg, self.ack, self.psh, self.rst, self.syn, self.fin = 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0
        self.window_size = 0x7110
        self.checksum = 0x0
        self.urg_pointer = 0x0
        self.data_offset_res_flags = (self.data_offset << 12) + (self.reserved << 9) + (self.ns << 8) + (self.cwr << 7) + (self.ece << 6) + (self.urg << 5) + (self.ack << 4) + (self.psh << 3) + (self.rst << 2) + (self.syn << 1) + self.fin
        
        ########
        # packet
        self.tcp_header = b""
        self.ip_header = b""
        self.packet = b""
       
       
    def calc_checksum(self, msg):
        s = 0
        for i in range(0, len(msg), 2):
            w = (msg[i] << 8) + msg[i+1] 
            s = s + w
        # s = 0x119cc
        s = (s >> 16) + (s & 0xffff)
        # s = 0x19cd
        s = ~s & 0xffff
        # s = 0xe632
        return s

        
    def generate_tmp_ip_header(self):
        tmp_ip_header = struct.pack("!BBHHHBBH4s4s", self.v_ihl, self.type_of_service, self.total_length,
                                          self.identification, self.f_fo,
                                          self.ttl, self.protocol, self.header_checksum,
                                          self.src_addr,
                                          self.dest_addr)
        return tmp_ip_header


    def generate_tmp_tcp_header(self):
        tmp_tcp_header = struct.pack("!HHLLHHHH", self.src_port, self.dest_port,
                                       self.seq_no,
                                       self.ack_no,
                                       self.data_offset_res_flags, self.window_size,
                                       self.checksum, self.urg_pointer)
        return tmp_tcp_header


    def generate_packet(self):
        # IP header + checksum
        final_ip_header = struct.pack("!BBHHHBBH4s4s", self.v_ihl, self.type_of_service, self.total_length,
                                                self.identification, self.f_fo,
                                                self.ttl, self.protocol, self.calc_checksum(self.generate_tmp_ip_header()),
                                                self.src_addr,
                                                self.dest_addr)
        # TCP header + checksum
        tmp_tcp_header = self.generate_tmp_tcp_header()
        pseudo_header = struct.pack("!4s4sBBH", self.src_addr, self.dest_addr, self.checksum, self.protocol, len(tmp_tcp_header))
        psh = pseudo_header + tmp_tcp_header
        final_tcp_header = struct.pack("!HHLLHHHH", self.src_port, self.dest_port,
                                             self.seq_no,
                                             self.ack_no,
                                             self.data_offset_res_flags, self.window_size,
                                             self.calc_checksum(psh), self.urg_pointer)
        
        self.ip_header = final_ip_header
        self.tcp_header = final_tcp_header
        self.packet = final_ip_header + final_tcp_header
    
    def get_packet(self):
        return self.packet