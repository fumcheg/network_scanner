import os
import socket
import time
import enum
import binascii

from headers import Header, Packet


class PORT(enum.Enum):

    CLOSED = 1
    OPEN_OR_FILTERED = 2
    OPEN = 3
    ADMIN_FILTERED = 4


def get_source_ip(dest_ip):
    '''
    Returns source IP by provided dest IP.
    '''    

    temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    temp_socket.settimeout(0.5)
    try:
        temp_socket.connect((dest_ip, 6969))
        source_ip = temp_socket.getsockname()[0]
    except socket.error as err:
        raise Exception(f"Failed to resolve source IP by provided dest IP:{dest_ip}! [error: {err}]")
    finally:
        temp_socket.close()
    return source_ip

def udp_send(host, dport, message):
    '''
    Sends UDP packet to host:dport.
    If it gets respose (which is unlikly since the packet is not any service-specific), then dport is open.
    If it throws socket.timeout, then port is probably open.
    Returns dport status, dport number, assumed service
    '''

    TIMEOUT = 1.0
    PACKET_SIZE = 1024

    try:
        srvc = socket.getservbyport(dport, 'udp')
    except:
        srvc = "unknown"

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection_socket:
        try:        
            connection_socket.settimeout(TIMEOUT)
            connection_socket.sendto(message, (host, dport))
            data, _ = connection_socket.recvfrom(PACKET_SIZE)
            
        except socket.timeout:
            return PORT.OPEN_OR_FILTERED, dport, srvc
        
        return PORT.OPEN, dport, srvc
    
def tcp_send(host, dport, source_ip):
    '''
    Sends TCP packet to host:dport.
    Uses handshake to detect open ports.
    Returns dport status, dport number, assumed service
    '''

    TIMEOUT = 1.0
    PACKET_SIZE = 1024

    try:
        srvc = socket.getservbyport(dport, 'tcp')
    except:
        srvc = "unknown"

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection_socket:
        try:        
            connection_socket.settimeout(TIMEOUT)
            connection_socket.connect((host, dport))

        except socket.error as err:
            return PORT.CLOSED, dport, srvc
        
        return PORT.OPEN, dport, srvc    
    
    # Half-handshake is NOT EMPLEMENTED - isn't worth it. It works, but not quet correct.
    # with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as connection_socket:
    #     try:   
    #         connection_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    #         connection_socket.settimeout(TIMEOUT)
    #         packet = Packet(source_ip, host, dport, 0x1B39)
    #         packet.generate_packet()
    #         connection_socket.sendto(packet.get_packet(), (host, 0))
            
    #         data, _ = connection_socket.recvfrom(PACKET_SIZE)
    #         response = binascii.hexlify(data)[65:68]

    #         if (response != b"012"):
    #             return PORT.CLOSED, dport, response

    #     except socket.error as err:
    #         return PORT.CLOSED, dport, srvc
        
    #     return PORT.OPEN, dport, srvc       

def icmp_receive(daddr, listen_dict, stop_event):
    '''
    Serves to detect closed ports. Raw socket is listening for all ICMP packets and identifies those have been sent as a response to our UDP packet.
    After that it marks those ports as closed.
    '''

    ICMP_UNREACHABLE = 3
    PORT_UNREACHABLE = 3
    PORT_ADMIN_FILTERED = 13
    TIMEOUT = 2.0
    
    if os.name == "nt":
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP
    
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol) as socket_listener:
        socket_listener.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        socket_listener.settimeout(TIMEOUT)

        if os.name == "nt": 
            socket_listener.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        while not stop_event.isSet():
            
            try:
                data, _ = socket_listener.recvfrom(1024)
                header = Header(data)

                if (header.get_protocol() == 1 and
                    header.get_saddr() == daddr and
                    header.get_icmp_type() == ICMP_UNREACHABLE):
                    if (header.get_icmp_code() == PORT_UNREACHABLE):   
                        listen_dict[header.get_dport()] = PORT.CLOSED
                    elif(header.get_icmp_code() == PORT_ADMIN_FILTERED):
                        listen_dict[header.get_dport()] = PORT.ADMIN_FILTERED

            except socket.timeout:
                pass # keep going until event is set