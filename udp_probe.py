import os
import socket

from headers import Header, PORT

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
        srvc = "Unknown"

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection_socket:
        try:        
            connection_socket.settimeout(TIMEOUT)
            connection_socket.sendto(message, (host, dport))
            data, _ = connection_socket.recvfrom(PACKET_SIZE)

        except socket.timeout:
            return PORT.OPEN_OR_FILTERED, dport, srvc
        
        return PORT.OPEN, dport, srvc

def icmp_receive(daddr, listen_dict, stop_event):
    '''
    Serves to detect closed ports. Raw socket is listening for all ICMP packets and identifies those have been sent as a response to our UDP packet.
    After that it marks that port as closed.
    '''

    ICMP_UNREACHABLE = 3
    PORT_UNREACHABLE = 3
    TIMEOUT = 2.0
    IS_CLOSED = True

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
                    header.get_icmp_code() == ICMP_UNREACHABLE and
                    header.get_icmp_type() == PORT_UNREACHABLE):   

                    listen_dict[header.get_dport()] = IS_CLOSED

            except socket.timeout:
                pass # keep going until event is set