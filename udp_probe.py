import time
import os
import socket

from Header import Header, PORT


def udp_send(host, dport, message):

    try:        
        connection_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        connection_socket.settimeout(2.0)
        connection_socket.sendto(message, (host, dport))
        data, _ = connection_socket.recvfrom(1024)

    except socket.timeout:
        return PORT.OPEN_OR_FILTERED, dport

    return PORT.OPEN, dport

def icmp_receive(daddr, scan_dict, stop_event):

    if os.name == "nt":
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP
    
    socket_listener = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    socket_listener.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    socket_listener.settimeout(5.0)

    if os.name == "nt": 
        socket_listener.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    print("icmp has begun")

    while not stop_event.isSet():

        try:

            data, _ = socket_listener.recvfrom(256)
            header = Header(data)
            # print(header.get_saddr(), daddr)
            # print(header.get_protocol())
            # print(header.get_icmp_code())
            # print(header.get_icmp_type())
            # print(header.get_sport(), header.get_dport())
            if (header.get_protocol() == 1 and
                header.get_saddr() == daddr and
                header.get_icmp_code() == 3 and
                header.get_icmp_type() == 3):
                
                scan_dict[header.get_dport()] = True

        except socket.timeout:
            pass