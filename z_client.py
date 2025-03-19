import time
import socket

for pings in range(10):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # client_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    # client_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    # client_socket.setsockopt( socket.IPPROTO_UDP, socket.CAN_ERR_FLAG, 1 )
    client_socket.settimeout(2.0)
    message = b'test'
    addr = ("127.0.0.1", 6969)

    start = time.time()
    client_socket.sendto(message, addr)
    # res = client_socket.connect_ex(("127.0.0.1", 6969))
    # print(res)
    try:
        code = client_socket.connect_ex(addr)
        print(code)

        # data = client_socket.recv(1024)
        data, server = client_socket.recvfrom(65535)
        end = time.time()
        elapsed = end - start
        print(f'{data} {pings} {elapsed}')
    except ConnectionResetError:
        print('UNREACHABLE')          
    except socket.timeout:
        print('REQUEST TIMED OUT')
      


# from socket import *
# import sys, time
# from datetime import datetime

# host = '127.0.0.1"'
# ports = [12000]

# def scan_host(host, port, r_code = 1) : 
#     try : 
#         s = socket(AF_INET, SOCK_DGRAM)
#         code = s.connect_ex((host, port))
#         if code == 0 : 
#             r_code = code
#         s.close()
#         print(code)
#     except Exception: 
#         pass
#     return r_code

# # try : 
# #     host = raw_input("[*] Enter Target Host Address :  ")
# # except KeyBoardInterrupt : 
# #     sys.exit(1)

# # hostip = gethostbyname(host)

# for port in ports : 
#     try : 
#         response = scan_host(host, port)
#         if response == 0 : 
#             print("[*] Port %d: Open" % (port))
#     except Exception: 
#         pass