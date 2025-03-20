import random
import socket

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind(('', 7070))

print(socket.getservbyport(5353, 'udp'))

while True:
    rand = 4 # random.randint(0, 10)
    message, address = server_socket.recvfrom(1024)
    print(message, address)
    message = message.upper()
    # if rand >= 4:
    #     server_socket.sendto(message, address)
    #     server_socket.sendto(message, address)