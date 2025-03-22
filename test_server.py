import random
import socket
import concurrent.futures

MAX_WORKERS = 10

def run_server(port):
     
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as socket_listener:
        socket_listener.bind(('127.0.0.1', port))
        print("Listening on port ", port)
        random.seed()
        rand = random.randint(0, 10)
        
        while True:
            message, address = socket_listener.recvfrom(1024)
            print(message, address)
            message = message.upper()
            if rand >= 7:
                socket_listener.sendto(message, address)

with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
    try:
        tasks = executor.map(run_server, [port for port in range(32501, 32501 + MAX_WORKERS)])
    except Exception as err:
        print(err)