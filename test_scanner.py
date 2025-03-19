from Header import PORT
from udp_probe import udp_send, icmp_receive
import concurrent.futures
from threading import Event

stop_event = Event()

saddr = ['127.0.0.1'] * 3
# daddr = ['127.0.0.1' ]* 3
daddr = '127.0.0.1'
dports = [x for x in range(6900, 7100)]
scan_dict = dict()
result_dict = dict()
# message = [b'test'] * 3
message = b'test'
print(saddr, daddr, dports, message)

with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
    results = []
    listen_task = executor.submit(icmp_receive, daddr, scan_dict, stop_event)
    # send_tasks = executor.map(udp_send, daddr, dports, message)
    for dport in dports:
        results.append(executor.submit(udp_send, daddr, dport, message))
    
    for future in concurrent.futures.as_completed(results):
    # for result in send_tasks:
        status, port = future.result()
        print(status, port)
        if (scan_dict.get(port) == True):
            result_dict[port] = PORT.CLOSED
        else:
            result_dict[port] = status

    stop_event.set()
    print(scan_dict)
    for key in sorted(result_dict.keys()):
        print(key, result_dict[key])