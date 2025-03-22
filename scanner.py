import concurrent.futures
from threading import Event

from headers import PORT
from probe import udp_send, icmp_receive

def udp_scan(host, dports):

    stop_event = Event()
    message = b'test message'
    listen_dict = dict()
    result_dict = dict()

    port_count = len(dports)

    print("-"*30)
    print("Starting scan")
    print(f"Scanned 0/{port_count} ports", end="\r", flush=True)

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        results = []

        # start ICMP listening task
        listen_task = executor.submit(icmp_receive, host, listen_dict, stop_event)
        
        # start UDP sender tasks
        for dport in dports:
            results.append(executor.submit(udp_send, host, dport, message))
        
        # scanned ports counter
        scanned = 0
        
        # collecting finished futures
        for future in concurrent.futures.as_completed(results):
            scanned += 1
            if scanned % 10 == 0:
                print(f"Scanned {scanned}/{port_count} ports", end="\r", flush=True)
            status, port, srvc = future.result()

            if (listen_dict.get(port) == True):
                result_dict[port] = [PORT.CLOSED, "None"]
            else:
                result_dict[port] = [status, srvc]

        # set event to stop ICMP listener
        stop_event.set()

        # result output
        print(f"UDP scan is over          \n")
        output = "\n".join(f"Scanned port: {key:<5}  Status: {result_dict[key][0]:21}  Plausible service: {result_dict[key][1]}"
                           for key in result_dict.keys() if result_dict[key][0] != PORT.CLOSED)
        
        return output
