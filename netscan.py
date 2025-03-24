"""
Use example:
python3 netscan.py sweep -i 192.168.1.1 -n 10 --outfile
python3 netscan.py scan -i 192.168.1.1 --proto tcp -p 200-300


TODO: add typing
TODO: add exceptions handling for ThreadPoolExecutor
TODO: re-design sweeper with sockets
TODO: re-design udp tcp scan as SYN-scan instead of full handshake scan


"""

import time
import argparse
import concurrent.futures
from threading import Event

from probe import get_source_ip, udp_send, tcp_send, icmp_receive, PORT
from sweeper import sweep


class ParserError(Exception):
    pass

class FileWriteError(Exception):
    pass

class InvalidArgsExc(Exception):
    pass

def create_parser():
    parser = argparse.ArgumentParser(description="Network scanner")
    parser.add_argument(
        # sweep - ping IP range, scan - TCP or UDP scan, depending on proto argument
        "task",        
        choices=["sweep", "scan"],
        help="Scan network by IP or scan host ports",
    )
    parser.add_argument(
        # Target host to start with. Number of hosts is defined in num_of_hosts (only for sweeper mode).
        "-i", "--ip", type=str, default="192.168.0.1", help="Host IP address, default 192.168.0.1"
    )
    parser.add_argument(
        # Only valid for sweep mode, ignored in scan mode
        "-n", "--num_of_hosts", type=int, default=1, help="Number of hosts (only for sweeper mode), default 1"
    )
    parser.add_argument(
        # Only for scan mode. Input udp or tcp protocol for scanning. Tcp is default.
        "--proto",
        nargs="?",
        type=str,
        default="tcp",
        help="tcp or udp protocol for port scan (only for scan mode). TCP by default."
    )
    parser.add_argument(
        # Only for scan mode. Input port or start-end range. Default is 1-30000.
        "-p", "--ports",
        nargs="?",
        type=str,
        default="1-1000",
        help="Port or ports range (e.g. 1-5000). By default 1-1000."
    )    
    parser.add_argument(
        # Output file to save results.
        "--outfile",
        nargs="?",
        type=str,
        const="output.txt",
        default=None,
        help="output file. If no filename specified, output.txt is used by default."
    )

    def get_args():
        nonlocal parser
        try:
            args = parser.parse_args()

            # Validate IP arguments
            octets = list(map(int, args.ip.split(".")))

            if len(octets) != 4:
                raise InvalidArgsExc(f"IP address {args.ip} is not valid")
            
            for octet in octets:
                if octet not in range(255):
                    raise InvalidArgsExc(f"IP address {args.ip} is not valid")
                
            if octets[-1] + int(args.num_of_hosts) > 255:
                raise InvalidArgsExc(f"Number of hosts is not valid")
            
            ip_base = ".".join(str(octet) for octet in octets[:-1])
            ip_list = [".".join([ip_base, str(octets[-1] + i)]) for i in range(int(args.num_of_hosts))]

            # Validate Protocol arguments
            if args.proto.lower() != "tcp" and args.proto.lower() != "udp":
                raise InvalidArgsExc(f"Protocol argument is not valid")       
            proto = args.proto.lower()

            # Validate Ports arguments
            ports = list(map(int, args.ports.split('-')))
            if len(ports) == 1 and ports[0] in range(1, 65535):
                port_list = [ports[0]]
            elif (len(ports) == 2 and ports[0] in range(1, 65536)
                  and ports[1] in range(1, 65536) and ports[0] < ports[1]):
                port_list = [port for port in range(ports[0], ports[1]+1)]
            else:
                raise InvalidArgsExc(f"Ports argument is not valid")

            return {
                "ip_list": ip_list,
                "port_list": port_list,
                "proto": proto,
                "task": args.task,
                "outfile": args.outfile
            }
        
        except Exception as err:
            raise ParserError(f"Failed to parse arguments! [error: {err}]")
        
        except InvalidArgsExc as err:
            raise InvalidArgsExc(f"Arguments are not correct! [error: {err}]")
        
        except (ValueError, TypeError) as err:
            raise InvalidArgsExc(f"Arguments are not correct! [error: {err}]")
        
        except Exception as err:
            raise RuntimeError(f"Unknown error occured during args validation! [error: {err}]")

    return get_args



def write_file(name, output):
    try:
        with open(name, "w") as f:
            f.writelines(output)
        return f"File {name} was written"
    except Exception:
        return None


def port_scan(host, dports, proto):

    stop_event = Event()
    message = b'test message'
    listen_dict = dict()
    result_dict = dict()

    port_count = len(dports)
    source_ip = get_source_ip(host)

    print("-"*30)
    print("Starting scan")
    print(f"Scanned 0/{port_count} ports", end="\r", flush=True)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        results = []

        # start ICMP listening task
        listen_task = executor.submit(icmp_receive, host, listen_dict, stop_event)
        
        if proto == 'udp':
            # start UDP sender tasks
            for dport in dports:
                results.append(executor.submit(udp_send, host, dport, message))
                time.sleep(1)
       
        if proto == 'tcp':
            # start TCP sender tasks
            for dport in dports:
                results.append(executor.submit(tcp_send, host, dport, source_ip))
                # in some cases remote host can limit its TCP or ICMP responses because of high request rate.
                # in this case you can limit request rate by adding timer
                # TODO: implement it as a dedicated cmd arg
                # time.sleep(1)
        
        # scanned ports counter
        scanned = 0
        
        # collecting finished futures
        for future in concurrent.futures.as_completed(results):
            scanned += 1
            if scanned % 10 == 0:
                print(f"Scanned {scanned}/{port_count} ports", end="\r", flush=True)
            status, port, srvc = future.result()
            if (listen_dict.get(port) == PORT.CLOSED):
                result_dict[port] = [PORT.CLOSED, "Unknown"]
            elif (listen_dict.get(port) == PORT.ADMIN_FILTERED):
                result_dict[port] = [PORT.ADMIN_FILTERED, "Unknown"]                
            else:
                result_dict[port] = [status, srvc]

        # set event to stop ICMP listener
        stop_event.set()

        #scan result output
        print(f"{proto.upper()} scan is over          ", end="\n", flush=True)
        output = "\n".join(f"Scanned port: {key:<5}  Status: {result_dict[key][0]:21}  Plausible service: {result_dict[key][1].strip()}"
                           for key in sorted(result_dict.keys())) #if result_dict[key][0] != PORT.CLOSED)
        
        return output

def sweep_scan(ip_list):

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(sweep, ip_list)
        results = "\n".join(results)

    return f"{'-' * 100}\n{results}{'-' * 100}\n"    


def main():

    getArgs = create_parser()

    try:
        args = getArgs()

    except ParserError as err:
        raise Exception(f"Failed to parse arguments! [error: {err}]")

    output = None
    if args["task"]== "sweep":
        try:
            output = sweep_scan(args["ip_list"])
            print(output)

        except Exception as err:
            raise Exception(err)
        
    if args["task"] == "scan":
        try:
            output = port_scan(args["ip_list"][0], args["port_list"], args["proto"])
            print(output)

        except Exception as err:
            raise Exception(err)
        
    if args["outfile"]:
        out = write_file(args["outfile"], output)
        if out:
            print(out)
        else:
            raise FileWriteError(f"Failed to write file with given name! [{args['outfile']}]")


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        print(f"Failed to execute script [error: {err}]")