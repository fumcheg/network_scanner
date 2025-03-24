usage: sudo python3 netscan.py {sweep,scan} [-h] [-i IP] [-n NUM_OF_HOSTS] [--proto [PROTO]] [-p [PORTS]] [--outfile [OUTFILE]]

Network scanner - USE WITH SUDO!!!

positional arguments:
  {sweep,scan}          Scan network by IP or scan host ports

options:
  -h, --help                                        show this help message and exit
  -i IP, --ip IP                                    IP address, default 192.168.0.1
  -n NUM_OF_HOSTS, --num_of_hosts NUM_OF_HOSTS      number of hosts (only for sweeper mode), default 1 (sweep mode only)
  --proto [PROTO]                                   tcp or udp protocol for port scan. TCP by default.
  -p [PORTS], --ports [PORTS]                       port or ports range (e.g. 1-5000). By default 1-1000.
  --outfile [OUTFILE]                               output file. If no filename specified, output.txt is used by default.

To scan available hosts:
python3 netscan.py sweep -i host_ip -n host_count

Usage example:

python3 netscan.py sweep -i 192.168.1.1 -n 10 --outfile # run network sweep with output to output.txt
sudo python3 netscan.py scan -i 192.168.166.129 --proto udp -p 1-100 # run udp scan for ports 1-100
sudo python3 netscan.py scan -i 192.168.166.129 --proto tcp -p 80 # run tcp scan for port 80