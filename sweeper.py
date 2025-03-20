import os

CMD = "ping -n 1 " if os.name == "nt" else "ping -c 1 "

def sweep(host):
    response = os.popen(CMD + host)
    result = "".join(line for line in response.readlines() if line != "\n")
    return f"Scanning result: {host}\n{result}"