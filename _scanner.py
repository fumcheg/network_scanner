import os

CMD = "ping -n 1 " if os.name == "nt" else "ping -c 1 "


class InvalidArgsExc(Exception):
    pass


def scanner_validate_input(ip, n):
    try:
        octets = list(map(int, ip.split(".")))
        if len(octets) != 4:
            raise InvalidArgsExc(f"IP address {ip} is not valid")
        for octet in octets:
            if octet not in range(255):
                raise InvalidArgsExc(f"IP address {ip} is not valid")
        if octets[-1] + int(n) > 255:
            raise InvalidArgsExc(f"Number of hosts is not valid")
        octetBase = ".".join(str(octet) for octet in octets[:-1])
        octetList = [".".join([octetBase, str(octets[-1] + i)]) for i in range(int(n))]
    except InvalidArgsExc as err:
        raise InvalidArgsExc(f"Arguments are not correct! [error: {err}]")
    except (ValueError, TypeError) as err:
        raise InvalidArgsExc(f"Arguments are not correct! [error: {err}]")
    except Exception as err:
        raise RuntimeError(
            f"Unknown error occured during args validation! [error: {err}]"
        )
    return octetList


def scanner_run(hostIP):
    response = os.popen(CMD + hostIP)
    result = "".join(line for line in response.readlines() if line != "\n")
    return f"Scanning result: {hostIP}\n{result}"
