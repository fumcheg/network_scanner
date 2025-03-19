"""
Use example:
python3 main.py scan -i 192.168.1.1 -n 10 --outfile
python3 main.py sendhttp --infile --outfile
"""

import argparse
from shutil import ExecError
import requests
import json

BASE_URL = "http://localhost:6969/"


class ParserError(Exception):
    pass


class FileWriteError(Exception):
    pass


def create_parser():
    parser = argparse.ArgumentParser(description="Network scanner")
    parser.add_argument(
        "task",
        choices=["scan", "sendhttp"],
        help="Scan network by IP or send HTTP request",
    )
    parser.add_argument(
        "-i", "--ip", type=str, default="192.168.0.1", help="IP address"
    )
    parser.add_argument(
        "-n", "--num_of_hosts", type=int, default=1, help="Number of hosts"
    )
    parser.add_argument(
        "--infile",
        nargs="?",
        type=str,
        const="input.txt",
        default=None,
        help="JSON file for HTTP proxy",
    )
    parser.add_argument(
        "--outfile",
        nargs="?",
        type=str,
        const="output.txt",
        default=None,
        help="Output file for server response",
    )

    def get_args():
        nonlocal parser
        try:
            return parser.parse_args()
        except Exception as err:
            raise ParserError(f"Failed to parse arguments! [error: {err}]")

    return get_args


def write_file(name, output):
    try:
        with open(name, "w") as f:
            f.writelines(output)
        return f"File {name} was written"
    except Exception:
        return None


def scan(args):
    payload = {"target": args.ip, "count": str(args.num_of_hosts)}

    try:
        print("Sent request. Waiting for server response...")
        response = requests.get(BASE_URL + "scan", json=payload, timeout=30)
        output = []
        if response.ok:
            output.append(f"Received server response: {response.status_code}\n")
            output.append(response.text.replace("\\n", "\n").lstrip('"').rstrip('"'))
            print("\n".join(output))
            if args.outfile:
                res = write_file(args.outfile, output)
                if res:
                    print(res)
                else:
                    raise FileWriteError(
                        f"Failed to write file with given name! [{args.outfile}]"
                    )
        else:
            print("Received negative server response ", response.status_code)

    except requests.exceptions.ConnectionError as err:
        raise Exception(f"Could not connect to server... {err}")


def sendhttp(args):

    if args.infile:
        output = []

        try:
            with open(args.infile, "r") as f:
                payload = json.load(f)
            print("Sent request. Waiting for server response...")
            response = requests.post(BASE_URL + "send-request", json=payload, timeout=5)
            output.append(f"Response status code: {response.status_code}\n")
            output.append(
                f"Response headers: {json.dumps(dict(response.headers), indent=4, sort_keys=True)}\n"
            )
            output.append(f"Response content:\n{response.text}\n")
            output = "\n".join(output)

            if args.outfile:
                res = write_file(args.outfile, output)
                if res:
                    print(res)
                else:
                    raise FileWriteError(
                        f"Failed to write file with given name! [{args.outfile}]"
                    )
            else:
                print(output)

        except FileWriteError as err:
            print(err)
            raise Exception(err)
        except requests.exceptions.ConnectionError as err:
            print(f"Could not connect to server...")
            raise Exception(err)
        except requests.exceptions.RequestException as err:
            print(f"Could not complete request or process response! [error: {err}]")
            raise Exception(err)
        except Exception as err:
            print(f"Unexpected error ocurred! [error: {err}]")
            raise Exception(err)


def main():

    getArgs = create_parser()
    try:
        args = getArgs()
    except ParserError as err:
        raise Exception(f"Failed to parse arguments! [error: {err}]")

    if args.task == "scan":
        try:
            scan(args)
        except FileWriteError as err:
            print(err)
        except Exception as err:
            raise Exception(err)

    if args.task == "sendhttp":
        try:
            sendhttp(args)
        except Exception as err:
            raise Exception(err)


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        print(f"Failed to execute script [error: {err}]")
