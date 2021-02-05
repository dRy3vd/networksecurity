#!/usr/bin/python
from scapy.all import *

def print_pkt(pkt):
   pkt.show()

pkt = sniff(filter='tcp and host 10.0.2.15 and port 23',prn=print_pkt)

