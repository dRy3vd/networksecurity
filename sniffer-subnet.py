#!/usr/bin/python
from scapy.all import *

def print_pkt(pkt):
   pkt.show()

pkt = sniff(filter='src 192.168.1.0/24',prn=print_pkt)

