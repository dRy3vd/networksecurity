from scapy.all import *

for ttl_incr in range(1,20):
	a = IP()
	b=ICMP()
	a.dst = '1.1.1.1'
	a.ttl = ttl_incr
	pkt = a/b
	ans = sr1(pkt, timeout=2)
	if ans:
		print("ttl = " + str(ttl_incr) + " and router IP = " + str(ans.src))
	else:
		print("No response")
	if ans and ans.src == '1.1.1.1':
		print("Finished.")
		break


