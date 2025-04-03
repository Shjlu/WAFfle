from scapy.all import *

p = IP(dst= "10.0.0.9", id=1111, ttl=99) / TCP(sport=RandShort(), dport=5000, seq=12345, ack=1000, window=1000, flags="S")/"HaX0r SVP"
ans, unans = srloop(p, inter=0.3, timeout=4)
ans.make_table(lambda s, r: (s.dst, s.dport, r.sprintf("%IP.id% \t %IP.ttl% \t %TCP.flags%")))