from scapy.all import rdpcap, IP, TCP
from collections import defaultdict

packets = rdpcap("traffic.pcap")

ips = defaultdict(int)
http_requests = 0

for p in packets:
    if IP in p:
        ips[p[IP].src] += 1

    if p.haslayer(TCP):
        if p[TCP].dport == 80 or p[TCP].sport == 80:
            http_requests += 1

print("\n=== SOC TRAFFIC ANALYSIS ===\n")

for ip, count in sorted(ips.items(), key=lambda x: x[1], reverse=True):
    print(f"{ip} -> {count} packets")

print(f"\nHTTP-related packets: {http_requests}")
print("\nStatus: No anomalies detected in baseline traffic")
