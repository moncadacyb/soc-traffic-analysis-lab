from scapy.all import rdpcap, TCP, IP
from collections import defaultdict

packets = rdpcap("scan.pcap")

port_counter = defaultdict(int)
syn_packets = 0

for p in packets:
    if p.haslayer(TCP) and p.haslayer(IP):
        if p[TCP].flags == "S":
            syn_packets += 1
            port_counter[p[TCP].dport] += 1

print("\n=== SOC ALERT SYSTEM ===\n")

print(f"SYN packets detected: {syn_packets}")

if syn_packets > 10:
    print("ALERT: Possible Port Scan Detected!")

print("\nTop targeted ports:")

for port, count in port_counter.items():
    print(f"Port {port} -> {count} attempts")
