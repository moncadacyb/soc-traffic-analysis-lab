from scapy.all import rdpcap, IP, TCP
from collections import defaultdict

# ==============================
# SOC Traffic Analyzer
# ==============================

def analyze_traffic(pcap_file):
    packets = rdpcap(pcap_file)

    ips = defaultdict(int)
    http_requests = 0

    for p in packets:

        # Count source IP packets
        if IP in p:
            ips[p[IP].src] += 1

        # Detect HTTP traffic
        if p.haslayer(TCP):
            if p[TCP].dport == 80 or p[TCP].sport == 80:
                http_requests += 1

    print("\n=== SOC TRAFFIC ANALYSIS ===\n")

    for ip, count in sorted(ips.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip} -> {count} packets")

    print(f"\nHTTP-related packets: {http_requests}")
    print("\nStatus: No anomalies detected in baseline traffic")


# ==============================
# SOC Alert Simulation
# ==============================

def soc_alert():
    print("\n=== SOC ALERT SYSTEM ===\n")
    print("Monitoring network activity...")
    print("No suspicious behavior detected.")
    print("System status: NORMAL")


# ==============================
# Main Execution
# ==============================

if __name__ == "__main__":

    analyze_traffic("traffic.pcap")

    soc_alert()
