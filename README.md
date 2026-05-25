# SOC Traffic Analysis Lab

## Overview
This project simulates a basic SOC (Security Operations Center) traffic analysis environment. It focuses on analyzing network traffic captured in PCAP files to identify patterns, HTTP activity, and potential anomalies using Python and Scapy.

## Objectives
- Analyze network traffic from PCAP files  
- Identify active IP addresses and packet distribution  
- Detect HTTP-related traffic  
- Simulate SOC-level baseline monitoring  

## Tools & Technologies
- Python 3  
- Scapy  
- Wireshark  
- tcpdump  
- Linux (Ubuntu/Kali)  

## Project Structure

## How It Works

### Traffic Analysis
`soc_analyzer.py` processes the PCAP file and:
- Extracts IP addresses  
- Counts packets per IP
  
- Detects HTTP traffic (port 80)  

### Output Example

## Evidence
The `screenshots/` folder contains:
- Network scanning (nmap)
- Traffic inspection (tcpdump)
- HTTP request testing (curl)
- Network configuration (ip a)

## Key Learning
- Network traffic analysis basics  
- PCAP inspection  
- SOC monitoring workflow  
- Python-based packet parsing  

## Future Improvements
- Detect port scanning behavior  
- Add anomaly detection rules  
- Improve alerting in soc_alert.py  
- Export results to JSON/CSV for SIEM  

## Author
SOC Traffic Analysis Lab – Cybersecurity practice project
