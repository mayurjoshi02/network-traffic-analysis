# Network Traffic Analysis

## Project Overview
This project captures and analyzes network traffic using tcpdump,
Wireshark, Python, and Scapy.

## Objective
To inspect network packets, identify protocols, and summarize
source and destination IP addresses.

## Tools Used
- Kali Linux
- tcpdump
- Wireshark
- Python 3
- Scapy

## Methodology
1. Identified the active network interface.
2. Captured 100 packets using tcpdump.
3. Saved the capture as a PCAP file.
4. Inspected DNS and TCP traffic using Wireshark.
5. Used Python and Scapy to count protocols and IP addresses.
6. Generated a text analysis report.

## Results
- Total packets analyzed: 100
- TCP packets: 85
- DNS packets: 15
- Kernel-dropped packets during capture: 0

## Files
- analyze_traffic.py: Packet analysis script
- save_report.py: Report generation script
- analysis_report.txt: Analysis results

## Conclusion
The project demonstrates basic network packet capture,
protocol analysis, and automated reporting.

## Disclaimer
This project was performed in a personal lab environment.
IP addresses and packet counts are observations from this capture.
They do not by themselves prove malicious activity.
