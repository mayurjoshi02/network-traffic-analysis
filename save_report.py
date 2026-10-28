from scapy.all import PcapReader, IP, TCP, UDP, DNS, ICMP
from collections import Counter
from datetime import datetime

protocols = Counter()
sources = Counter()
destinations = Counter()
total = 0

with PcapReader("network_traffic.pcap") as packets:
    for packet in packets:
        total += 1
        if IP in packet:
            sources[packet[IP].src] += 1
            destinations[packet[IP].dst] += 1

        if DNS in packet:
            protocols["DNS"] += 1
        elif TCP in packet:
            protocols["TCP"] += 1
        elif UDP in packet:
            protocols["UDP"] += 1
        elif ICMP in packet:
            protocols["ICMP"] += 1
        else:
            protocols["Other"] += 1

with open("analysis_report.txt", "w") as report:
    report.write("NETWORK TRAFFIC ANALYSIS REPORT\n")
    report.write("=" * 35 + "\n")
    report.write(f"Date: {datetime.now():%Y-%m-%d %H:%M}\n")
    report.write(f"Total packets analyzed: {total}\n\n")
    report.write("Protocol counts:\n")
    for protocol, count in protocols.most_common():
        report.write(f"{protocol}: {count}\n")

    report.write("\nTop source IPs:\n")
    for ip, count in sources.most_common(5):
        report.write(f"{ip}: {count} packets\n")

    report.write("\nTop destination IPs:\n")
    for ip, count in destinations.most_common(5):
        report.write(f"{ip}: {count} packets\n")

print("Report saved to analysis_report.txt")
