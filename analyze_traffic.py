from collections import Counter
from scapy.all import PcapReader, IP, TCP, UDP, ICMP, DNS

file_name = "network_traffic.pcap"

protocols = Counter()
source_ips = Counter()
destination_ips = Counter()
total = 0

with PcapReader(file_name) as packets:
    for packet in packets:
        total += 1

        if IP in packet:
            source_ips[packet[IP].src] += 1
            destination_ips[packet[IP].dst] += 1

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

print("=== Network Traffic Analysis ===")
print("Total packets:", total)

print("\nProtocol counts:")
for name, count in protocols.most_common():
    print(f"{name}: {count}")

print("\nTop source IPs:")
for ip, count in source_ips.most_common(5):
    print(f"{ip}: {count} packets")

print("\nTop destination IPs:")
for ip, count in destination_ips.most_common(5):
    print(f"{ip}: {count} packets")

