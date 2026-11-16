from scapy.all import PcapReader, IP, IPv6, TCP, UDP
from collections import Counter

PCAP_FILE = r"PCAP_FILE = "sample_traffic.pcapng""

packet_count = 0
protocols = Counter()
source_ips = Counter()
destination_ips = Counter()

print("\nNETWORK TRAFFIC ANALYSIS")
print("-" * 40)

try:
    with PcapReader(PCAP_FILE) as packets:
        for packet in packets:
            packet_count += 1

            if IP in packet:
                source_ips[packet[IP].src] += 1
                destination_ips[packet[IP].dst] += 1

            elif IPv6 in packet:
                source_ips[packet[IPv6].src] += 1
                destination_ips[packet[IPv6].dst] += 1

            if TCP in packet:
                protocols["TCP"] += 1
            elif UDP in packet:
                protocols["UDP"] += 1
            else:
                protocols["Other"] += 1

    print("Total Packets:", packet_count)

    print("\nProtocol Distribution:")
    for protocol, count in protocols.most_common():
        print(protocol, ":", count)

    print("\nTop 5 Source IPs:")
    for ip, count in source_ips.most_common(5):
        print(ip, ":", count)

    print("\nTop 5 Destination IPs:")
    for ip, count in destination_ips.most_common(5):
        print(ip, ":", count)

except FileNotFoundError:
    print("ERROR: PCAPNG file not found.")

except Exception as error:
    print("ERROR:", error)
