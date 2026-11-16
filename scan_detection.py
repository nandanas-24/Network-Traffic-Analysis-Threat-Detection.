from scapy.all import PcapReader, IP, IPv6, TCP
from collections import defaultdict

PCAP_FILE = r"PCAP_FILE = "sample_traffic.pcapng""

scan_data = defaultdict(set)

with PcapReader(PCAP_FILE) as packets:

    for packet in packets:

        if TCP in packet:

            tcp = packet[TCP]

            # SYN set, ACK not set
            if tcp.flags.S and not tcp.flags.A:

                if IP in packet:
                    src = packet[IP].src
                    dst = packet[IP].dst

                elif IPv6 in packet:
                    src = packet[IPv6].src
                    dst = packet[IPv6].dst

                else:
                    continue

                scan_data[(src, dst)].add(tcp.dport)

print("\nTCP PORT SCAN INVESTIGATION")
print("-" * 45)

found = False

for (src, dst), ports in scan_data.items():

    if len(ports) >= 10:

        found = True

        print("\nPOSSIBLE PORT SCAN")
        print("Source IP:", src)
        print("Destination IP:", dst)
        print("Unique destination ports:", len(ports))
        print("Ports:", sorted(ports))

if not found:
    print("No possible port scans detected using this threshold.")

print("\nInvestigation completed.")
