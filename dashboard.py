import subprocess
import pandas as pd
import matplotlib.pyplot as plt
from scapy.all import PcapReader, IP, IPv6, TCP, UDP

PCAP_FILE = r"C:\Users\nanda\OneDrive\Documents\wireshark.pcapng"
TSHARK = r"C:\Program Files\Wireshark\tshark.exe"

# Read packet information
protocols = {"TCP": 0, "UDP": 0, "Other": 0}
sources = {}
destinations = {}
total_packets = 0

with PcapReader(PCAP_FILE) as packets:
    for packet in packets:
        total_packets += 1

        if TCP in packet:
            protocols["TCP"] += 1
        elif UDP in packet:
            protocols["UDP"] += 1
        else:
            protocols["Other"] += 1

        if IP in packet:
            src, dst = packet[IP].src, packet[IP].dst
        elif IPv6 in packet:
            src, dst = packet[IPv6].src, packet[IPv6].dst
        else:
            continue

        sources[src] = sources.get(src, 0) + 1
        destinations[dst] = destinations.get(dst, 0) + 1

# Count retransmissions using TShark
command = [
    TSHARK, "-r", PCAP_FILE,
    "-Y", "tcp.analysis.retransmission",
    "-T", "fields", "-e", "frame.number"
]

result = subprocess.run(command, capture_output=True, text=True)

if result.returncode != 0:
    raise RuntimeError(result.stderr)

retransmissions = len([
    line for line in result.stdout.splitlines() if line.strip()
])

# Port scan investigation
scan_data = {}

with PcapReader(PCAP_FILE) as packets:
    for packet in packets:
        if TCP in packet:
            tcp = packet[TCP]

            if tcp.flags.S and not tcp.flags.A:
                if IP in packet:
                    src, dst = packet[IP].src, packet[IP].dst
                elif IPv6 in packet:
                    src, dst = packet[IPv6].src, packet[IPv6].dst
                else:
                    continue

                scan_data.setdefault((src, dst), set()).add(tcp.dport)

possible_scans = sum(
    1 for ports in scan_data.values() if len(ports) >= 10
)

# Dashboard
fig, axes = plt.subplots(2, 2, figsize=(14, 9))

fig.suptitle(
    "NETWORK TRAFFIC THREAT DETECTION DASHBOARD",
    fontsize=16,
    fontweight="bold"
)

# Protocol distribution
axes[0, 0].pie(
    protocols.values(),
    labels=protocols.keys(),
    autopct="%1.1f%%"
)
axes[0, 0].set_title("Protocol Distribution")

# Top source IPs
top_sources = sorted(
    sources.items(), key=lambda x: x[1], reverse=True
)[:5]

axes[0, 1].barh(
    [ip[-18:] for ip, count in top_sources],
    [count for ip, count in top_sources]
)
axes[0, 1].set_title("Top 5 Source IPs")
axes[0, 1].invert_yaxis()

# Top destination IPs
top_destinations = sorted(
    destinations.items(), key=lambda x: x[1], reverse=True
)[:5]

axes[1, 0].barh(
    [ip[-18:] for ip, count in top_destinations],
    [count for ip, count in top_destinations]
)
axes[1, 0].set_title("Top 5 Destination IPs")
axes[1, 0].invert_yaxis()

# Security summary
axes[1, 1].axis("off")

summary = f"""
SECURITY INVESTIGATION SUMMARY

Total Packets: {total_packets}

TCP Packets: {protocols['TCP']}
UDP Packets: {protocols['UDP']}
Other Packets: {protocols['Other']}

TCP Retransmissions: {retransmissions}

Possible Port Scan Pairs: {possible_scans}

Port Scan Threshold: 10 unique ports
"""

axes[1, 1].text(
    0.05, 0.9, summary,
    fontsize=12,
    verticalalignment="top",
    family="monospace"
)

plt.tight_layout()
plt.savefig("network_security_dashboard.png", dpi=300)
plt.show()

print("Dashboard generated successfully!")
print("Saved as network_security_dashboard.png")