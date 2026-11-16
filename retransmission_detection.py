import subprocess

PCAP_FILE = r"PCAP_FILE = "sample_traffic.pcapng""

TSHARK = r"C:\Program Files\Wireshark\tshark.exe"

command = [
    TSHARK,
    "-r", PCAP_FILE,
    "-Y", "tcp.analysis.retransmission",
    "-T", "fields",
    "-e", "frame.number"
]

result = subprocess.run(
    command,
    capture_output=True,
    text=True
)

if result.returncode != 0:
    print("Error:", result.stderr)
else:
    packets = [
        line for line in result.stdout.splitlines()
        if line.strip()
    ]

    print("\nTCP RETRANSMISSION DETECTION")
    print("-" * 40)
    print("Total retransmission packets:", len(packets))
    print("Detection completed.")
