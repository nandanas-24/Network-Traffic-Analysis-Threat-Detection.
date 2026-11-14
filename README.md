# Network Traffic Analysis and Threat Detection Using Wireshark and Python

## 📌 Project Overview

This project focuses on analysing network traffic and identifying possible security-related activities using Wireshark and Python.

Wireshark is used to capture and investigate network packets, while Python automates packet analysis and basic threat detection. TShark is used to identify TCP retransmissions, and Matplotlib is used to generate a graphical dashboard.

The main objective is to understand network communication, analyse packet behaviour, and perform basic security monitoring.

## 🎯 Objectives

- Capture and analyse network traffic using Wireshark.
- Understand TCP, UDP, DNS, and HTTPS protocols.
- Analyse source and destination IP addresses.
- Investigate TCP flags and retransmissions.
- Detect possible TCP port scanning activity using Python.
- Automate packet analysis using Scapy.
- Generate a graphical network traffic dashboard.

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| Python | Network traffic analysis |
| Wireshark | Packet capture and analysis |
| Scapy | Packet processing |
| TShark | Automated packet analysis |
| Matplotlib | Dashboard generation |
| Pandas | Data handling |
| PowerShell | Program execution |

## 📂 Project Structure

```text
Network-Traffic-Threat-Detection/
│
├── main.py
├── scan_detection.py
├── retransmission_detection.py
├── dashboard.py
├── network_security_dashboard.png
├── README.md
└── .gitignore
```

## ⚙️ Project Modules

### 1. Network Traffic Analysis
- Reads captured PCAPNG files.
- Counts total packets.
- Identifies TCP, UDP, and other protocols.
- Displays top source and destination IP addresses.

### 2. TCP Port Scan Detection
- Analyses TCP SYN packets.
- Checks unique destination ports for each source-destination pair.
- Uses a threshold of 10 unique ports to flag possible port scanning activity.

### 3. TCP Retransmission Detection
- Uses TShark to identify TCP retransmission packets.
- Automates the analysis using Python.
- Displays the total retransmission count.

### 4. Graphical Dashboard
- Displays protocol distribution.
- Shows top source IP addresses.
- Shows top destination IP addresses.
- Displays retransmission and port scan investigation results.

## 📊 Project Results

The captured network traffic contained the following results:

| Parameter | Result |
|---|---:|
| Total Packets | 23,715 |
| TCP Packets | 6,249 |
| UDP Packets | 17,363 |
| Other Packets | 103 |
| TCP Retransmissions | 177 |
| Possible Port Scans | 0 |

**Observation:** No possible TCP port scans were detected using the selected threshold of 10 unique destination ports.

The 177 retransmissions indicate observed network retransmission behaviour and do not necessarily represent a security threat.

## 🖥️ Dashboard

The project generates a graphical dashboard using Python and Matplotlib.

Dashboard includes:
- Protocol distribution
- Top 5 source IP addresses
- Top 5 destination IP addresses
- Security investigation summary

## 🚀 Installation and Execution

### Step 1: Install Python Libraries

```bash
python -m pip install scapy pandas matplotlib
```

### Step 2: Install Wireshark

Install Wireshark with TShark support.

### Step 3: Clone the Repository

```bash
git clone https://github.com/YOUR-USERNAME/Network-Traffic-Threat-Detection.git
```

### Step 4: Open the Project Folder

```bash
cd Network-Traffic-Threat-Detection
```

### Step 5: Configure the PCAPNG File

Place your own authorised PCAPNG capture file on your computer.

Update the `PCAP_FILE` variable in the Python scripts with the correct file location.

### Step 6: Run the Programs

Main traffic analysis:

```bash
python main.py
```

TCP port scan detection:

```bash
python scan_detection.py
```

TCP retransmission detection:

```bash
python retransmission_detection.py
```

Generate dashboard:

```bash
python dashboard.py
```

## 🔮 Future Enhancements

- Real-time network traffic monitoring.
- Improved threat detection methods.
- Detection of additional suspicious network activities.
- Interactive security dashboard.
- Machine learning-based network anomaly detection.

## 📚 Learning Outcomes

Through this project, I gained practical knowledge of:

- Network packet capture and analysis.
- TCP, UDP, DNS, and HTTPS communication.
- IP address analysis.
- Python-based network automation.
- Basic security monitoring techniques.
- Network traffic visualisation.

## 👩‍💻 Author

**Nandana S.**

Electronics and Communication Engineering Student

GitHub: https://github.com/nandanas-24

LinkedIn: https://www.linkedin.com/in/nandana-s-6b33762a/

---

**Note:** This project is intended for educational and defensive network analysis. Use packet captures from networks you own or are authorised to monitor.
