# Ethical Hacking Lab: Man-in-the-Middle and DNS Spoofing

![License](https://img.shields.io/badge/license-Educational-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)

## 📋 Table of Contents

- [Overview](#overview)
- [Lab Architecture](#lab-architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Task 1: ARP Spoofing](#task-1-arp-spoofing)
  - [Task 2: Traffic Analysis](#task-2-traffic-analysis)
  - [Task 3: DNS Spoofing](#task-3-dns-spoofing)
- [Project Structure](#project-structure)
- [Documentation](#documentation)
- [Ethics and Legal Notice](#ethics-and-legal-notice)
- [License](#license)

## 🔍 Overview

This repository contains a comprehensive implementation of network security attacks performed in a controlled, isolated laboratory environment. The project demonstrates:

- **ARP Cache Poisoning** to establish a Man-in-the-Middle (MitM) position
- **Network Traffic Analysis** to extract sensitive data from unencrypted protocols
- **DNS Spoofing** using NFQUEUE architecture to redirect victims to malicious servers

All experiments were conducted in a fully isolated VirtualBox environment for educational purposes only.

## 🏗️ Lab Architecture

The laboratory consists of three virtual machines on an isolated internal network (`labnet` - `192.168.100.0/24`):

```
┌─────────────────────────────────────────────────────────────┐
│                     VirtualBox Host                         │
│                                                             │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐ │
│  │   Gateway/     │  │     Victim     │  │    Attacker    │ │
│  │    Server      │  │   (Ubuntu)     │  │  (Kali Linux)  │ │
│  │  192.168.100.1 │  │ 192.168.100.2  │  │ 192.168.100.3  │ │
│  │                │  │                │  │                │ │
│  │ - NAT Router   │  │ - Static IP    │  │ - Scapy        │ │
│  │ - DNS (dnsmasq)│  │ - DHCP Client  │  │ - NFQueue      │ │
│  │ - Apache       │  │                │  │ - Wireshark    │ │
│  └────────┬───────┘  └────────┬───────┘  └─────────┬──────┘ │
│           │                   │                    │        │
│           └───────────────────┴────────────────────┘        │
│                        labnet (Internal Network)            │
└─────────────────────────────────────────────────────────────┘
```

### Network Configuration

- **Gateway/Server (192.168.100.1)**
  - Ubuntu Server with dual NICs
  - NAT routing with iptables
  - DNS/DHCP services (dnsmasq)
  - Apache web server

- **Victim (192.168.100.2)**
  - Ubuntu Desktop
  - Configured to use gateway as sole DNS server
  - Target of all attacks

- **Attacker (192.168.100.3)**
  - Kali Linux
  - Python 3.8+ with Scapy
  - Netfilter Queue support
  - Wireshark for traffic analysis

## 📦 Requirements

### System Requirements

- VirtualBox 6.0+
- 8GB RAM minimum (recommended: 16GB)
- 50GB free disk space
- Host OS: Windows, macOS, or Linux

### Python Dependencies

See `requirements.txt` for complete list. Main dependencies:

- `scapy >= 2.4.5` - Packet manipulation
- `NetfilterQueue >= 1.1.0` - Linux kernel packet interception
- `python-iptables >= 1.0.0` - iptables integration

### Linux Packages (Attacker VM)

```bash
sudo apt update
sudo apt install -y \
    python3 \
    python3-pip \
    python3-scapy \
    python3-netfilterqueue \
    tcpdump \
    wireshark \
    net-tools \
    iptables
```

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/simonecurci/ethical-hacking-assignment-2.git
cd ethical-hacking-assignment-2
```

### 2. Install Python Dependencies

```bash
pip3 install -r requirements.txt
```

### 3. Set Up Virtual Machines

Follow the detailed setup instructions in the lab report (`report.pdf`) or see the [Lab Setup Guide](#lab-architecture).

## 💻 Usage

> **⚠️ WARNING**: These tools must ONLY be used in isolated lab environments. Unauthorized use is illegal.

### Task 1: ARP Spoofing

Establish a Man-in-the-Middle position between the victim and gateway:

```bash
cd scripts
sudo python3 arp_spoof.py -v 192.168.100.2 -g 192.168.100.1 -i eth0 --verbose
```

**Options:**
- `-v, --victim`: Target victim IP address
- `-g, --gateway`: Gateway IP address
- `-i, --interface`: Network interface to use
- `--verbose`: Enable verbose output

**Graceful Exit:** Press `Ctrl+C` to stop the attack and restore ARP tables.

**Captured Traffic:** `pcap_files/arp_spoof_task_1.pcap`

### Task 2: Traffic Analysis

Analyze captured PCAP files to extract sensitive information:

```bash
cd scripts
python3 pcap_analyzer.py -f ../pcap_files/arp_spoof_filtered_task_2_ssh_telnet_ftp.pcap
```

The script will extract:
- HTTP URLs visited
- DNS queries performed
- Protocol statistics
- **FTP, Telnet, and SSH credentials** (plaintext)
- Top network talkers

**Alternative:** Open `*.pcap` files in Wireshark for manual analysis.

**Evidence:** See `evidence/pcap_analyzer_task_2.log` for script output.

### Task 3: DNS Spoofing

Intercept and forge DNS responses using NFQUEUE:

#### Step 1: Configure Targets

Edit `evidence/targets_task_3.txt` with domains to spoof:

```
example.com 192.168.100.3
google.com 192.168.100.3
# Format: domain redirect_ip
```

#### Step 2: Start Fake Web Server

```bash
# Terminal 1
sudo python3 -m http.server 80
```

#### Step 3: Maintain MitM Position

```bash
# Terminal 2
cd scripts
sudo python3 arp_spoof.py -v 192.168.100.2 -g 192.168.100.1 -i eth0
```

#### Step 4: Launch DNS Spoofer

```bash
# Terminal 3
cd scripts
sudo python3 dns_spoof.py \
    -i eth0 \
    -t ../evidence/targets_task_3.txt \
    -v 192.168.100.2 \
    -g 192.168.100.1 \
    -a 192.168.100.3
```

**Options:**
- `-i, --interface`: Victim's input interface
- `-t, --targets`: Path to targets file
- `-v, --victim-ip`: Victim's IP address
- `-g, --gateway-ip`: Gateway IP address
- `-a, --attacker-ip`: Your fake server IP (default: 192.168.100.3)

**Captured Traffic:** 
- Full capture: `pcap_files/dns_spoof_task_3.pcap`
- Filtered (DNS only): `pcap_files/dns_spoof_filtered_task_3_only_dns_.pcap`

## 📁 Project Structure

```
ethical-hacking-assignment-2/
├── README.md                  # This file
├── requirements.txt           # Python dependencies
│
├── evidence/                  # Evidence screenshots and logs
│   ├── arp_table_before_spoof_task_1.png
│   ├── arp_table_after_spoof_task_1.png
│   ├── server_task_1.png
│   ├── pcap_analyzer_task_2.log
│   ├── wireshark_packets_task_2.png
│   ├── wireshark_statistics_task_2.png
│   ├── targets_task_3.txt
│   ├── fake_website_task_3.log
│   ├── redirect_curl_task_3.png
│   ├── browser_spoofed_google_task_3.png
│   └── dns_spoofed_google_task_3.png
│
├── pcap_files/                # Network capture files
│   ├── arp_spoof_task_1.pcap
│   ├── arp_spoof_filtered_task_2_ssh_telnet_ftp.pcap
│   ├── dns_spoof_task_3.pcap
│   └── dns_spoof_filtered_task_3_only_dns_.pcap
│
└── scripts/                   # Python scripts
    ├── arp_spoof.py          # ARP spoofing attack (Task 1)
    ├── pcap_analyzer.py      # Traffic analysis tool (Task 2)
    └── dns_spoof.py          # DNS spoofing attack (Task 3)
```

## 📚 Documentation

### Evidence and Logs

All evidence from the experiments is organized in the `evidence/` folder:

- **Task 1 Screenshots**: ARP table states before/after spoofing, graceful restoration
- **Task 2 Logs**: Complete output from `pcap_analyzer.py` and Wireshark statistics
- **Task 3 Evidence**: DNS spoofing redirects, fake website logs, browser screenshots

### Key Findings

1. **ARP Spoofing**: Successfully poisoned ARP caches, achieving transparent MitM position
2. **Traffic Interception**: Extracted plaintext credentials from FTP, Telnet, and SSH traffic
3. **DNS Manipulation**: Successfully redirected victims using NFQUEUE architecture
4. **Modern Defenses**: HTTPS and HSTS effectively prevented downgrade attacks

## 🛡️ Mitigation Strategies

The lab report discusses comprehensive defenses:

- **ARP Spoofing**: Dynamic ARP Inspection (DAI), static ARP entries, monitoring tools
- **Traffic Interception**: TLS/SSL encryption (HTTPS, SFTP), VPNs
- **DNS Spoofing**: DNSSEC validation, DNS-over-HTTPS (DoH), DNS-over-TLS (DoT)
- **Downgrade Attacks**: HSTS headers, HSTS preload lists

## ⚖️ Ethics and Legal Notice

### ⚠️ IMPORTANT DISCLAIMER

The techniques demonstrated in this repository are **ILLEGAL** if performed without explicit authorization. This project is intended **EXCLUSIVELY** for:

- Academic education in controlled environments
- Security research in isolated labs
- Authorized penetration testing with written permission

### Ethical Guidelines

✅ **ALLOWED:**
- Using these tools in your own isolated virtual lab
- Educational purposes in approved academic settings
- Authorized security testing with written consent

❌ **PROHIBITED:**
- Any use on networks you don't own or control
- Unauthorized interception of third-party communications
- Any malicious or illegal activity

### Legal Consequences

Unauthorized network attacks violate laws in most jurisdictions, including:
- Computer Fraud and Abuse Act (CFAA) - United States
- Computer Misuse Act - United Kingdom
- Similar cybercrime laws worldwide

**Penalties can include:**
- Criminal prosecution
- Substantial fines
- Imprisonment
- Civil liability

### Author's Statement

All experiments in this project were conducted in a fully isolated VirtualBox environment under the author's complete control. No university, corporate, home, or public networks were affected.

## 📄 License

This project is provided for **educational purposes only**. The author assumes no liability for misuse.

## 🙏 Acknowledgments

- Course: Ethical Hacking (Academic)
- Tools: Scapy, Netfilter, Wireshark
- Platform: VirtualBox, Kali Linux, Ubuntu
- Repository: [github.com/simonecurci/ethical-hacking-assignment-2](https://github.com/simonecurci/ethical-hacking-assignment-2)

---

**Remember**: With great power comes great responsibility. Use your skills ethically.
