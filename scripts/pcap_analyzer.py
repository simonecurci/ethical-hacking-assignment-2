#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http, dns
import argparse
from collections import Counter
import sys
import re

def get_arguments():
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(description="PCAP Traffic Analyzer")
    parser.add_argument("-f", "--file", required=True, dest="pcap_file", 
                        help="Path to the .pcap file (e.g., arp_spoof_capture.pcap)")
    args = parser.parse_args()
    return args

def analyze_pcap(pcap_file):
    """
    Reads a pcap file and extracts HTTP URLs, DNS queries, protocol counts,
    top talkers, and FTP credentials.
    """
    try:
        packets = scapy.rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"[!] Error: File not found: {pcap_file}", file=sys.stderr)
        sys.exit(1)
    except scapy.error.Scapy_Exception:
        print(f"[!] Error: Unable to read the pcap file.", file=sys.stderr)
        sys.exit(1)

    http_requests = []
    dns_queries = []
    ftp_creds = []
    protocol_counts = Counter()
    top_talkers_src = Counter()

    print(f"\n[+] Analyzing '{pcap_file}' ({len(packets)} total packets)...")

    for packet in packets:
        # --- Protocol Counting (IP/ARP Layer) ---
        if packet.haslayer(scapy.IP):
            top_talkers_src[packet[scapy.IP].src] += 1
            
            if packet.haslayer(scapy.TCP):
                protocol_counts['TCP'] += 1
            elif packet.haslayer(scapy.UDP):
                protocol_counts['UDP'] += 1
            elif packet.haslayer(scapy.ICMP):
                protocol_counts['ICMP'] += 1
        
        elif packet.haslayer(scapy.ARP):
            protocol_counts['ARP'] += 1
            if packet[scapy.ARP].op == 2: # 'is-at' (Response)
                top_talkers_src[packet[scapy.ARP].psrc] += 1

        # --- HTTP Extraction (Task 2) ---
        if packet.haslayer(http.HTTPRequest):
            try:
                method = packet[http.HTTPRequest].Method.decode('utf-8')
                host = packet[http.HTTPRequest].Host.decode('utf-8')
                path = packet[http.HTTPRequest].Path.decode('utf-8')
                url = f"{method} http://{host}{path}"
                if url not in http_requests:
                    http_requests.append(url)
            except Exception:
                pass # Ignore malformed packets

        # --- DNS Extraction (Task 2 & 3) ---
        if packet.haslayer(dns.DNSQR) and packet[dns.DNS].qr == 0: # Query (qr=0)
            try:
                query = packet[dns.DNSQR].qname.decode('utf-8')
                if query not in dns_queries:
                    dns_queries.append(query)
            except Exception:
                pass

        # --- FTP Credentials Extraction (Bonus) ---
        if packet.haslayer(scapy.TCP) and (packet[scapy.TCP].dport == 21 or packet[scapy.TCP].sport == 21):
            if packet.haslayer(scapy.Raw):
                try:
                    load = packet[scapy.Raw].load.decode('utf-8').strip()
                    if load.upper().startswith("USER ") or load.upper().startswith("PASS "):
                        if load not in ftp_creds:
                            ftp_creds.append(load)
                except Exception:
                    pass

    # --- Print Results ---
    
    print("\n--- 🗣️ Top Talkers (IP/ARP Sources) ---")
    if not top_talkers_src:
        print("No IP/ARP talkers found.")
    else:
        for ip, count in top_talkers_src.most_common(5):
            print(f"[+] {ip:<16} : {count} packets")

    print("\n--- 📊 Protocol Count (L3/L4) ---")
    if not protocol_counts:
        print("No protocols found.")
    else:
        for proto, count in protocol_counts.items():
            print(f"[+] {proto:<5}: {count} packets")

    print("\n--- ❓ DNS Queries Performed ---")
    if not dns_queries:
        print("No DNS queries found.")
    else:
        for query in dns_queries:
            print(f"[+] {query}")
    
    print("\n--- 🌐 HTTP URLs Visited ---")
    if not http_requests:
        print("No HTTP requests found.")
    else:
        for url in http_requests:
            print(f"[+] {url}")

    print("\n--- 🗄️ FTP Credentials (plaintext!) ---")
    if not ftp_creds:
        print("No FTP credentials found.")
    else:
        for cred in ftp_creds:
            print(f"[!] {cred}")
            
    print("\n[+] Analysis completed.")

def main():
    args = get_arguments()
    analyze_pcap(args.pcap_file)

if __name__ == "__main__":
    main()