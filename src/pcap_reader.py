# pcap_reader.py
"""
IoT-Shield: Stateless High-Performance Feature Extractor (dpkt Edition)

This module utilizes 'dpkt' for ultra-fast, byte-level packet parsing.
It performs stateless extraction, guaranteeing a flat and minimal 
memory footprint regardless of PCAP file size.
"""

import argparse
import csv
import os
import socket
import sys
import dpkt

def extract_features_dpkt(pcap_path, csv_path, infected_ip):
    print(f"[INFO] Initiating stateless extraction (dpkt) for: {pcap_path}")
    print(f"[INFO] Target Infected IP (Botnet Class): {infected_ip}")
    
    last_seen_time = {}
    packet_count = 0
    malicious_count = 0
    normal_count = 0
    
    try:
        f_in = open(pcap_path, 'rb')
    except PermissionError:
        print(f"[ERROR] Permission denied: Cannot read {pcap_path}. Check file ownership.")
        sys.exit(1)
        
    try:
        # Automatically detect standard PCAP or PCAPNG formats
        try:
            pcap = dpkt.pcap.Reader(f_in)
        except ValueError:
            f_in.seek(0)
            pcap = dpkt.pcapng.Reader(f_in)
            
        with open(csv_path, mode='w', newline='') as out_file:
            csv_writer = csv.writer(out_file)
            
            csv_writer.writerow([
                'total_size_bytes', 'payload_size_bytes', 'ttl',
                'is_tcp', 'is_udp', 'is_icmp', 'tcp_window', 'tcp_flag', 'iat_ms', 'label'
            ])
            
            for ts, buf in pcap:
                packet_count += 1
                
                # Silently skip corrupted Ethernet-level packets
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                except Exception:
                    continue
                    
                # Ignore non-IPv4 traffic (e.g., ARP, IPv6)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                    
                ip = eth.data
                
                try:
                    src_ip_str = socket.inet_ntoa(ip.src)
                except Exception:
                    continue
                
                # 1. Automatic Ground-Truth Labeling
                label = 1 if src_ip_str == infected_ip else 0
                if label == 1:
                    malicious_count += 1
                else:
                    normal_count += 1
                    
                # 2. Inter-Arrival Time (IAT) Calculation
                if src_ip_str in last_seen_time:
                    iat_ms = (ts - last_seen_time[src_ip_str]) * 1000.0
                else:
                    iat_ms = 0.0
                last_seen_time[src_ip_str] = ts
                
                # Prevent RAM exhaustion caused by malware IP spoofing
                if len(last_seen_time) > 100000:
                    last_seen_time.clear()
                    
                # 3. Base IP Metrics
                total_size_bytes = len(buf)
                ttl = ip.ttl
                
                # 4. Transport Layer Metrics Identification
                is_tcp, is_udp, is_icmp = 0, 0, 0
                tcp_window, tcp_flag_num, payload_size_bytes = 0, 0, 0
                
                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
                    is_tcp = 1
                    tcp_window = tcp.win
                    tcp_flag_num = tcp.flags
                    payload_size_bytes = len(tcp.data)
                    
                elif isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data
                    is_udp = 1
                    payload_size_bytes = len(udp.data)
                    
                elif isinstance(ip.data, dpkt.icmp.ICMP):
                    icmp = ip.data
                    is_icmp = 1
                    payload_size_bytes = len(icmp.data)
                    
                csv_writer.writerow([
                    total_size_bytes, payload_size_bytes, ttl,
                    is_tcp, is_udp, is_icmp, tcp_window, tcp_flag_num, f"{iat_ms:.4f}", label
                ])
                
                if packet_count % 1000000 == 0:
                    print(f"[PROCESS] {packet_count:,} packets extracted... (Botnet: {malicious_count:,} | Normal: {normal_count:,})")
                    
    except Exception as e:
        print(f"\n[ERROR] An exception occurred during parsing: {e}")
    finally:
        f_in.close()
        
    print(f"\n[SUCCESS] Feature extraction completed.")
    print(f"[STATISTICS] Total processed packets: {packet_count:,}")
    print(f"[STATISTICS] Dataset distribution -> Botnet: {malicious_count:,} | Benign: {normal_count:,}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="IoT-Shield Feature Extractor: Generates lightweight CSV datasets from massive PCAP files."
    )
    parser.add_argument("-i", "--input", required=True, help="Path to the input .pcap file")
    parser.add_argument("-o", "--output", default="dataset_extended.csv", help="Path to the output .csv file")
    parser.add_argument("-t", "--target", required=True, help="Known infected IP address for labeling")

    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"[ERROR] Target file '{args.input}' not found.")
        sys.exit(1)

    extract_features_dpkt(args.input, args.output, args.target)