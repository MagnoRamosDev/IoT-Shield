# src/extractor.py
import argparse
import csv
import os
import socket
import dpkt
import binascii

def mac_addr(address):
    return ':'.join('%02x' % dpkt.compat.compat_ord(b) for b in address)

def run_ml_extraction(pcap_path, csv_path, infected_ip):
    print(f"[INFO] Extração TinyML Resiliente para: {pcap_path}")
    last_seen_time = {}
    packet_count, malicious_count, normal_count = 0, 0, 0
    error_count = 0
    
    try:
        f_in = open(pcap_path, 'rb')
        try:
            pcap = dpkt.pcap.Reader(f_in)
        except ValueError:
            f_in.seek(0)
            pcap = dpkt.pcapng.Reader(f_in)
            
        csv_dir = os.path.dirname(csv_path)
        if csv_dir:
            os.makedirs(csv_dir, exist_ok=True)
            
        with open(csv_path, mode='w', newline='') as out_file:
            csv_writer = csv.writer(out_file)
            csv_writer.writerow(['total_size_bytes', 'payload_size_bytes', 'ttl', 'is_tcp', 'is_udp', 'is_icmp', 'tcp_window', 'tcp_flag', 'iat_ms', 'label'])
            
            # Usamos um iterador manual para controlar as falhas no meio do ficheiro
            pcap_iter = iter(pcap)
            
            while True:
                try:
                    # Tenta ler o próximo pacote
                    ts, buf = next(pcap_iter)
                except StopIteration:
                    break # Fim natural do ficheiro
                except Exception as e:
                    error_count += 1
                    # Se houver erro de leitura (ex: pacote truncado ou corrompido)
                    # Imprimimos o erro e deixamos o dpkt tentar ler o próximo na iteração seguinte
                    # Nota: O dpkt avança o ponteiro do ficheiro internamente se falhar no buffer
                    print(f"  [AVISO] Pulando pacote corrompido no offset {f_in.tell()}: {e}")
                    continue

                packet_count += 1
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if not isinstance(eth.data, dpkt.ip.IP): continue
                    
                    ip = eth.data
                    src_ip_str = socket.inet_ntoa(ip.src)
                    
                    label = 1 if src_ip_str == infected_ip else 0
                    if label == 1: malicious_count += 1
                    else: normal_count += 1
                        
                    iat_ms = (ts - last_seen_time[src_ip_str]) * 1000.0 if src_ip_str in last_seen_time else 0.0
                    last_seen_time[src_ip_str] = ts
                    if len(last_seen_time) > 100000: last_seen_time.clear()
                        
                    is_tcp, is_udp, is_icmp = 0, 0, 0
                    tcp_window, tcp_flag_num, payload_size_bytes = 0, 0, 0
                    
                    if isinstance(ip.data, dpkt.tcp.TCP):
                        is_tcp, tcp_window, tcp_flag_num, payload_size_bytes = 1, ip.data.win, ip.data.flags, len(ip.data.data)
                    elif isinstance(ip.data, dpkt.udp.UDP):
                        is_udp, payload_size_bytes = 1, len(ip.data.data)
                    elif isinstance(ip.data, dpkt.icmp.ICMP):
                        is_icmp, payload_size_bytes = 1, len(ip.data.data)
                        
                    csv_writer.writerow([len(buf), payload_size_bytes, ip.ttl, is_tcp, is_udp, is_icmp, tcp_window, tcp_flag_num, f"{iat_ms:.4f}", label])
                except Exception:
                    # Erro na dissecação do pacote (estranho, mas possível se o buf estiver mal formado)
                    continue

    except Exception as e:
        print(f"\n[ERROR] Falha crítica no ficheiro {pcap_path}: {e}")
    finally:
        if 'f_in' in locals(): f_in.close()
        
    print(f"[SUCCESS] Extração Concluída: {packet_count:,} pacotes processados.")
    if error_count > 0:
        print(f"          ({error_count} pacotes corrompidos foram ignorados)")

def run_eda_extraction(pcap_path, output_dir, infected_ip):
    # Lógica similar aplicada ao EDA para garantir que o Data Science não pare
    print(f"[INFO] Extração Profunda (EDA) Resiliente para: {pcap_path}")
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        
    base_name = os.path.basename(pcap_path).replace('.pcap', '').replace('.pcapng', '')
    benign_path = os.path.join(output_dir, f"{base_name}_benign.csv")
    malicious_path = os.path.join(output_dir, f"{base_name}_malicious.csv")
    
    columns = ['timestamp', 'eth_src', 'eth_dst', 'ip_src', 'ip_dst', 'ip_len', 'ip_ttl', 'ip_proto', 'src_port', 'dst_port', 'tcp_seq', 'tcp_ack', 'tcp_flags', 'tcp_window', 'udp_len', 'icmp_type', 'icmp_code', 'payload_len', 'payload_hex']
    packet_count, error_count = 0, 0
    
    try:
        f_in = open(pcap_path, 'rb')
        try: pcap = dpkt.pcap.Reader(f_in)
        except ValueError:
            f_in.seek(0)
            pcap = dpkt.pcapng.Reader(f_in)
            
        with open(benign_path, 'w', newline='') as f_ben, open(malicious_path, 'w', newline='') as f_mal:
            writer_ben, writer_mal = csv.writer(f_ben), csv.writer(f_mal)
            writer_ben.writerow(columns)
            writer_mal.writerow(columns)
            
            pcap_iter = iter(pcap)
            while True:
                try:
                    ts, buf = next(pcap_iter)
                except StopIteration:
                    break
                except Exception as e:
                    error_count += 1
                    continue
                
                packet_count += 1
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if not isinstance(eth.data, dpkt.ip.IP): continue
                    ip = eth.data
                    src_ip_str = socket.inet_ntoa(ip.src)
                    dst_ip_str = socket.inet_ntoa(ip.dst)
                    
                    is_malicious = (src_ip_str == infected_ip)
                    active_writer = writer_mal if is_malicious else writer_ben
                    
                    src_port, dst_port, tcp_seq, tcp_ack, tcp_flags, tcp_window, udp_len, icmp_type, icmp_code = '', '', '', '', '', '', '', '', ''
                    payload_bytes = b''
                    
                    if isinstance(ip.data, dpkt.tcp.TCP):
                        src_port, dst_port, tcp_seq, tcp_ack, tcp_flags, tcp_window, payload_bytes = ip.data.sport, ip.data.dport, ip.data.seq, ip.data.ack, ip.data.flags, ip.data.win, bytes(ip.data.data)
                    elif isinstance(ip.data, dpkt.udp.UDP):
                        src_port, dst_port, udp_len, payload_bytes = ip.data.sport, ip.data.dport, ip.data.ulen, bytes(ip.data.data)
                    elif isinstance(ip.data, dpkt.icmp.ICMP):
                        icmp_type, icmp_code, payload_bytes = ip.data.type, ip.data.code, bytes(ip.data.data)

                    payload_hex = binascii.hexlify(payload_bytes).decode('utf-8') if payload_bytes else ''
                    active_writer.writerow([f"{ts:.6f}", mac_addr(eth.src), mac_addr(eth.dst), src_ip_str, dst_ip_str, ip.len, ip.ttl, ip.p, src_port, dst_port, tcp_seq, tcp_ack, tcp_flags, tcp_window, udp_len, icmp_type, icmp_code, len(payload_bytes), payload_hex])
                except Exception:
                    continue
    except Exception as e:
        print(f"\n[ERROR] Falha severa no EDA: {e}")
    finally:
        if 'f_in' in locals(): f_in.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Módulo de Extração de Features de Rede.")
    parser.add_argument("--mode", choices=["ml", "eda"], required=True, help="Modo de extração (TinyML ou Data Science)")
    parser.add_argument("-i", "--input", required=True, help="Caminho do PCAP")
    parser.add_argument("-o", "--output", required=True, help="Saída (Arquivo CSV para ml, Pasta para eda)")
    parser.add_argument("-t", "--target", required=True, help="IP Infectado (Botnet)")
    args = parser.parse_args()

    if args.mode == "ml": run_ml_extraction(args.input, args.output, args.target)
    elif args.mode == "eda": run_eda_extraction(args.input, args.output, args.target)