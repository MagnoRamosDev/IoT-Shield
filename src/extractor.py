import os
import glob
import multiprocessing
import dpkt
import socket
import numpy as np

class Welford:
    __slots__ = ['count', 'mean', 'm2', 'min_val', 'max_val']
    def __init__(self):
        self.count = 0
        self.mean = 0.0
        self.m2 = 0.0
        self.min_val = float('inf')
        self.max_val = float('-inf')

    def update(self, val):
        self.count += 1
        delta = val - self.mean
        self.mean += delta / self.count
        delta2 = val - self.mean
        self.m2 += delta * delta2
        if val < self.min_val:
            self.min_val = val
        if val > self.max_val:
            self.max_val = val

    def get_stats(self):
        if self.count == 0:
            return 0.0, 0.0, 0.0, 0.0
        variance = self.m2 / self.count if self.count > 1 else 0.0
        mi = self.min_val if self.count > 0 else 0.0
        ma = self.max_val if self.count > 0 else 0.0
        return float(mi), float(ma), float(self.mean), float(variance ** 0.5)

class FlowTracker:
    __slots__ = [
        'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'is_malicious',
        'start_time', 'last_time', 'first_s2d_time', 'last_s2d_time', 'first_d2s_time', 'last_d2s_time',
        'b_packets', 's2d_packets', 's2d_bytes', 'd2s_packets', 'd2s_bytes',
        'b_ps', 's2d_ps', 'd2s_ps', 'b_piat', 's2d_piat', 'd2s_piat'
    ]
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol, malicious_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.is_malicious = 1.0 if src_ip == malicious_ip else 0.0
        
        self.start_time = None
        self.last_time = None
        self.first_s2d_time = None
        self.last_s2d_time = None
        self.first_d2s_time = None
        self.last_d2s_time = None

        self.b_packets = 0
        self.s2d_packets = 0
        self.s2d_bytes = 0
        self.d2s_packets = 0
        self.d2s_bytes = 0

        self.b_ps = Welford()
        self.s2d_ps = Welford()
        self.d2s_ps = Welford()

        self.b_piat = Welford()
        self.s2d_piat = Welford()
        self.d2s_piat = Welford()

    def add_packet(self, pkg_src, pkg_time, pkg_size):
        if self.start_time is None:
            self.start_time = pkg_time
            self.first_s2d_time = pkg_time if pkg_src == self.src_ip else None
            self.first_d2s_time = pkg_time if pkg_src != self.src_ip else None

        direction = "s2d" if pkg_src == self.src_ip else "d2s"
        
        self.b_packets += 1
        self.b_ps.update(pkg_size)
        if self.last_time is not None:
            self.b_piat.update((pkg_time - self.last_time) * 1000.0)
        self.last_time = pkg_time

        if direction == "s2d":
            self.s2d_packets += 1
            self.s2d_bytes += pkg_size
            self.s2d_ps.update(pkg_size)
            if self.first_s2d_time is None:
                self.first_s2d_time = pkg_time
            if self.last_s2d_time is not None:
                self.s2d_piat.update((pkg_time - self.last_s2d_time) * 1000.0)
            self.last_s2d_time = pkg_time
        else:
            self.d2s_packets += 1
            self.d2s_bytes += pkg_size
            self.d2s_ps.update(pkg_size)
            if self.first_d2s_time is None:
                self.first_d2s_time = pkg_time
            if self.last_d2s_time is not None:
                self.d2s_piat.update((pkg_time - self.last_d2s_time) * 1000.0)
            self.last_d2s_time = pkg_time

    def export(self):
        b_dur = (self.last_time - self.start_time) * 1000.0 if self.start_time is not None else 0.0
        s2d_dur = (self.last_s2d_time - self.first_s2d_time) * 1000.0 if self.first_s2d_time is not None and self.last_s2d_time is not None else 0.0
        d2s_dur = (self.last_d2s_time - self.first_d2s_time) * 1000.0 if self.first_d2s_time is not None and self.last_d2s_time is not None else 0.0

        b_min_ps, b_max_ps, b_mean_ps, b_std_ps = self.b_ps.get_stats()
        s2d_min_ps, s2d_max_ps, s2d_mean_ps, s2d_std_ps = self.s2d_ps.get_stats()
        d2s_min_ps, d2s_max_ps, d2s_mean_ps, d2s_std_ps = self.d2s_ps.get_stats()

        b_min_piat, b_max_piat, b_mean_piat, b_std_piat = self.b_piat.get_stats()
        s2d_min_piat, s2d_max_piat, s2d_mean_piat, s2d_std_piat = self.s2d_piat.get_stats()
        d2s_min_piat, d2s_max_piat, d2s_mean_piat, d2s_std_piat = self.d2s_piat.get_stats()

        return [
            float(self.src_port),
            float(self.dst_port),
            float(self.protocol),
            b_dur, float(self.b_packets),
            s2d_dur, float(self.s2d_packets), float(self.s2d_bytes),
            d2s_dur, float(self.d2s_packets), float(self.d2s_bytes),
            b_min_ps, b_max_ps, b_mean_ps, b_std_ps,
            s2d_min_ps, s2d_max_ps, s2d_mean_ps, s2d_std_ps,
            d2s_min_ps, d2s_max_ps, d2s_mean_ps, d2s_std_ps,
            b_min_piat, b_max_piat, b_mean_piat, b_std_piat,
            s2d_min_piat, s2d_max_piat, s2d_mean_piat, s2d_std_piat,
            d2s_min_piat, d2s_max_piat, d2s_mean_piat, d2s_std_piat,
            self.is_malicious
        ]

def pcap_worker_task(args):
    pcap_path, malicious_ip, worker_id, max_flows, max_dict_size, tmp_dir = args
    if not os.path.exists(pcap_path):
        return
        
    print(f"Worker {worker_id} starting {pcap_path} with Malicious IP: {malicious_ip}")
    
    # Pre-allocate shared buffer RAM for THIS worker
    # 36 features, float32 -> ~144 bytes per flow
    buffer = np.zeros((max_flows, 36), dtype=np.float32)
    buffer_idx = 0
    chunk_counter = 0
    
    active_flows = {}
    
    try:
        with open(pcap_path, 'rb') as f:
            try:
                reader = dpkt.pcap.Reader(f)
            except ValueError:
                f.seek(0)
                reader = dpkt.pcapng.Reader(f)
            
            iterator = iter(reader)
            packet_count = 0
            
            while True:
                try:
                    ts, buf = next(iterator)
                except StopIteration:
                    break
                except Exception:
                    # Ignore corrupted packets that cannot be parsed by dpkt
                    continue
                
                packet_count += 1
                
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue
                    ip = eth.data
                    src_ip = socket.inet_ntoa(ip.src)
                    dst_ip = socket.inet_ntoa(ip.dst)
                    
                    protocol = ip.p
                    if isinstance(ip.data, dpkt.tcp.TCP) or isinstance(ip.data, dpkt.udp.UDP):
                        src_port = ip.data.sport
                        dst_port = ip.data.dport
                    else:
                        src_port = 0
                        dst_port = 0
                        
                    # Create generic bidirectional flow key
                    fwd_key = (src_ip, src_port, dst_ip, dst_port, protocol)
                    rev_key = (dst_ip, dst_port, src_ip, src_port, protocol)
                    
                    if fwd_key in active_flows:
                        flow_key = fwd_key
                    elif rev_key in active_flows:
                        flow_key = rev_key
                    else:
                        flow_key = fwd_key
                        # Force evict oldest to honor the strict RAM boundary
                        if len(active_flows) >= max_dict_size:
                            oldest_key = next(iter(active_flows))
                            oldest_tracker = active_flows.pop(oldest_key)
                            
                            features = oldest_tracker.export()
                            buffer[buffer_idx] = features
                            buffer_idx += 1
                            
                            # Dump numpy buffer to SSD seamlessly
                            if buffer_idx >= max_flows:
                                np.save(os.path.join(tmp_dir, f"w{worker_id}_c{chunk_counter}.npy"), buffer)
                                chunk_counter += 1
                                buffer_idx = 0
                                buffer.fill(0)
                        
                        active_flows[flow_key] = FlowTracker(src_ip, dst_ip, src_port, dst_port, protocol, malicious_ip)
                        
                    tracker = active_flows[flow_key]
                    
                    # Absolute time limit 1s
                    if tracker.start_time is not None and ts - tracker.start_time > 1.0:
                        # Flow expired, save it
                        features = tracker.export()
                        buffer[buffer_idx] = features
                        buffer_idx += 1
                        
                        # Start new flow
                        del active_flows[flow_key]
                        tracker = FlowTracker(src_ip, dst_ip, src_port, dst_port, protocol, malicious_ip)
                        active_flows[flow_key] = tracker
                        
                        # Buffer dump logic
                        if buffer_idx >= max_flows:
                            np.save(os.path.join(tmp_dir, f"w{worker_id}_c{chunk_counter}.npy"), buffer)
                            chunk_counter += 1
                            buffer_idx = 0
                            buffer.fill(0) # optional clear
                            
                    tracker.add_packet(src_ip, ts, len(buf))
                    
                    # Periodic eviction of old/stale flows to prevent unlimited RAM growth
                    if packet_count % 50000 == 0:
                        keys_to_delete = []
                        for k, t in active_flows.items():
                            if t.start_time is not None and ts - t.start_time > 1.0:
                                features = t.export()
                                buffer[buffer_idx] = features
                                buffer_idx += 1
                                keys_to_delete.append(k)
                                
                                if buffer_idx >= max_flows:
                                    np.save(os.path.join(tmp_dir, f"w{worker_id}_c{chunk_counter}.npy"), buffer)
                                    chunk_counter += 1
                                    buffer_idx = 0
                                    buffer.fill(0)
                        
                        for k in keys_to_delete:
                            del active_flows[k]
                            
                except Exception:
                    pass
                    
            # Export remaining active flows
            for tracker in active_flows.values():
                features = tracker.export()
                buffer[buffer_idx] = features
                buffer_idx += 1
                if buffer_idx >= max_flows:
                    np.save(os.path.join(tmp_dir, f"w{worker_id}_c{chunk_counter}.npy"), buffer)
                    chunk_counter += 1
                    buffer_idx = 0
                    buffer.fill(0)
                    
            # dump remaining
            if buffer_idx > 0:
                np.save(os.path.join(tmp_dir, f"w{worker_id}_c{chunk_counter}.npy"), buffer[:buffer_idx])
                
    except Exception as e:
        print(f"Error parsing pcap {pcap_path}: {e}")

def split_pcap_task(args):
    line, max_bytes, mb_size, splits_dir = args
    new_mapping = []
    line = line.strip()
    if not line:
        return new_mapping
        
    parts = line.split(" ")
    if len(parts) >= 2:
        pcap = parts[0]
        mal_ip = parts[1]
        
        if not os.path.exists(pcap):
            return new_mapping
            
        file_size = os.path.getsize(pcap)
        if file_size <= max_bytes:
            # No split needed for this tiny file
            new_mapping.append(f"{pcap} {mal_ip}\n")
            return new_mapping
            
        print(f"Splitting {pcap} ({file_size/1024/1024:.1f} MB) into chunks of {mb_size} MB...")
        base_name = os.path.basename(pcap).replace(".pcap", "").replace(".pcapng", "")
        
        try:
            f_in = open(pcap, 'rb')
            try:
                reader = dpkt.pcap.Reader(f_in)
            except ValueError:
                f_in.seek(0)
                reader = dpkt.pcapng.Reader(f_in)
                
            iterator = iter(reader)
            
            file_idx = 0
            current_bytes = 0
            writer = None
            f_out = None
            
            while True:
                try:
                    ts, buf = next(iterator)
                except StopIteration:
                    break
                except Exception:
                    continue
                    
                if writer is None:
                    out_name = f"{base_name}_part{file_idx}.pcap"
                    f_out_path = os.path.join(splits_dir, out_name)
                    f_out = open(f_out_path, 'wb')
                    writer = dpkt.pcap.Writer(f_out)
                    new_mapping.append(f"{f_out_path} {mal_ip}\n")
                    current_bytes = 0
                    
                writer.writepkt(buf, ts)
                current_bytes += len(buf)
                
                if current_bytes >= max_bytes:
                    f_out.close()
                    writer = None
                    file_idx += 1
                    
            if f_out is not None and not f_out.closed:
                f_out.close()
            f_in.close()
            
        except Exception as e:
            print(f"Error splitting {pcap}: {e}")
            new_mapping.append(f"{pcap} {mal_ip}\n") # fallback to original
            
    return new_mapping

def split_pcaps_if_needed(dataset_list_path, mb_size, tmp_dir, workers=4):
    """
    Splits very large PCAP files into multiple smaller ones (chunked by megabytes) 
    to ensure perfect load distribution among the workers.
    Returns the path to a new dataset mapping file.
    """
    splits_dir = os.path.join(tmp_dir, "splits")
    os.makedirs(splits_dir, exist_ok=True)
    new_dataset_list_path = os.path.join(tmp_dir, "datasets_list_split.txt")
    
    with open(dataset_list_path, 'r') as f:
        lines = f.readlines()
        
    max_bytes = mb_size * 1024 * 1024
    
    tasks = [(line, max_bytes, mb_size, splits_dir) for line in lines]
    new_mapping = []
    
    with multiprocessing.Pool(workers) as pool:
        results = pool.map(split_pcap_task, tasks)
        
    for res in results:
        new_mapping.extend(res)
                
    with open(new_dataset_list_path, 'w') as f_out:
        f_out.writelines(new_mapping)
        
    return new_dataset_list_path

def run_extraction(dataset_list_path, workers, max_ram_mb, tmp_dir):
    with open(dataset_list_path, 'r') as f:
        lines = f.readlines()
        
    tasks = []
    # 36 floats of 4 bytes = 144 bytes per flow
    bytes_per_flow = 144
    
    # Calculate how many flows we can fit in RAM PER WORKER
    # Reserve 20% for Python object overhead
    usable_ram_bytes = (max_ram_mb * 1024 * 1024) * 0.8
    ram_per_worker = usable_ram_bytes / max(workers, 1)
    
    # 40% RAM for Numpy Array (buffer)
    max_flows_per_worker = int((ram_per_worker * 0.4) / bytes_per_flow)
    if max_flows_per_worker < 1000:
        max_flows_per_worker = 1000 # Absolute minimum
        
    # 40% RAM strictly allocated for Python 'active_flows' dictionary objects
    # ~2KB expected per flow object and tracking nodes
    max_dict_size = int((ram_per_worker * 0.4) / 2000)
    if max_dict_size < 1000:
        max_dict_size = 1000
        
    worker_id = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        parts = line.split(" ")
        if len(parts) >= 2:
            pcap = parts[0]
            mal_ip = parts[1]
            tasks.append((pcap, mal_ip, worker_id, max_flows_per_worker, max_dict_size, tmp_dir))
            worker_id += 1

    print(f"Starting parsing with {workers} workers. Max flows array per worker: {max_flows_per_worker}, max dictionary size: {max_dict_size}")
    
    with multiprocessing.Pool(workers) as pool:
        pool.map(pcap_worker_task, tasks)
