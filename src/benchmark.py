import os
import time
import ctypes
import joblib
import pandas as pd
import numpy as np
from src.dashboard import print_ui, print_table
from rich.table import Table

def run_benchmark(out_dir="results", samples=10000):
    model_path = os.path.join(out_dir, "rf_model.pkl")
    c_path = os.path.join(out_dir, "iot_shield_model.c")
    so_path = os.path.join(out_dir, "iot_shield_model.so")
    test_csv = os.path.join(out_dir, "test.csv")
    
    if not os.path.exists(model_path) or not os.path.exists(c_path) or not os.path.exists(test_csv):
        print_ui("[bold red][!] Benchmark requires trained model, C code, and test.csv.[/bold red]")
        return
        
    print_ui("[bold cyan][*] Compiling C model to shared library for benchmarking...[/bold cyan]")
    
    wrapper_c = os.path.join(out_dir, "benchmark_wrapper.c")
    with open(wrapper_c, "w") as f:
        f.write("""
extern void score(double * input, double * output);
void benchmark_batch(double * inputs, double * outputs, int n_samples, int n_features) {
    for (int i = 0; i < n_samples; i++) {
        score(&inputs[i * n_features], &outputs[i * 2]);
    }
}
""")
    # Compile the C code with -O3 for maximum performance
    ret = os.system(f"gcc -O3 -shared -fPIC {c_path} {wrapper_c} -o {so_path}")
    if ret != 0:
        print_ui("[bold red][!] Failed to compile C model.[/bold red]")
        return
        
    print_ui("[bold cyan][*] Loading test data...[/bold cyan]")
    df = pd.read_csv(test_csv)
    
    # === Feature Engineering (replicated from trainer) ===
    if "src2dst_stddev_ps" in df.columns:
        df["is_constant_payload"] = (df["src2dst_stddev_ps"] < 1.0).astype(float)

    if "src2dst_concurrent_flows" in df.columns and "bidirectional_duration_ms" in df.columns:
        dur_sec = df["bidirectional_duration_ms"].replace(0, 1.0) / 1000.0
        df["src2dst_flow_rate"] = (df["src2dst_concurrent_flows"] / dur_sec).clip(upper=2000)

    if "src2dst_packets" in df.columns and "dst2src_packets" in df.columns:
        dst_pkts = df["dst2src_packets"].replace(0, 1.0)
        df["in_out_packet_ratio"] = (df["src2dst_packets"] / dst_pkts).clip(upper=100)

    if "src2dst_syn_packets" in df.columns and "src2dst_packets" in df.columns:
        src_pkts = df["src2dst_packets"].replace(0, 1.0)
        df["syn_to_total_ratio"] = df["src2dst_syn_packets"] / src_pkts

    if "protocol" in df.columns and "dst_port" in df.columns:
        discovery_ports = [1900, 5353, 137, 138, 67, 68]
        is_disc = (df["protocol"] == 17) & (df["dst_port"].isin(discovery_ports))
        df["is_discovery_protocol"] = is_disc.astype(float)
        
    concurrent_features = ["src2dst_concurrent_flows", "dst2src_concurrent_flows", "bidirectional_concurrent_flows"]
    for col in concurrent_features:
        if col in df.columns:
            df[col] = df[col].clip(upper=10)
    # ===================================================

    print_ui("[bold cyan][*] Loading Python model...[/bold cyan]")
    rf = joblib.load(model_path)
    
    with open(os.path.join(out_dir, "feature_names.txt"), "r") as f:
        feature_names = f.read().split(",")
        
    X_df = df[feature_names]
    X = X_df.values
        
    # Limit to N samples
    if len(X) > samples:
        X = X[:samples]
    else:
        samples = len(X)
        
    X_c = np.ascontiguousarray(X, dtype=np.float64)
    
    print_ui(f"[bold cyan][*] Benchmarking Python on {samples} flows...[/bold cyan]")
    # Warmup
    _ = rf.predict_proba(X[:10])
    
    start_py = time.perf_counter()
    _ = rf.predict_proba(X)
    end_py = time.perf_counter()
    time_py = end_py - start_py
    
    print_ui(f"[bold cyan][*] Benchmarking Native C on {samples} flows...[/bold cyan]")
    
    # Load the shared library
    c_lib = ctypes.CDLL(os.path.abspath(so_path))
    
    # void benchmark_batch(double * inputs, double * outputs, int n_samples, int n_features)
    c_lib.benchmark_batch.argtypes = [
        ctypes.POINTER(ctypes.c_double), 
        ctypes.POINTER(ctypes.c_double),
        ctypes.c_int,
        ctypes.c_int
    ]
    c_lib.benchmark_batch.restype = None
    
    n_features = X_c.shape[1]
    output_array = (ctypes.c_double * (samples * 2))()
    input_array = X_c.ctypes.data_as(ctypes.POINTER(ctypes.c_double))
    
    # Warmup
    c_lib.benchmark_batch(input_array, output_array, min(10, samples), n_features)
    
    start_c = time.perf_counter()
    c_lib.benchmark_batch(input_array, output_array, samples, n_features)
    end_c = time.perf_counter()
    time_c = end_c - start_c
    
    speedup = time_py / time_c if time_c > 0 else float('inf')
    
    table = Table(title="Inference Benchmark (Python vs Native C)", show_header=True, header_style="bold yellow")
    table.add_column("Environment", style="cyan")
    table.add_column("Total Time (s)", justify="right")
    table.add_column("Throughput (flows/s)", justify="right", style="green")
    table.add_column("Latency per flow (µs)", justify="right")
    table.add_column("Speedup", justify="right", style="magenta")
    
    py_tps = samples / time_py
    c_tps = samples / time_c
    
    py_lat = (time_py / samples) * 1_000_000
    c_lat = (time_c / samples) * 1_000_000
    
    table.add_row("Python (scikit-learn)", f"{time_py:.4f}s", f"{py_tps:,.0f}", f"{py_lat:.2f} µs", "1.00x")
    table.add_row("C Firmware (m2cgen)", f"{time_c:.4f}s", f"{c_tps:,.0f}", f"{c_lat:.2f} µs", f"{speedup:.2f}x")
    
    print_ui("\n")
    print_table(table)
    
    # ========================================================
    # END-TO-END BENCHMARK (Sniffer + AI)
    # ========================================================
    bench_pcap = os.path.join(out_dir, "benchmark.pcap")
    if os.path.exists(bench_pcap):
        print_ui("\n[bold cyan][*] Running End-to-End Sniffer+AI Benchmark on benchmark.pcap...[/bold cyan]")
        import subprocess
        import re
        
        def run_with_time(cmd):
            res = subprocess.run(["/usr/bin/time", "-v"] + cmd, capture_output=True, text=True)
            output = res.stderr
            
            elapsed = 0.0
            cpu = "0%"
            ram_kb = 0
            
            # Regex parse
            el_m = re.search(r"Elapsed \(wall clock\) time.*?:\s+(.*)", output)
            if el_m:
                time_str = el_m.group(1).strip()
                if ":" in time_str:
                    parts = time_str.split(":")
                    if len(parts) == 2:
                        elapsed = float(parts[0]) * 60 + float(parts[1])
                    elif len(parts) == 3:
                        elapsed = float(parts[0]) * 3600 + float(parts[1]) * 60 + float(parts[2])
            
            cpu_m = re.search(r"Percent of CPU this job got:\s+(.*)", output)
            if cpu_m: cpu = cpu_m.group(1).strip()
                
            ram_m = re.search(r"Maximum resident set size \(kbytes\):\s+(\d+)", output)
            if ram_m: ram_kb = int(ram_m.group(1))
            
            return elapsed, cpu, ram_kb / 1024.0 # MB

        # 1. Prepare Python E2E script
        py_e2e_path = os.path.join(out_dir, "py_e2e.py")
        with open(py_e2e_path, "w") as f:
            f.write(f"""
import os, joblib, numpy as np, pandas as pd
from src.extractor import pcap_worker_task
pcap_worker_task(('{bench_pcap}', '0.0.0.0', 999, 50000, 10000, '{out_dir}'))
npy_path = os.path.join('{out_dir}', 'part_999_0.npy')
if os.path.exists(npy_path):
    py_flows = np.load(npy_path)
    X_py = np.ascontiguousarray(py_flows[:, :17], dtype=np.float64) # simplistic feature emulation
    rf = joblib.load(os.path.join('{out_dir}', 'rf_model.pkl'))
    _ = rf.predict_proba(X_py)
    os.remove(npy_path)
""")
        
        # 2. Benchmark Python End-to-End
        time_e2e_py, cpu_py, ram_py = run_with_time(["./venv/bin/python", py_e2e_path])
        
        # 3. Benchmark C End-to-End
        c_sniffer = os.path.join(out_dir, "iot_shield_sniffer")
        time_e2e_c, cpu_c, ram_c = run_with_time([c_sniffer, bench_pcap])
        
        # 4. Benchmark C Emulated OpenWRT Router (1GHz, 128MB)
        # 1GHz is roughly 25% of a modern 4GHz core. We use systemd-run to apply cgroups limit.
        emulated_cmd = [
            "systemd-run", "--user", "--scope", "-q", 
            "-p", "CPUQuota=25%", "-p", "MemoryMax=128M"
        ]
        time_e2e_emu, cpu_emu, ram_emu = run_with_time(emulated_cmd + [c_sniffer, bench_pcap])
        
        # Avoid division by zero
        time_e2e_py = max(time_e2e_py, 0.0001)
        time_e2e_c = max(time_e2e_c, 0.0001)
        time_e2e_emu = max(time_e2e_emu, 0.0001)
        
        e2e_speedup = time_e2e_py / time_e2e_c
        emu_speedup = time_e2e_py / time_e2e_emu
        
        # Contagem de pacotes com tcpdump para a tabela
        pkt_count = 50000 # tcpdump extraiu 50k
        py_e2e_tps = pkt_count / time_e2e_py
        c_e2e_tps = pkt_count / time_e2e_c
        emu_e2e_tps = pkt_count / time_e2e_emu
        
        py_e2e_lat = (time_e2e_py / pkt_count) * 1000000
        c_e2e_lat = (time_e2e_c / pkt_count) * 1000000
        emu_e2e_lat = (time_e2e_emu / pkt_count) * 1000000
        
        e2e_table = Table(title="End-to-End Pipeline (Sniffer + Inference)", show_header=True, header_style="bold yellow")
        e2e_table.add_column("Environment", style="cyan")
        e2e_table.add_column("Latency/Pkt", justify="right")
        e2e_table.add_column("CPU %", justify="right", style="yellow")
        e2e_table.add_column("RAM (MB)", justify="right", style="red")
        e2e_table.add_column("Throughput (Pkts/s)", justify="right", style="green")
        e2e_table.add_column("Speedup", justify="right", style="magenta")
        
        e2e_table.add_row("Python (Scapy+ML)", f"{py_e2e_lat:.2f} µs", cpu_py, f"{ram_py:.1f} MB", f"{py_e2e_tps:,.0f}", "1.00x")
        e2e_table.add_row("C Firmware (Nativo)", f"{c_e2e_lat:.2f} µs", cpu_c, f"{ram_c:.1f} MB", f"{c_e2e_tps:,.0f}", f"{e2e_speedup:.2f}x")
        e2e_table.add_row("C Emulado (1GHz/128MB)", f"{emu_e2e_lat:.2f} µs", cpu_emu, f"{ram_emu:.1f} MB", f"{emu_e2e_tps:,.0f}", f"{emu_speedup:.2f}x")
        
        print_ui("\n")
        print_table(e2e_table)

    print_ui("\n[bold green][+] Benchmark Completed![/bold green]")
