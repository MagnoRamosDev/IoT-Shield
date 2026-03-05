# benchmark_model.py
import joblib
import time
import psutil
import os
import numpy as np

def run_benchmark():
    model_path = 'results/iot_shield_model.pkl'
    
    if not os.path.exists(model_path):
        print(f"[ERROR] Model '{model_path}' not found. Please train the model first.")
        return

    print("⏱️ Initiating IoT-Shield Benchmark...")
    process = psutil.Process(os.getpid())

    # 1. Memory Measurement (Pre-load)
    mem_before = process.memory_info().rss / (1024 * 1024)

    # 2. Model Loading
    start_load = time.time()
    model = joblib.load(model_path)
    load_time = time.time() - start_load
    
    mem_after = process.memory_info().rss / (1024 * 1024)
    model_size_ram = mem_after - mem_before

    # 3. Inference Speed Benchmark
    num_packets = 100000
    print(f"[INFO] Simulating inference for {num_packets:,} synthetic packets...")
    dummy_data = np.random.rand(num_packets, 9)
    
    start_inference = time.time()
    model.predict(dummy_data)
    total_inference_time = time.time() - start_inference
    
    avg_latency_ms = (total_inference_time / num_packets) * 1000
    estimated_throughput = int(num_packets / total_inference_time)

    # 4. Results Output
    print("\n" + "="*50)
    print("📊 BENCHMARK RESULTS")
    print("="*50)
    print(f"📁 Model RAM Footprint:     {model_size_ram:.2f} MB")
    print(f"⏱️ Load Time:               {load_time:.4f} seconds")
    print(f"⚡ Avg Latency per Packet:  {avg_latency_ms:.6f} ms")
    print(f"🚀 Estimated Throughput:    {estimated_throughput:,} packets/s")
    print("="*50)
    
    if avg_latency_ms < 0.1:
        print("✅ Conclusion: Excellent performance for Real-Time IDS architectures.")
    else:
        print("⚠️ Warning: Latency may be too high for 1Gbps network links.")

if __name__ == "__main__":
    run_benchmark()