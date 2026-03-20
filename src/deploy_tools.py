# src/deploy_tools.py
import os
import time
import joblib
import argparse
import psutil
import numpy as np
import m2cgen as m2c

def export_model_to_c(model_path, output_c_path):
    if not os.path.exists(model_path):
        print(f"[ERROR] Modelo '{model_path}' não encontrado. Treine-o primeiro.")
        return

    print(f"[INFO] Carregando modelo treinado: {model_path}...")
    model = joblib.load(model_path)

    print("[INFO] Transpilando o modelo de IA para código C (Isso pode demorar um pouco)...")
    c_code = m2c.export_to_c(model)

    os.makedirs(os.path.dirname(output_c_path), exist_ok=True)
    with open(output_c_path, "w") as f:
        f.write("#include <string.h>\n\n")
        f.write(c_code)

    print(f"[SUCCESS] Modelo C-Native exportado para: '{output_c_path}'.")

def run_python_benchmark(model_path, num_packets):
    if not os.path.exists(model_path):
        print(f"[ERROR] Modelo '{model_path}' não encontrado.")
        return

    print(f"⏱️ Iniciando Benchmark Python (Software) para: {os.path.basename(model_path)}")
    process = psutil.Process(os.getpid())

    # 1. Medição de Memória (Pré-load)
    mem_before = process.memory_info().rss / (1024 * 1024)

    # 2. Carregamento do Modelo
    start_load = time.time()
    model = joblib.load(model_path)
    load_time = time.time() - start_load
    
    mem_after = process.memory_info().rss / (1024 * 1024)
    model_size_ram = mem_after - mem_before

    # 3. Benchmark de Velocidade de Inferência
    print(f"[INFO] Simulando inferência para {num_packets:,} pacotes sintéticos...")
    dummy_data = np.random.rand(num_packets, 9)
    
    start_inference = time.time()
    model.predict(dummy_data)
    total_inference_time = time.time() - start_inference
    
    avg_latency_ms = (total_inference_time / num_packets) * 1000
    estimated_throughput = int(num_packets / total_inference_time) if total_inference_time > 0 else 0

    # 4. Saída de Resultados
    print("\n" + "="*50)
    print("📊 RESULTADOS DO BENCHMARK (PYTHON - SOFTWARE)")
    print("="*50)
    print(f"📁 Consumo de RAM do Modelo: {model_size_ram:.2f} MB")
    print(f"⏱️ Tempo de Carregamento:    {load_time:.4f} segundos")
    print(f"⚡ Latência Média p/ Pacote: {avg_latency_ms:.6f} ms")
    print(f"🚀 Throughput Estimado:      {estimated_throughput:,} pacotes/s")
    print("="*50)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ferramentas de Deploy e Benchmark do IoT-Shield.")
    parser.add_argument("--mode", choices=["export", "benchmark"], required=True, help="Modo de operação")
    parser.add_argument("--model", required=True, help="Caminho para o arquivo .pkl do modelo")
    parser.add_argument("--output-c", default="results/iot_model.c", help="Caminho de saída para o C")
    parser.add_argument("--packets", type=int, default=100000, help="Número de pacotes para simular")
    
    args = parser.parse_args()

    if args.mode == "export":
        export_model_to_c(args.model, args.output_c)
    elif args.mode == "benchmark":
        run_python_benchmark(args.model, args.packets)