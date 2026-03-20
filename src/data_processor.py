# src/data_processor.py
import os
import glob
import argparse
import random
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import binascii

# ==========================================
# FUNÇÕES DE MERGE E AMOSTRAGEM
# ==========================================
def merge_csvs(file_pattern, output_path):
    files = [f for f in glob.glob(file_pattern) if os.path.basename(output_path) not in f]
    if not files: return
    print(f"[INFO] Unificando {len(files)} ficheiros em {os.path.basename(output_path)}...")
    with open(output_path, 'w', encoding='utf-8') as fout:
        for i, filepath in enumerate(files):
            with open(filepath, 'r', encoding='utf-8') as fin:
                header = fin.readline()
                if i == 0: fout.write(header) 
                for line in fin: fout.write(line)

def cleanup_fragments(directory, keep_files):
    removed = 0
    for f in glob.glob(os.path.join(directory, "*.csv")):
        if os.path.basename(f) not in keep_files:
            os.remove(f)
            removed += 1
    print(f"[SUCCESS] {removed} ficheiros temporários apagados.")

def create_sample(input_file, output_file, target_mb):
    if not os.path.exists(input_file): return
    target_bytes = target_mb * 1024 * 1024
    total_bytes = os.path.getsize(input_file)
    keep_prob = 1.0 if total_bytes <= target_bytes else target_bytes / total_bytes
    
    print(f"⏳ Processando amostra ({keep_prob:.2%}): {os.path.basename(input_file)}")
    with open(input_file, 'r', encoding='utf-8') as fin, open(output_file, 'w', encoding='utf-8') as fout:
        fout.write(fin.readline())
        for line in fin:
            if random.random() <= keep_prob: fout.write(line)

# ==========================================
# FUNÇÕES DE ANÁLISE EXPLORATÓRIA (EDA)
# ==========================================
def load_and_merge(benign_path, malicious_path):
    print("[INFO] Carregando as amostras de dados...")
    df_benign = pd.read_csv(benign_path)
    df_malicious = pd.read_csv(malicious_path)
    
    df_benign['class'] = 'Benigno'
    df_malicious['class'] = 'Maligno (Mirai)'
    
    df_full = pd.concat([df_benign, df_malicious], ignore_index=True)
    df_full.fillna({'src_port': -1, 'dst_port': -1, 'payload_len': 0, 'payload_hex': ''}, inplace=True)
    
    df_full['timestamp'] = pd.to_numeric(df_full['timestamp'], errors='coerce')
    df_full = df_full.sort_values(by='timestamp')
    
    print(f"[SUCCESS] Dataset unificado: {len(df_full):,} pacotes.\n")
    return df_full

def generate_eda_plots(df, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    sns.set_theme(style="whitegrid")
    print("[INFO] Gerando gráficos de rede (Metadados)...")

    plt.figure(figsize=(8, 6))
    sns.countplot(data=df, x='ip_proto', hue='class', palette={'Benigno': '#2ecc71', 'Maligno (Mirai)': '#e74c3c'})
    plt.title('Distribuição de Protocolos (6=TCP, 17=UDP, 1=ICMP)')
    plt.yscale('log')
    plt.ylabel('Contagem (Log)')
    plt.xlabel('Protocolo IP')
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, '01_protocol_distribution.png'), dpi=300)
    plt.close()

    plt.figure(figsize=(12, 6))
    df_ports = df[df['dst_port'] != -1]
    top_ports = df_ports['dst_port'].value_counts().nlargest(10).index
    df_top_ports = df_ports[df_ports['dst_port'].isin(top_ports)]
    sns.countplot(data=df_top_ports, x='dst_port', hue='class', order=top_ports, palette={'Benigno': '#2ecc71', 'Maligno (Mirai)': '#e74c3c'})
    plt.title('Top 10 Portas de Destino (Alvos de Ataque)')
    plt.yscale('log')
    plt.ylabel('Contagem (Log)')
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, '02_top_dst_ports.png'), dpi=300)
    plt.close()

def hex_to_ascii(hex_str):
    if not isinstance(hex_str, str) or hex_str == '':
        return None
    try:
        raw_bytes = binascii.unhexlify(hex_str.strip())
        return "".join([chr(b) if 32 <= b <= 126 else '.' for b in raw_bytes])
    except Exception:
        return None

def analyze_correlated_signatures(df, output_dir):
    print("[INFO] Extraindo Assinaturas e Calculando Frequência Temporal...")
    df_p = df[df['payload_len'] > 0].copy()
    if df_p.empty:
        print("[WARNING] Nenhum pacote com payload encontrado.")
        return

    proto_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
    df_p['proto_name'] = df_p['ip_proto'].map(lambda x: proto_map.get(x, f"Outro({x})"))
    df_p['payload_ascii'] = df_p['payload_hex'].apply(hex_to_ascii)
    df_p.dropna(subset=['payload_ascii'], inplace=True)

    group_cols = ['class', 'ip_src', 'ip_dst', 'proto_name', 'dst_port', 'ip_ttl', 'payload_len', 'payload_ascii']
    
    signatures = df_p.groupby(group_cols).agg(
        packet_count=('timestamp', 'size'),
        first_seen=('timestamp', 'min'),
        last_seen=('timestamp', 'max')
    ).reset_index()

    signatures['duration_sec'] = signatures['last_seen'] - signatures['first_seen']
    
    def calc_metrics(row):
        count = row['packet_count']
        duration = row['duration_sec']
        if duration > 86400: return pd.Series([0, 0, True]) 
        if duration > 0 and count > 1:
            return pd.Series([count / duration, (duration / (count - 1)) * 1000, False])
        return pd.Series([0, 0, False])

    signatures[['pkts_per_sec', 'avg_interval_ms', 'mixed_pcaps']] = signatures.apply(calc_metrics, axis=1)
    signatures = signatures.sort_values(by='packet_count', ascending=False)

    report_path = os.path.join(output_dir, '03_correlated_signatures_report.txt')
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write("=========================================================\n")
        f.write("🛡️  RELATÓRIO DE ASSINATURAS CORRELACIONADAS (IoT-Shield)\n")
        f.write("=========================================================\n\n")

        for class_name in ['Maligno (Mirai)', 'Benigno']:
            f.write(f"\n{'='*60}\n")
            f.write(f">>> TOP 15 FLUXOS CORRELACIONADOS: {class_name.upper()} <<<\n")
            f.write(f"{'='*60}\n\n")
            
            top_sigs = signatures[signatures['class'] == class_name].head(15)
            if top_sigs.empty:
                f.write("Nenhuma assinatura com payload encontrada para esta classe.\n")
                continue

            for idx, row in top_sigs.iterrows():
                f.write(f"🔥 ASSINATURA REPETIDA {row['packet_count']:,} VEZES\n")
                f.write(f"   ├─ Atacante/Origem: {row['ip_src']}\n")
                f.write(f"   ├─ Alvo/Destino:    {row['ip_dst']} (Porta: {row['dst_port']})\n")
                f.write(f"   ├─ Metadados:       Proto: {row['proto_name']} | TTL: {row['ip_ttl']} | Tamanho: {row['payload_len']} bytes\n")
                if row['mixed_pcaps']: f.write(f"   ├─ Frequência:      [Aviso] Pacotes espalhados em capturas de dias diferentes.\n")
                elif row['packet_count'] == 1: f.write(f"   ├─ Frequência:      Pacote único.\n")
                else:
                    f.write(f"   ├─ Frequência:      {row['pkts_per_sec']:,.2f} pacotes/segundo\n")
                    f.write(f"   ├─ Intervalo:       Um pacote enviado a cada {row['avg_interval_ms']:,.2f} ms\n")
                
                payload_text = row['payload_ascii']
                if len(payload_text) > 80: payload_text = payload_text[:80] + " ... [TRUNCADO]"
                f.write(f"   └─ Payload:         {payload_text}\n")
                f.write("-" * 60 + "\n")
    print(f"[SUCCESS] Relatório de correlação salvo em: {report_path}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Módulo de Processamento e Análise de Dados EDA.")
    parser.add_argument("--mode", choices=["merge", "sample", "analyze", "balance", "merge_ml"], required=True, help="Modo de operação")
    
    # Argumentos para merge/sample
    parser.add_argument("--dir", default="data/datasets/eda", help="Diretório alvo")
    parser.add_argument("--mb", type=float, default=100.0, help="Tamanho em MB (para modo sample)")
    
    # Argumentos para analyze
    parser.add_argument("--benign", default="data/datasets/eda/sample_benign.csv", help="Amostra benigna")
    parser.add_argument("--malicious", default="data/datasets/eda/sample_malicious.csv", help="Amostra maligna")
    parser.add_argument("--outdir", default="results/eda_plots", help="Pasta para resultados gráficos")
    
    args = parser.parse_args()
    
    benign_full, malicious_full = os.path.join(args.dir, "full_benign.csv"), os.path.join(args.dir, "full_malicious.csv")
    
    if args.mode == "merge":
        print("=========================================================")
        print("🧹 IoT-Shield: Unificador de Datasets EDA")
        print("=========================================================\n")
        merge_csvs(os.path.join(args.dir, "*_benign.csv"), benign_full)
        merge_csvs(os.path.join(args.dir, "*_malicious.csv"), malicious_full)
        cleanup_fragments(args.dir, keep_files=["full_benign.csv", "full_malicious.csv"])
        
    elif args.mode == "sample":
        print("=========================================================")
        print(f"🎲 IoT-Shield: Amostragem Aleatória para EDA ({args.mb} MB)")
        print("=========================================================\n")
        create_sample(benign_full, os.path.join(args.dir, "sample_benign.csv"), args.mb)
        create_sample(malicious_full, os.path.join(args.dir, "sample_malicious.csv"), args.mb)
        
    elif args.mode == "analyze":
        print("=========================================================")
        print("📈 IoT-Shield: Análise de Dados e Correlação de Fluxos")
        print("=========================================================\n")
        if not os.path.exists(args.benign) or not os.path.exists(args.malicious):
            print("[ERROR] Ficheiros de amostra não encontrados. Corra o modo 'sample' primeiro.")
        else:
            df_combined = load_and_merge(args.benign, args.malicious)
            generate_eda_plots(df_combined, args.outdir)
            analyze_correlated_signatures(df_combined, args.outdir)
            print("✅ Análise concluída com sucesso!")
            
    # ========================================================
    # NOVOS MODOS PARA MACHINE LEARNING (POOL GLOBAL)
    # ========================================================
    elif args.mode == "merge_ml":
        print("=========================================================")
        print("🗂️ IoT-Shield: Criando Pool Global de PCAPs")
        print("=========================================================\n")
        os.makedirs("data/datasets/unified/train", exist_ok=True)
        os.makedirs("data/datasets/unified/test", exist_ok=True)
        
        merge_csvs("data/datasets/train/*.csv", "data/datasets/unified/train/global_train.csv")
        merge_csvs("data/datasets/test/*.csv", "data/datasets/unified/test/global_test.csv")
        print("\n[SUCCESS] Todos os PCAPs foram unidos num Pool Global!")

    elif args.mode == "balance":
        print("=========================================================")
        print("⚖️ IoT-Shield: Motor de Balanceamento Global (C-Core)")
        print("=========================================================\n")
        
        c_source = "src/fast_balancer.c"
        c_binary = "results/fast_balancer"
        
        if not os.path.exists(c_binary):
            print(f"[INFO] Compilando motor C de alta performance ({c_source})...")
            os.makedirs("results", exist_ok=True)
            os.system(f"gcc -O3 {c_source} -o {c_binary}")
            
        os.makedirs("data/datasets/balanced/train", exist_ok=True)
        os.makedirs("data/datasets/balanced/test", exist_ok=True)
        
        train_in = "data/datasets/unified/train/global_train.csv"
        train_out = "data/datasets/balanced/train/balanced_train.csv"
        if os.path.exists(train_in):
            print(f"⏳ Balanceando Global Train: {train_in}")
            os.system(f"./{c_binary} {train_in} {train_out} 1.0")
            
        test_in = "data/datasets/unified/test/global_test.csv"
        test_out = "data/datasets/balanced/test/balanced_test.csv"
        if os.path.exists(test_in):
            print(f"⏳ Balanceando Global Test: {test_in}")
            os.system(f"./{c_binary} {test_in} {test_out} 1.0")
            
        print("\n[SUCCESS] Datasets globais balanceados na velocidade nativa do hardware!")