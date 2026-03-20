# src/model_pipeline.py
import os
import time
import joblib
import argparse
import glob
import psutil
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix

def optimize_dtypes(df):
    """
    O grande segredo contra o OOM Killer do Linux:
    Reduz o uso de RAM do DataFrame em mais de 60% rebaixando os tipos.
    """
    for col in df.columns:
        if df[col].dtype == 'float64':
            df[col] = pd.to_numeric(df[col], downcast='float')
        elif df[col].dtype == 'int64':
            df[col] = pd.to_numeric(df[col], downcast='integer')
    return df

def load_ram_safe(folder_path, max_ram_mb):
    """
    Carrega os dados em pedaços e monitora a RAM ativamente.
    Reserva 30% da RAM para os dados e 70% para as cópias internas do Random Forest.
    """
    print(f"  -> Carregando base de: {folder_path} (Limite Alocado: {max_ram_mb} MB)")
    
    # 30% de margem ultraconservadora para a leitura inicial
    memory_limit_bytes = (max_ram_mb * 0.30) * 1024 * 1024
    process = psutil.Process(os.getpid())
    
    all_files = glob.glob(os.path.join(folder_path, "*.csv"))
    if not all_files: return None
    
    df_list = []
    total_rows = 0
    hit_limit = False
    
    for file in all_files:
        if hit_limit: break
        
        # Lê em pedaços de 200 mil para verificação de RAM mais frequente
        chunk_iterator = pd.read_csv(file, chunksize=200000)
        
        for chunk in chunk_iterator:
            # Otimiza o pedaço antes mesmo de guardá-lo na RAM definitiva
            chunk = optimize_dtypes(chunk)
            df_list.append(chunk)
            total_rows += len(chunk)
            
            # Checa o consumo atual real
            current_mem = process.memory_info().rss
            
            if current_mem >= memory_limit_bytes:
                print(f"  ⚠️  Alerta de RAM: Consumo seguro atingido ({current_mem / 1024 / 1024:.0f} MB).")
                print(f"  ⚠️  Abortando a leitura extra. {total_rows:,} pacotes carregados.")
                hit_limit = True
                break

    print(f"  -> Juntando as tabelas... (Isto pode dar um leve pico de RAM)")
    combined_df = pd.concat(df_list, ignore_index=True)
    combined_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    combined_df.fillna(0, inplace=True)
    
    # Passa o otimizador uma última vez por garantia
    combined_df = optimize_dtypes(combined_df)
    
    final_ram_mb = process.memory_info().rss / 1024 / 1024
    print(f"  -> Dataset pronto na RAM: {final_ram_mb:.0f} MB ocupados.")
    return combined_df

def plot_academic_graphs(model, feature_names, y_true, y_pred, results_dir="results"):
    print("[INFO] Gerando gráficos acadêmicos...")
    importances = model.feature_importances_
    indices = np.argsort(importances)
    plt.figure(figsize=(10, 6))
    sns.set_theme(style="whitegrid")
    bars = plt.barh(range(len(indices)), importances[indices], color='steelblue', align='center')
    plt.yticks(range(len(indices)), [feature_names[i] for i in indices])
    plt.xlabel('Importância Relativa')
    plt.title('TinyML Edge Detection: Importância das Features', fontsize=14, pad=15)
    for bar in bars: plt.text(bar.get_width() + 0.01, bar.get_y() + bar.get_height()/2, f'{bar.get_width()*100:.2f}%', va='center')
    plt.tight_layout()
    plt.savefig(os.path.join(results_dir, "plot_feature_importance.png"), dpi=300)
    plt.close()

    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(8, 6))
    sns.set_theme(style="white")
    ax = sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', cbar=False, annot_kws={"size": 14})
    ax.set_title('Avaliação do Modelo: Matriz de Confusão', fontsize=14, pad=15)
    ax.xaxis.set_ticklabels(['Benigno (0)', 'Botnet (1)'])
    ax.yaxis.set_ticklabels(['Benigno (0)', 'Botnet (1)'])
    plt.tight_layout()
    plt.savefig(os.path.join(results_dir, "plot_confusion_matrix.png"), dpi=300)
    plt.close()

def run_pipeline(train_dir, test_dir, output_model, n_estimators, max_depth, max_ram_mb):
    feature_cols = ['total_size_bytes', 'payload_size_bytes', 'ttl', 'is_tcp', 'is_udp', 'is_icmp', 'tcp_window', 'tcp_flag', 'iat_ms']

    print(f"[1/3] Preparando ambiente de treinamento...")
    train_df = load_ram_safe(train_dir, max_ram_mb)
    if train_df is None: return
    
    print(f"\n[2/3] Treinando Random Forest ({n_estimators} árvores, Profundidade: {max_depth})...")
    start_time = time.time()
    
    # REMOVIDO n_jobs=-1 PARA EVITAR EXPLOSÃO DE RAM POR MULTIPROCESSAMENTO!
    # n_jobs=1 (padrão) força o treinamento sequencial e seguro.
    rf_model = RandomForestClassifier(n_estimators=n_estimators, max_depth=max_depth, random_state=42)
    rf_model.fit(train_df[feature_cols], train_df['label'])
    
    # Libera a memória do dataset de treino ativamente antes de carregar o teste
    del train_df 
    
    os.makedirs(os.path.dirname(output_model), exist_ok=True)
    joblib.dump(rf_model, output_model)
    print(f"[SUCCESS] Modelo treinado e salvo em {time.time() - start_time:.2f} segundos.")

    if test_dir:
        print("\n[3/3] Avaliando nos Dados de Teste...")
        test_df = load_ram_safe(test_dir, max_ram_mb)
        if test_df is not None:
            y_true, y_pred = test_df['label'], rf_model.predict(test_df[feature_cols])
            print(f"Acurácia Global: {accuracy_score(y_true, y_pred):.4f}")
            plot_academic_graphs(rf_model, feature_cols, y_true, y_pred, os.path.dirname(output_model))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Treina e Avalia o modelo IoT-Shield.")
    parser.add_argument("--train-dir", required=True)
    parser.add_argument("--test-dir", default=None)
    parser.add_argument("--output", default="results/iot_shield_model.pkl")
    parser.add_argument("--estimators", type=int, default=15)
    parser.add_argument("--depth", type=int, default=8)
    parser.add_argument("--max-ram", type=int, default=4096, help="RAM Máxima em MB")
    args = parser.parse_args()

    run_pipeline(args.train_dir, args.test_dir, args.output, args.estimators, args.depth, args.max_ram)