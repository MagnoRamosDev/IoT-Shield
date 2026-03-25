# src/model/train.py
import os
import time
import joblib
import argparse
import glob
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import gc

# Trava de RAM nos Tipos de Dados
OPTIMIZED_DTYPES = {
    'total_size_bytes': 'int32',
    'payload_size_bytes': 'int32',
    'ttl': 'int16',
    'is_tcp': 'int8',
    'is_udp': 'int8',
    'is_icmp': 'int8',
    'tcp_window': 'int32',
    'tcp_flag': 'int16',
    'iat_ms': 'float32',
    'label': 'int8'
}

def load_data_fraction(folder_path, frac=0.20):
    """Lê uma fração do dataset garantindo que todas as classes sejam amostradas."""
    all_files = glob.glob(os.path.join(folder_path, "*.csv"))
    if not all_files: return None
    
    df_list = []
    for file in all_files:
        chunk_iterator = pd.read_csv(file, chunksize=250000, dtype=OPTIMIZED_DTYPES)
        for chunk in chunk_iterator:
            # Pega X% de cada bloco para garantir homogeneidade sem estourar RAM
            df_list.append(chunk.sample(frac=frac, random_state=int(time.time())))

    combined_df = pd.concat(df_list, ignore_index=True)
    del df_list
    gc.collect()
    
    combined_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    combined_df.fillna(0, inplace=True)
    return combined_df.sample(frac=1.0, random_state=42).reset_index(drop=True)

def plot_academic_graphs(model, feature_names, y_true, y_pred, results_dir="results"):
    os.makedirs(results_dir, exist_ok=True)
    
    importances = model.feature_importances_
    indices = np.argsort(importances)
    plt.figure(figsize=(10, 6))
    sns.set_theme(style="whitegrid")
    plt.barh(range(len(indices)), importances[indices], color='steelblue', align='center')
    plt.yticks(range(len(indices)), [feature_names[i] for i in indices])
    plt.xlabel('Importância Relativa')
    plt.title('TinyML Edge Detection: Importância das Features', fontsize=14, pad=15)
    plt.tight_layout()
    plt.savefig(os.path.join(results_dir, "plot_feature_importance.png"), dpi=300)
    plt.close()

    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(8, 6))
    sns.set_theme(style="white")
    ax = sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', cbar=False, annot_kws={"size": 14})
    ax.set_title('Avaliação do Modelo: Matriz de Confusão', fontsize=14, pad=15)
    ax.xaxis.set_ticklabels(['Benigno (0)', 'Mirai (1)'])
    ax.yaxis.set_ticklabels(['Benigno (0)', 'Mirai (1)'])
    plt.tight_layout()
    plt.savefig(os.path.join(results_dir, "plot_confusion_matrix.png"), dpi=300)
    plt.close()

def run_pipeline(train_dir, test_dir, output_model, n_estimators, max_depth, max_ram_mb):
    feature_cols = ['total_size_bytes', 'payload_size_bytes', 'ttl', 'is_tcp', 'is_udp', 'is_icmp', 'tcp_window', 'tcp_flag', 'iat_ms']

    print(f"\n[1/3] Iniciando Treinamento Incremental (Out-of-Core)...")
    
    # A MÁGICA: warm_start=True permite adicionar árvores progressivamente
    rf_model = RandomForestClassifier(
        n_estimators=0, 
        max_depth=max_depth, 
        warm_start=True, 
        n_jobs=-1, # Todos os núcleos ativados com segurança!
        random_state=42
    )

    batches = 5 # Divide o treino em 5 fases (cada uma lendo 20% dos dados)
    trees_per_batch = max(1, n_estimators // batches)

    start_time = time.time()

    for batch in range(1, batches + 1):
        print(f"\n  >>> Processando Lote {batch}/{batches} <<<")
        
        # Carrega 20% do dataset e mistura benignos com malignos
        train_df = load_data_fraction(train_dir, frac=0.20)
        
        X_train_np = np.ascontiguousarray(train_df[feature_cols].values, dtype=np.float32)
        y_train_np = np.ascontiguousarray(train_df['label'].values, dtype=np.int8)
        
        del train_df
        gc.collect()
        
        # Incrementa o número de árvores na floresta
        if batch == batches:
            rf_model.n_estimators = n_estimators # Garante exatamente o limite na última volta
        else:
            rf_model.n_estimators += trees_per_batch
            
        print(f"  -> Treinando floresta com {rf_model.n_estimators} árvores ativas ({len(y_train_np):,} pacotes)...")
        rf_model.fit(X_train_np, y_train_np)
        
        # Joga o grupo de dados atual fora e esvazia a RAM para o próximo lote
        del X_train_np, y_train_np
        gc.collect()

    os.makedirs(os.path.dirname(output_model), exist_ok=True)
    joblib.dump(rf_model, output_model)
    print(f"\n[SUCCESS] Treinamento Incremental finalizado em {time.time() - start_time:.2f} segundos.")

    if test_dir:
        print("\n[2/3] Avaliando nos Dados de Teste...")
        # Lê apenas 15% do teste real para avaliar sem gargalos
        test_df = load_data_fraction(test_dir, frac=0.15)
        if test_df is not None:
            y_true = test_df['label']
            y_pred = rf_model.predict(np.ascontiguousarray(test_df[feature_cols].values, dtype=np.float32))
            
            print("\n=========================================================")
            print(f"🎯 ACURÁCIA GLOBAL: {accuracy_score(y_true, y_pred):.4f}")
            print("=========================================================")
            print("\n📊 RELATÓRIO DE CLASSIFICAÇÃO:")
            print(classification_report(y_true, y_pred, target_names=['Benigno (0)', 'Mirai (1)'], digits=4))
            
            plot_academic_graphs(rf_model, feature_cols, y_true, y_pred, os.path.dirname(output_model))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--train-dir", required=True)
    parser.add_argument("--test-dir", default=None)
    parser.add_argument("--output", default="results/iot_shield_model.pkl")
    parser.add_argument("--estimators", type=int, default=15)
    parser.add_argument("--depth", type=int, default=8)
    parser.add_argument("--max-ram", type=int, default=4096)
    args = parser.parse_args()

    run_pipeline(args.train_dir, args.test_dir, args.output, args.estimators, args.depth, args.max_ram)