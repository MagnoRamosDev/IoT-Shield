# src/model_pipeline.py
import os
import time
import joblib
import argparse
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from utils.data_loader import load_datasets_smart

def plot_academic_graphs(model, feature_names, y_true, y_pred, results_dir="results"):
    print("[INFO] Gerando gráficos acadêmicos...")
    # 1. Feature Importance
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

    # 2. Confusion Matrix
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

def run_pipeline(train_dir, test_dir, output_model, n_estimators, max_depth, sample_rate):
    feature_cols = ['total_size_bytes', 'payload_size_bytes', 'ttl', 'is_tcp', 'is_udp', 'is_icmp', 'tcp_window', 'tcp_flag', 'iat_ms']

    print(f"[1/3] Carregando dados de treino...")
    train_df = load_datasets_smart(train_dir, sample_rate=sample_rate)
    if train_df is None: return
    
    print(f"\n[2/3] Treinando Random Forest ({n_estimators} árvores)...")
    start_time = time.time()
    rf_model = RandomForestClassifier(n_estimators=n_estimators, max_depth=max_depth, n_jobs=-1, random_state=42)
    rf_model.fit(train_df[feature_cols], train_df['label'])
    
    os.makedirs(os.path.dirname(output_model), exist_ok=True)
    joblib.dump(rf_model, output_model)
    print(f"[SUCCESS] Modelo salvo em {time.time() - start_time:.2f} segundos.")

    if test_dir:
        print("\n[3/3] Avaliando nos Dados de Teste e Gerando Gráficos...")
        test_df = load_datasets_smart(test_dir, sample_rate=sample_rate)
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
    parser.add_argument("--sample-rate", type=float, default=0.05)
    args = parser.parse_args()

    run_pipeline(args.train_dir, args.test_dir, args.output, args.estimators, args.depth, args.sample_rate)