"""
IoT-Shield: Academic Visualization Generator

This module loads the pre-trained TinyML model and the test datasets to generate
publication-ready, high-resolution plots. It produces a Confusion Matrix heatmap 
and a Feature Importance bar chart, saving them as PNG files for academic papers
and presentations.
"""

import os
import glob
import joblib
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix

def load_test_data_smart(folder_path):
    """
    Loads test datasets in chunks to maintain low memory usage footprint.
    Samples 5% of the botnet traffic while keeping 100% of the benign traffic.
    """
    print(f"[INFO] Loading test datasets from {folder_path}...")
    all_files = glob.glob(os.path.join(folder_path, "*.csv"))
    if not all_files:
        print(f"[ERROR] No CSV files found in {folder_path}")
        return None
    
    df_list = []
    
    for file in all_files:
        chunk_iterator = pd.read_csv(file, chunksize=10000000)
        for chunk in chunk_iterator:
            normal_traffic = chunk[chunk['label'] == 0]
            
            botnet_traffic = chunk[chunk['label'] == 1]
            if len(botnet_traffic) > 0:
                botnet_traffic = botnet_traffic.sample(frac=0.05, random_state=42)
            
            df_list.append(normal_traffic)
            df_list.append(botnet_traffic)
            
    combined_df = pd.concat(df_list, ignore_index=True)
    combined_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    combined_df.fillna(0, inplace=True)
    
    return combined_df

def plot_feature_importance(model, feature_names, output_filename="plot_feature_importance.png"):
    """Generates and saves a horizontal bar chart of feature importances."""
    print("[INFO] Generating Feature Importance chart...")
    
    importances = model.feature_importances_
    indices = np.argsort(importances) # Sort in ascending order for horizontal bar chart
    
    plt.figure(figsize=(10, 6))
    sns.set_theme(style="whitegrid")
    
    # Create horizontal bar plot
    bars = plt.barh(range(len(indices)), importances[indices], color='steelblue', align='center')
    plt.yticks(range(len(indices)), [feature_names[i] for i in indices])
    plt.xlabel('Relative Importance')
    plt.title('TinyML Edge Detection: Feature Importance', fontsize=14, pad=15)
    
    # Add percentage labels to the right of each bar
    for bar in bars:
        width = bar.get_width()
        plt.text(width + 0.01, bar.get_y() + bar.get_height()/2, 
                 f'{width*100:.2f}%', 
                 ha='left', va='center', fontsize=10)
                 
    plt.tight_layout()
    plt.savefig(output_filename, dpi=300, bbox_inches='tight')
    print(f"[SUCCESS] Chart saved as {output_filename}")
    plt.close()

def plot_confusion_matrix(y_true, y_pred, output_filename="plot_confusion_matrix.png"):
    """Generates and saves a heatmap representing the Confusion Matrix."""
    print("[INFO] Generating Confusion Matrix heatmap...")
    
    cm = confusion_matrix(y_true, y_pred)
    
    plt.figure(figsize=(8, 6))
    sns.set_theme(style="white")
    
    # Create heatmap
    ax = sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                     cbar=False, annot_kws={"size": 14})
                     
    ax.set_xlabel('Predicted Label', fontsize=12, labelpad=10)
    ax.set_ylabel('True Label', fontsize=12, labelpad=10)
    ax.set_title('Zero-Day Attack Evaluation: Confusion Matrix', fontsize=14, pad=15)
    
    ax.xaxis.set_ticklabels(['Benign (0)', 'Botnet (1)'])
    ax.yaxis.set_ticklabels(['Benign (0)', 'Botnet (1)'])
    
    plt.tight_layout()
    plt.savefig(output_filename, dpi=300, bbox_inches='tight')
    print(f"[SUCCESS] Chart saved as {output_filename}")
    plt.close()

def main():
    print("=========================================================")
    print("📊 IoT-Shield: Academic Plot Generator")
    print("=========================================================\n")

    model_path = 'results/iot_shield_model.pkl'
    if not os.path.exists(model_path):
        print(f"[ERROR] Model file '{model_path}' not found.")
        print("[INFO] Please run the training script first to export the model.")
        return

    # 1. Load the frozen brain
    print("[INFO] Loading pre-trained model...")
    rf_model = joblib.load(model_path)

    feature_cols = [
        'total_size_bytes', 'payload_size_bytes', 'ttl', 
        'is_tcp', 'is_udp', 'is_icmp', 'tcp_window', 'tcp_flag', 'iat_ms'
    ]

    # 2. Generate Feature Importance Plot
    plot_feature_importance(rf_model, feature_cols, output_filename="results/plot_feature_importance.png")

    # 3. Load Test Data & Predict
    test_df = load_test_data_smart("data/datasets/test")
    if test_df is not None:
        X_test = test_df[feature_cols]
        y_true = test_df['label']
        
        print("[INFO] Running predictions on test data...")
        y_pred = rf_model.predict(X_test)
        
        # 4. Generate Confusion Matrix Plot
        plot_confusion_matrix(y_true, y_pred, output_filename="results/plot_confusion_matrix.png")

    print("\n[SUCCESS] All academic plots have been generated successfully!")

if __name__ == "__main__":
    main()