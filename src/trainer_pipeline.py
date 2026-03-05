# experiment_runner.py
import os
import glob
import time
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

def load_datasets_smart(folder_path, is_train=True):
    """
    Reads CSV files in chunks to maintain memory efficiency.
    Retains all benign traffic (class 0) and performs undersampling 
    on the attack traffic (class 1) to prevent model overfitting.
    """
    all_files = glob.glob(os.path.join(folder_path, "*.csv"))
    if not all_files:
        print(f"[ERROR] No CSV files found in {folder_path}")
        return None
    
    df_list = []
    # Use a 2% sample for training and 5% for testing to balance memory constraints
    sample_rate = 0.02 if is_train else 0.05 
    
    for file in all_files:
        print(f"  -> Loading {os.path.basename(file)} in chunks...")
        chunk_iterator = pd.read_csv(file, chunksize=5000000)
        
        for chunk in chunk_iterator:
            normal_traffic = chunk[chunk['label'] == 0]
            botnet_traffic = chunk[chunk['label'] == 1]
            
            if len(botnet_traffic) > 0:
                botnet_traffic = botnet_traffic.sample(frac=sample_rate, random_state=42)
            
            df_list.append(normal_traffic)
            df_list.append(botnet_traffic)
            
    combined_df = pd.concat(df_list, ignore_index=True)
    combined_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    combined_df.fillna(0, inplace=True)
    
    return combined_df

def run_experiment():
    print("=========================================================")
    print("🧪 IoT-Shield: Random Forest Training & Evaluation")
    print("=========================================================\n")

    feature_cols = [
        'total_size_bytes', 'payload_size_bytes', 'ttl', 
        'is_tcp', 'is_udp', 'is_icmp', 'tcp_window', 'tcp_flag', 'iat_ms'
    ]

    CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
    TRAIN_DIR = os.path.join(CURRENT_DIR, "..", "data", "datasets", "train")
    TEST_DIR = os.path.join(CURRENT_DIR, "..", "data", "datasets", "test")

    # 1. Data Loading
    print("[1/4] Loading training data (Memory-Safe Mode)...")
    train_df = load_datasets_smart(TRAIN_DIR, is_train=True)
    if train_df is None: return
    
    X_train = train_df[feature_cols]
    y_train = train_df['label']
    
    print(f"[INFO] Training set size: {len(train_df):,} samples.")
    print(f"       Benign (0): {len(train_df[train_df['label'] == 0]):,}")
    print(f"       Botnet (1): {len(train_df[train_df['label'] == 1]):,}")

    # 2. Model Training
    print("\n[2/4] Training Lightweight Random Forest Classifier...")
    start_time = time.time()
    
    # n_jobs=-1 utilizes all available CPU cores
    rf_model = RandomForestClassifier(
        n_estimators=100, 
        max_depth=15, 
        n_jobs=-1, 
        random_state=42
    )
    rf_model.fit(X_train, y_train)
    
    print(f"[SUCCESS] Training completed in {time.time() - start_time:.2f} seconds.")

    # 3. Model Export
    RESULTS_DIR = os.path.join(CURRENT_DIR, "..", "results")
    print(RESULTS_DIR)
    os.makedirs(RESULTS_DIR, exist_ok=True)
    model_filename = f"{RESULTS_DIR}/iot_shield_model.pkl"
    
    joblib.dump(rf_model, model_filename)
    print(f"[INFO] Model successfully exported as '{model_filename}'.")

    # 4. Evaluation
    print("\n[4/4] Evaluating on Unseen Test Data...")
    test_df = load_datasets_smart(TEST_DIR, is_train=False)
    if test_df is None: return
    
    X_test = test_df[feature_cols]
    y_test = test_df['label']
    
    y_pred = rf_model.predict(X_test)
    
    print("\n=========================================================")
    print("📊 FINAL EVALUATION REPORT")
    print("=========================================================\n")
    print(f"Global Accuracy: {accuracy_score(y_test, y_pred):.4f}\n")
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    print("\nClassification Metrics:")
    print(classification_report(y_test, y_pred, target_names=["Benign (0)", "Botnet (1)"]))

if __name__ == "__main__":
    run_experiment()