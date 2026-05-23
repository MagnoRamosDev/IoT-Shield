import os
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix
import joblib
from src.dashboard import print_ui, display_metrics, display_confusion_matrix, display_protocol_confusion_matrix, display_threshold_sweep, display_feature_importance

def load_excluded_features(exclude_file):
    excluded = set()
    if os.path.exists(exclude_file):
        with open(exclude_file, 'r') as f:
            for line in f:
                feat = line.strip()
                if feat and not feat.startswith('#'):
                    excluded.add(feat)
    return excluded

def process_dataframe(df, excluded_features):
    y = df['is_malicious'].values
    X_df = df.drop(columns=['is_malicious'])
    
    if "src2dst_stddev_ps" in X_df.columns:
        X_df["is_constant_payload"] = (X_df["src2dst_stddev_ps"] < 1.0).astype(float)

    if "src2dst_concurrent_flows" in X_df.columns and "bidirectional_duration_ms" in X_df.columns:
        dur_sec = X_df["bidirectional_duration_ms"].replace(0, 1.0) / 1000.0
        X_df["src2dst_flow_rate"] = (X_df["src2dst_concurrent_flows"] / dur_sec).clip(upper=2000)

    if "src2dst_packets" in X_df.columns and "dst2src_packets" in X_df.columns:
        dst_pkts = X_df["dst2src_packets"].replace(0, 1.0)
        X_df["in_out_packet_ratio"] = (X_df["src2dst_packets"] / dst_pkts).clip(upper=100)

    if "src2dst_syn_packets" in X_df.columns and "src2dst_packets" in X_df.columns:
        src_pkts = X_df["src2dst_packets"].replace(0, 1.0)
        X_df["syn_to_total_ratio"] = X_df["src2dst_syn_packets"] / src_pkts

    if "protocol" in X_df.columns and "dst_port" in X_df.columns:
        discovery_ports = [1900, 5353, 137, 138, 67, 68]
        is_disc = (X_df["protocol"] == 17) & (X_df["dst_port"].isin(discovery_ports))
        X_df["is_discovery_protocol"] = is_disc.astype(float)
        
    columns_to_drop = [col for col in excluded_features if col in X_df.columns]
    if columns_to_drop:
        X_df.drop(columns=columns_to_drop, inplace=True)
        
    concurrent_features = ["src2dst_concurrent_flows", "dst2src_concurrent_flows", "bidirectional_concurrent_flows"]
    for col in concurrent_features:
        if col in X_df.columns:
            X_df[col] = X_df[col].clip(upper=10)
            
    return X_df, y

def run_training(output_dir, exclude_file, threshold=0.5, folds=5):
    print_ui(f"[bold blue][*] Loading exclusions from {exclude_file}...[/bold blue]")
    excluded_features = load_excluded_features(exclude_file)
    if excluded_features:
        print_ui(f"  - Exclusions active: {', '.join(excluded_features)}")
    else:
        print_ui("  - No exclusions configured.")
        
    print_ui(f"[bold blue][*] Starting {folds}-Fold Cross Validation...[/bold blue]")
    
    all_y_test = []
    all_y_pred = []
    all_y_proba = []
    all_test_protocols = []
    all_test_dfs = []
    
    for k in range(1, folds + 1):
        print_ui(f"\n[bold cyan][*] --- Fold {k}/{folds} ---[/bold cyan]")
        test_csv = os.path.join(output_dir, f"fold_{k}.csv")
        if not os.path.exists(test_csv):
            print_ui(f"[red][!] Fold file {test_csv} not found. Run Phase 2 first.[/red]")
            return
            
        test_df = pd.read_csv(test_csv)
        train_dfs = []
        for i in range(1, folds + 1):
            if i != k:
                train_dfs.append(pd.read_csv(os.path.join(output_dir, f"fold_{i}.csv")))
                
        train_df = pd.concat(train_dfs, ignore_index=True)
        
        X_train_df, y_train = process_dataframe(train_df, excluded_features)
        X_test_df, y_test = process_dataframe(test_df, excluded_features)
        
        rf = RandomForestClassifier(n_estimators=100, max_depth=8, min_samples_split=5, random_state=52, n_jobs=-1, max_features=2)
        rf.fit(X_train_df.values, y_train)
        
        y_proba = rf.predict_proba(X_test_df.values)[:, 1]
        y_pred = (y_proba >= threshold).astype(int)
        
        all_y_test.extend(y_test)
        all_y_pred.extend(y_pred)
        all_y_proba.extend(y_proba)
        all_test_protocols.extend(test_df['protocol'].values)
        
        test_df['predicted_label'] = y_pred
        test_df['probability_malicious'] = y_proba
        all_test_dfs.append(test_df)
        
        acc = accuracy_score(y_test, y_pred)
        print_ui(f"  [dim]Fold {k} Accuracy: {acc*100:.5f}%[/dim]")

    print_ui("\n[bold cyan][*] --- Global Cross-Validation Results ---[/bold cyan]")
    y_test_global = np.array(all_y_test)
    y_pred_global = np.array(all_y_pred)
    y_proba_global = np.array(all_y_proba)
    
    acc  = accuracy_score(y_test_global, y_pred_global)
    prec = precision_score(y_test_global, y_pred_global, average='weighted', zero_division=0)
    rec  = recall_score(y_test_global, y_pred_global, average='weighted', zero_division=0)
    f1   = f1_score(y_test_global, y_pred_global, average='weighted', zero_division=0)
    
    display_metrics(acc, prec, rec, f1)
    
    cm = confusion_matrix(y_test_global, y_pred_global)
    display_confusion_matrix(cm)
    
    # --- Protocol Confusion Matrix ---
    test_protocols = np.array(all_test_protocols)
    unique_protos = sorted(list(set(test_protocols)))
    proto_rows = []
    
    for proto in unique_protos:
        mask = test_protocols == proto
        y_test_proto = y_test_global[mask]
        y_pred_proto = y_pred_global[mask]
        
        if len(y_test_proto) > 0:
            cm_proto = confusion_matrix(y_test_proto, y_pred_proto, labels=[0, 1])
            tn, fp, fn, tp = cm_proto.ravel()
            
            proto_name = str(int(proto))
            if proto == 6: proto_name = "6 (TCP)"
            elif proto == 17: proto_name = "17 (UDP)"
            elif proto == 1: proto_name = "1 (ICMP)"
            
            proto_rows.append((proto_name, str(tn), str(fp), str(fn), str(tp)))

    display_protocol_confusion_matrix(proto_rows)
    print_ui("[bold magenta]Classification Report:[/bold magenta]")
    print_ui(classification_report(y_test_global, y_pred_global, digits=5))

    # --- Threshold sweep table ---
    n_benign    = (y_test_global == 0).sum()
    n_malicious = (y_test_global == 1).sum()
    sweep_rows = []

    for t in [0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.90]:
        yp = (y_proba_global >= t).astype(int)
        fp = int(((yp == 1) & (y_test_global == 0)).sum())
        fn = int(((yp == 0) & (y_test_global == 1)).sum())
        acc_t = accuracy_score(y_test_global, yp)
        marker = " ◀ current" if abs(t - threshold) < 0.001 else ""
        sweep_rows.append((
            f"{t:.2f}{marker}",
            f"{fp}/{n_benign}  ({fp/n_benign*100:.5f}%)",
            f"{fn}/{n_malicious}  ({fn/n_malicious*100:.5f}%)",
            f"{acc_t*100:.5f}%",
        ))

    display_threshold_sweep(sweep_rows, threshold)

    print_ui("\n[bold cyan][*] Training Final Model on ALL Folds...[/bold cyan]")
    final_dfs = [pd.read_csv(os.path.join(output_dir, f"fold_{i}.csv")) for i in range(1, folds + 1)]
    final_df = pd.concat(final_dfs, ignore_index=True)
    X_final_df, y_final = process_dataframe(final_df, excluded_features)
    feature_names = X_final_df.columns.tolist()
    
    rf_final = RandomForestClassifier(n_estimators=100, max_depth=8, min_samples_split=5, random_state=52, n_jobs=-1, max_features=2)
    rf_final.fit(X_final_df.values, y_final)
    
    importances = rf_final.feature_importances_
    sorted_idx = importances.argsort()[::-1]
    feat_rows = []
    
    for i, idx in enumerate(sorted_idx):
        importance_val = importances[idx]
        feat_name = feature_names[idx]
        feat_rows.append((f"{i+1}", feat_name, f"{importance_val * 100:.5f}%"))
        
    print_ui("[bold cyan][*] Extracting Feature Importances (Gini Impurity / MDI) from Final Model...[/bold cyan]")
    display_feature_importance(feat_rows)
    
    global_test_df = pd.concat(all_test_dfs, ignore_index=True)
    y_pred_series = global_test_df['predicted_label'].values
    y_test_series = global_test_df['is_malicious'].values
    
    misclassified_mask = y_pred_series != y_test_series
    misclassified_count = misclassified_mask.sum()
    if misclassified_count > 0:
        misclassified_df = global_test_df[misclassified_mask]
        misclass_path = os.path.join(output_dir, "misclassified.csv")
        misclassified_df.to_csv(misclass_path, index=False)
        print_ui(f"\n[bold red][*] Exported {misclassified_count} misclassified flows to: {misclass_path}[/bold red]")
    else:
        print_ui(f"\n[bold green][*] No misclassified flows to export![/bold green]")

    correct_mask = y_pred_series == y_test_series
    correct_count = correct_mask.sum()
    if correct_count > 0:
        correct_df = global_test_df[correct_mask]
        correct_path = os.path.join(output_dir, "correctly_classified.csv")
        correct_df.to_csv(correct_path, index=False)
        print_ui(f"[bold green][*] Exported {correct_count} correctly classified flows to: {correct_path}[/bold green]")

    model_path = os.path.join(output_dir, "rf_model.pkl")
    features_path = os.path.join(output_dir, "feature_names.txt")
    joblib.dump(rf_final, model_path)
    with open(features_path, "w") as f:
        f.write(",".join(feature_names))
        
    print_ui(f"[bold green][*] Saved Final Random Forest model to: {model_path}[/bold green]")
    print_ui("\n[bold green][+] Phase 3 Completed![/bold green]")
