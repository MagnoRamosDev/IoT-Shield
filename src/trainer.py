import os
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix
from sklearn.inspection import permutation_importance
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

def run_training(train_csv, test_csv, exclude_file, threshold=0.5):
    pass
    
    if not os.path.exists(train_csv) or not os.path.exists(test_csv):
        print_ui("[red][!] Phase 3 Requires Phase 2 to be executed first. train.csv or test.csv not found.[/red]")
        return
        
    print_ui(f"[bold blue][*] Loading exclusions from {exclude_file}...[/bold blue]")
    excluded_features = load_excluded_features(exclude_file)
    if excluded_features:
        print_ui(f"  - Exclusions active: {', '.join(excluded_features)}")
    else:
        print_ui("  - No exclusions configured.")
        
    print_ui("[bold blue][*] Loading final mapped dataset frames...[/bold blue]")
    train_df = pd.read_csv(train_csv)
    test_df = pd.read_csv(test_csv)
    
    # Separate label
    y_train = train_df['is_malicious'].values
    y_test = test_df['is_malicious'].values
    
    # Identify final features
    X_train_df = train_df.drop(columns=['is_malicious'])
    X_test_df = test_df.drop(columns=['is_malicious'])
    
    # === Feature Engineering ===
    # 1. Binarize Standard Deviation (is_constant_payload)
    if "src2dst_stddev_ps" in X_train_df.columns:
        X_train_df["is_constant_payload"] = (X_train_df["src2dst_stddev_ps"] < 1.0).astype(float)
        X_test_df["is_constant_payload"] = (X_test_df["src2dst_stddev_ps"] < 1.0).astype(float)
        print_ui("[dim]  - New feature created: is_constant_payload (1 if stddev < 1.0)[/dim]")

    # 2. Flow Rate (flows per sec) to handle NAT safely with Clipping
    if "src2dst_concurrent_flows" in X_train_df.columns and "bidirectional_duration_ms" in X_train_df.columns:
        train_dur_sec = X_train_df["bidirectional_duration_ms"].replace(0, 1.0) / 1000.0
        test_dur_sec = X_test_df["bidirectional_duration_ms"].replace(0, 1.0) / 1000.0
        # Calculate the rate (flows per second) and apply clipping to prevent dominance of extreme outliers
        X_train_df["src2dst_flow_rate"] = (X_train_df["src2dst_concurrent_flows"] / train_dur_sec).clip(upper=2000)
        X_test_df["src2dst_flow_rate"] = (X_test_df["src2dst_concurrent_flows"] / test_dur_sec).clip(upper=2000)
        print_ui("[dim]  - New feature created: src2dst_flow_rate (flows per sec, max limit=1000)[/dim]")

    # 3. Asymmetry (In/Out Ratio)
    if "src2dst_packets" in X_train_df.columns and "dst2src_packets" in X_train_df.columns:
        train_dst_pkts = X_train_df["dst2src_packets"].replace(0, 1.0)
        test_dst_pkts = X_test_df["dst2src_packets"].replace(0, 1.0)
        X_train_df["in_out_packet_ratio"] = (X_train_df["src2dst_packets"] / train_dst_pkts).clip(upper=100)
        X_test_df["in_out_packet_ratio"] = (X_test_df["src2dst_packets"] / test_dst_pkts).clip(upper=100)
        print_ui("[dim]  - New feature created: in_out_packet_ratio (src2dst_packets / dst2src_packets)[/dim]")

    # 4. Incomplete Handshake Ratio (SYN packets / Total Packets)
    if "src2dst_syn_packets" in X_train_df.columns and "src2dst_packets" in X_train_df.columns:
        train_src_pkts = X_train_df["src2dst_packets"].replace(0, 1.0)
        test_src_pkts = X_test_df["src2dst_packets"].replace(0, 1.0)
        X_train_df["syn_to_total_ratio"] = X_train_df["src2dst_syn_packets"] / train_src_pkts
        X_test_df["syn_to_total_ratio"] = X_test_df["src2dst_syn_packets"] / test_src_pkts
        print_ui("[dim]  - New feature created: syn_to_total_ratio (syn_packets / total_src_packets)[/dim]")

    # 5. Discovery Protocol Flag
    if "protocol" in X_train_df.columns and "dst_port" in X_train_df.columns:
        # Common discovery/broadcast ports: 1900 (SSDP), 5353 (mDNS), 137/138 (NetBIOS), 67/68 (DHCP)
        discovery_ports = [1900, 5353, 137, 138, 67, 68]
        # protocol 17 is UDP
        train_is_disc = (X_train_df["protocol"] == 17) & (X_train_df["dst_port"].isin(discovery_ports))
        test_is_disc = (X_test_df["protocol"] == 17) & (X_test_df["dst_port"].isin(discovery_ports))
        
        X_train_df["is_discovery_protocol"] = train_is_disc.astype(float)
        X_test_df["is_discovery_protocol"] = test_is_disc.astype(float)
        print_ui("[dim]  - New feature created: is_discovery_protocol (True for UDP on ports 1900, 5353, 137...)[/dim]")
    # ===========================
    
    columns_to_drop = [col for col in excluded_features if col in X_train_df.columns]
    
    if columns_to_drop:
        print_ui(f"[yellow]  - Dropping columns: {', '.join(columns_to_drop)}[/yellow]")
        X_train_df.drop(columns=columns_to_drop, inplace=True)
        X_test_df.drop(columns=columns_to_drop, inplace=True)
        
    # Clipping to force the model to learn from other features
    concurrent_features = ["src2dst_concurrent_flows", "dst2src_concurrent_flows", "bidirectional_concurrent_flows"]
    for col in concurrent_features:
        if col in X_train_df.columns:
            X_train_df[col] = X_train_df[col].clip(upper=10)
            X_test_df[col] = X_test_df[col].clip(upper=10)
            print_ui(f"[dim]  - Clipping applied to {col} (max limit = 10)[/dim]")

    feature_names = X_train_df.columns.tolist()
    X_train = X_train_df.values
    X_test = X_test_df.values
    
    print_ui(f"[green]  - Training Records: {len(X_train)}  | Testing Records: {len(X_test)}[/green]")
    print_ui(f"[green]  - Feature Space Dimension: {len(feature_names)}[/green]")
    
    print_ui("[bold cyan][*] Training Random Forest model (with depth pruning)...[/bold cyan]")
    
    rf = RandomForestClassifier(n_estimators=100, max_depth=8, min_samples_split=5, random_state=52, n_jobs=-1, max_features=2)
    
    rf.fit(X_train, y_train)
    
    # Calculate depth statistics
    depths = [tree.tree_.max_depth for tree in rf.estimators_]
    avg_depth = sum(depths) / len(depths)
    print_ui(f"[bold green][+] Model fitted! (Avg Tree Depth: {avg_depth:.1f} / Max Allowed: 8)[/bold green]")
    
    print_ui("[bold cyan][*] Evaluating on Testing Dataset...[/bold cyan]")
    y_proba = rf.predict_proba(X_test)[:, 1]  # probability of being malicious
    y_pred  = (y_proba >= threshold).astype(int)

    print_ui(f"[bold yellow]  Using classification threshold: {threshold:.2f}[/bold yellow]")
    print_ui(f"  (raise to let more benign pass; lower to catch more malicious)\n")

    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, average='weighted', zero_division=0)
    rec  = recall_score(y_test, y_pred, average='weighted', zero_division=0)
    f1   = f1_score(y_test, y_pred, average='weighted', zero_division=0)
    
    display_metrics(acc, prec, rec, f1)
    
    cm = confusion_matrix(y_test, y_pred)
    display_confusion_matrix(cm)

    # --- Protocol Confusion Matrix ---
    
    test_protocols = test_df['protocol'].values
    unique_protos = sorted(list(set(test_protocols)))
    
    proto_rows = []
    
    for proto in unique_protos:
        mask = test_protocols == proto
        y_test_proto = y_test[mask]
        y_pred_proto = y_pred[mask]
        
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
    print_ui(classification_report(y_test, y_pred, digits=5))

    # --- Threshold sweep table ---
    n_benign    = (y_test == 0).sum()
    n_malicious = (y_test == 1).sum()
    sweep_rows = []

    for t in [0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.90]:
        yp = (y_proba >= t).astype(int)
        fp = int(((yp == 1) & (y_test == 0)).sum())   # benign wrongly blocked
        fn = int(((yp == 0) & (y_test == 1)).sum())   # malicious wrongly allowed
        acc_t = accuracy_score(y_test, yp)
        marker = " ◀ current" if abs(t - threshold) < 0.001 else ""
        sweep_rows.append((
            f"{t:.2f}{marker}",
            f"{fp}/{n_benign}  ({fp/n_benign*100:.5f}%)",
            f"{fn}/{n_malicious}  ({fn/n_malicious*100:.5f}%)",
            f"{acc_t*100:.5f}%",
        ))

    display_threshold_sweep(sweep_rows, threshold)

    print_ui("[bold cyan][*] Extracting Feature Importances (Gini Impurity / MDI)...[/bold cyan]")
    
    # Switch from Permutation to inherent Gini importance from the trees
    # This prevents the 0.0000 problem caused by perfectly correlated datasets during permutation drops
    importances = rf.feature_importances_
    
    sorted_idx = importances.argsort()[::-1]
    feat_rows = []
    
    for i, idx in enumerate(sorted_idx):
        importance_val = importances[idx]
        feat_name = feature_names[idx]
        feat_rows.append((f"{i+1}", feat_name, f"{importance_val * 100:.5f}%"))
        
    display_feature_importance(feat_rows)
    
    # Save misclassified flows
    out_dir = os.path.dirname(test_csv)
    
    misclassified_mask = y_pred != y_test
    misclassified_count = misclassified_mask.sum()
    if misclassified_count > 0:
        misclassified_df = test_df[misclassified_mask].copy()
        misclassified_df['predicted_label'] = y_pred[misclassified_mask]
        misclassified_df['probability_malicious'] = y_proba[misclassified_mask]
        
        misclass_path = os.path.join(out_dir, "misclassified.csv")
        misclassified_df.to_csv(misclass_path, index=False)
        print_ui(f"\n[bold red][*] Exported {misclassified_count} misclassified flows to: {misclass_path}[/bold red]")
    else:
        print_ui(f"\n[bold green][*] No misclassified flows to export![/bold green]")

    # Save correctly classified flows
    correct_mask = y_pred == y_test
    correct_count = correct_mask.sum()
    if correct_count > 0:
        correct_df = test_df[correct_mask].copy()
        correct_df['predicted_label'] = y_pred[correct_mask]
        correct_df['probability_malicious'] = y_proba[correct_mask]
        
        correct_path = os.path.join(out_dir, "correctly_classified.csv")
        correct_df.to_csv(correct_path, index=False)
        print_ui(f"[bold green][*] Exported {correct_count} correctly classified flows to: {correct_path}[/bold green]")

    import joblib
    model_path = os.path.join(out_dir, "rf_model.pkl")
    features_path = os.path.join(out_dir, "feature_names.txt")
    joblib.dump(rf, model_path)
    with open(features_path, "w") as f:
        f.write(",".join(feature_names))
        
    print_ui(f"[bold green][*] Saved Random Forest model to: {model_path}[/bold green]")
    print_ui("\n[bold green][+] Phase 3 Completed![/bold green]")
