import os
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix
from sklearn.inspection import permutation_importance
from rich.console import Console
from rich.table import Table

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
    console = Console()
    
    if not os.path.exists(train_csv) or not os.path.exists(test_csv):
        console.print("[red][!] Phase 3 Requires Phase 2 to be executed first. train.csv or test.csv not found.[/red]")
        return
        
    console.print(f"[bold blue][*] Loading exclusions from {exclude_file}...[/bold blue]")
    excluded_features = load_excluded_features(exclude_file)
    if excluded_features:
        console.print(f"  - Exclusions active: {', '.join(excluded_features)}")
    else:
        console.print("  - No exclusions configured.")
        
    console.print("[bold blue][*] Loading final mapped dataset frames...[/bold blue]")
    train_df = pd.read_csv(train_csv)
    test_df = pd.read_csv(test_csv)
    
    # We must unconditionally drop is_malicious from features, and assign to y!
    # And we also drop any columns the user mandated
    
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
        console.print("[dim]  - Nova feature criada: is_constant_payload (1 se stddev < 1.0)[/dim]")

    # 2. Flow Rate (flows per sec) to handle NAT safely with Clipping
    if "src2dst_concurrent_flows" in X_train_df.columns and "bidirectional_duration_ms" in X_train_df.columns:
        train_dur_sec = X_train_df["bidirectional_duration_ms"].replace(0, 1.0) / 1000.0
        test_dur_sec = X_test_df["bidirectional_duration_ms"].replace(0, 1.0) / 1000.0
        # Calcula a taxa (fluxos por segundo) e aplica saturação para evitar domínio de outliers absurdos
        X_train_df["src2dst_flow_rate"] = (X_train_df["src2dst_concurrent_flows"] / train_dur_sec).clip(upper=2000)
        X_test_df["src2dst_flow_rate"] = (X_test_df["src2dst_concurrent_flows"] / test_dur_sec).clip(upper=2000)
        console.print("[dim]  - Nova feature criada: src2dst_flow_rate (fluxos por seg, limite max=1000)[/dim]")

    # 3. Asymmetry (In/Out Ratio)
    if "src2dst_packets" in X_train_df.columns and "dst2src_packets" in X_train_df.columns:
        train_dst_pkts = X_train_df["dst2src_packets"].replace(0, 1.0)
        test_dst_pkts = X_test_df["dst2src_packets"].replace(0, 1.0)
        X_train_df["in_out_packet_ratio"] = (X_train_df["src2dst_packets"] / train_dst_pkts).clip(upper=100)
        X_test_df["in_out_packet_ratio"] = (X_test_df["src2dst_packets"] / test_dst_pkts).clip(upper=100)
        console.print("[dim]  - Nova feature criada: in_out_packet_ratio (src2dst_packets / dst2src_packets)[/dim]")

    # 4. Incomplete Handshake Ratio (SYN packets / Total Packets)
    if "src2dst_syn_packets" in X_train_df.columns and "src2dst_packets" in X_train_df.columns:
        train_src_pkts = X_train_df["src2dst_packets"].replace(0, 1.0)
        test_src_pkts = X_test_df["src2dst_packets"].replace(0, 1.0)
        X_train_df["syn_to_total_ratio"] = X_train_df["src2dst_syn_packets"] / train_src_pkts
        X_test_df["syn_to_total_ratio"] = X_test_df["src2dst_syn_packets"] / test_src_pkts
        console.print("[dim]  - Nova feature criada: syn_to_total_ratio (syn_packets / total_src_packets)[/dim]")

    # 5. Discovery Protocol Flag
    if "protocol" in X_train_df.columns and "dst_port" in X_train_df.columns:
        # Portas comuns de discovery/broadcast: 1900 (SSDP), 5353 (mDNS), 137/138 (NetBIOS), 67/68 (DHCP)
        discovery_ports = [1900, 5353, 137, 138, 67, 68]
        # protocolo 17 é UDP
        train_is_disc = (X_train_df["protocol"] == 17) & (X_train_df["dst_port"].isin(discovery_ports))
        test_is_disc = (X_test_df["protocol"] == 17) & (X_test_df["dst_port"].isin(discovery_ports))
        
        X_train_df["is_discovery_protocol"] = train_is_disc.astype(float)
        X_test_df["is_discovery_protocol"] = test_is_disc.astype(float)
        console.print("[dim]  - Nova feature criada: is_discovery_protocol (True para UDP nas portas 1900, 5353, 137...)[/dim]")
    # ===========================
    
    columns_to_drop = [col for col in excluded_features if col in X_train_df.columns]
    
    if columns_to_drop:
        console.print(f"[yellow]  - Dropping columns: {', '.join(columns_to_drop)}[/yellow]")
        X_train_df.drop(columns=columns_to_drop, inplace=True)
        X_test_df.drop(columns=columns_to_drop, inplace=True)
        
    # Saturação (Clipping) para forçar o modelo a aprender com as outras features
    concurrent_features = ["src2dst_concurrent_flows", "dst2src_concurrent_flows", "bidirectional_concurrent_flows"]
    for col in concurrent_features:
        if col in X_train_df.columns:
            X_train_df[col] = X_train_df[col].clip(upper=10)
            X_test_df[col] = X_test_df[col].clip(upper=10)
            console.print(f"[dim]  - Saturação (Clipping) aplicada em {col} (limite máximo = 10)[/dim]")

    feature_names = X_train_df.columns.tolist()
    X_train = X_train_df.values
    X_test = X_test_df.values
    
    console.print(f"[green]  - Training Records: {len(X_train)}  | Testing Records: {len(X_test)}[/green]")
    console.print(f"[green]  - Feature Space Dimension: {len(feature_names)}[/green]")
    
    console.print("[bold cyan][*] Training Random Forest model (with depth pruning)...[/bold cyan]")
    
    # Para testar a redução de feature dominance por Subsampling, comente a linha abaixo e descomente a seguinte:
    #rf = RandomForestClassifier(n_estimators=100, max_depth=8, min_samples_split=5, random_state=52, n_jobs=-1)
    rf = RandomForestClassifier(n_estimators=100, max_depth=8, min_samples_split=5, random_state=52, n_jobs=-1, max_features=2)
    
    rf.fit(X_train, y_train)
    
    # Calculate depth statistics
    depths = [tree.tree_.max_depth for tree in rf.estimators_]
    avg_depth = sum(depths) / len(depths)
    console.print(f"[bold green][+] Model fitted! (Avg Tree Depth: {avg_depth:.1f} / Max Allowed: 8)[/bold green]")
    
    console.print("[bold cyan][*] Evaluating on Testing Dataset...[/bold cyan]")
    y_proba = rf.predict_proba(X_test)[:, 1]  # probability of being malicious
    y_pred  = (y_proba >= threshold).astype(int)

    console.print(f"[bold yellow]  Using classification threshold: {threshold:.2f}[/bold yellow]")
    console.print(f"  (raise to let more benign pass; lower to catch more malicious)\n")

    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, average='weighted', zero_division=0)
    rec  = recall_score(y_test, y_pred, average='weighted', zero_division=0)
    f1   = f1_score(y_test, y_pred, average='weighted', zero_division=0)
    
    metrics_table = Table(title="Performance Metrics", show_header=True, header_style="bold magenta")
    metrics_table.add_column("Metric", style="dim", width=20)
    metrics_table.add_column("Score")
    
    metrics_table.add_row("Accuracy", f"{acc * 100:.5f}%")
    metrics_table.add_row("Precision", f"{prec * 100:.5f}%")
    metrics_table.add_row("Recall", f"{rec * 100:.5f}%")
    metrics_table.add_row("F1-Score", f"{f1 * 100:.5f}%")
    
    console.print()
    console.print(metrics_table)
    console.print()
    
    cm = confusion_matrix(y_test, y_pred)
    cm_table = Table(title="Confusion Matrix", show_header=True, header_style="bold magenta")
    cm_table.add_column("Actual \\ Predicted")
    cm_table.add_column("Class 0 (Benign)")
    cm_table.add_column("Class 1 (Malicious)")
    cm_table.add_row("Class 0 (Benign)", str(cm[0][0]), str(cm[0][1]))
    cm_table.add_row("Class 1 (Malicious)", str(cm[1][0]), str(cm[1][1]))
    
    console.print(cm_table)

    # --- Matriz de Confusão por Protocolo ---
    console.print()
    
    test_protocols = test_df['protocol'].values
    unique_protos = sorted(list(set(test_protocols)))
    
    proto_cm_table = Table(title="Confusion Matrix by Protocol", show_header=True, header_style="bold magenta")
    proto_cm_table.add_column("Protocol")
    proto_cm_table.add_column("TN (Benign -> Benign)", style="green")
    proto_cm_table.add_column("FP (Benign -> Mal)", style="red")
    proto_cm_table.add_column("FN (Mal -> Benign)", style="yellow")
    proto_cm_table.add_column("TP (Mal -> Mal)", style="green")
    
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
            
            proto_cm_table.add_row(proto_name, str(tn), str(fp), str(fn), str(tp))

    console.print(proto_cm_table)
    console.print()
    console.print("[bold magenta]Classification Report:[/bold magenta]")
    console.print(classification_report(y_test, y_pred, digits=5))

    # --- Threshold sweep table ---
    console.print()
    console.print("[bold cyan][*] Threshold Sweep — tradeoff overview:[/bold cyan]")
    sweep_table = Table(show_header=True, header_style="bold yellow")
    sweep_table.add_column("Threshold",                      justify="center", style="cyan",   min_width=12)
    sweep_table.add_column("Benign Blocked (FP)",            justify="center", style="red",    min_width=20)
    sweep_table.add_column("Malicious Passed (FN)",          justify="center", style="yellow", min_width=22)
    sweep_table.add_column("Accuracy",                       justify="center", style="green",  min_width=10)

    n_benign    = (y_test == 0).sum()
    n_malicious = (y_test == 1).sum()

    for t in [0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.90]:
        yp = (y_proba >= t).astype(int)
        fp = int(((yp == 1) & (y_test == 0)).sum())   # benign wrongly blocked
        fn = int(((yp == 0) & (y_test == 1)).sum())   # malicious wrongly allowed
        acc_t = accuracy_score(y_test, yp)
        marker = " ◀ current" if abs(t - threshold) < 0.001 else ""
        sweep_table.add_row(
            f"{t:.2f}{marker}",
            f"{fp}/{n_benign}  ({fp/n_benign*100:.5f}%)",
            f"{fn}/{n_malicious}  ({fn/n_malicious*100:.5f}%)",
            f"{acc_t*100:.5f}%",
        )

    console.print(sweep_table)
    console.print(
        "[dim]Tip: use [bold]--threshold 0.6[/bold] to block only high-confidence malicious flows,[/dim]\n"
        "[dim]     reducing benign false-positives at the cost of passing more malicious traffic.[/dim]"
    )


    console.print("[bold cyan][*] Extracting Feature Importances (Gini Impurity / MDI)...[/bold cyan]")
    
    # Switch from Permutation to inherent Gini importance from the trees
    # This prevents the 0.0000 problem caused by perfectly correlated datasets during permutation drops
    importances = rf.feature_importances_
    
    sorted_idx = importances.argsort()[::-1]
    
    feat_table = Table(title="Random Forest Feature Importance (MDI)", show_header=True, header_style="bold yellow")
    feat_table.add_column("Rank", justify="right", style="cyan", no_wrap=True)
    feat_table.add_column("Feature Name", style="magenta")
    feat_table.add_column("Importance (% of Tree Splits)", style="green")
    
    for i, idx in enumerate(sorted_idx):
        importance_val = importances[idx]
        feat_name = feature_names[idx]
        
        feat_table.add_row(f"{i+1}", feat_name, f"{importance_val * 100:.5f}%")
        
    console.print(feat_table)
    
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
        console.print(f"\n[bold red][*] Exported {misclassified_count} misclassified flows to: {misclass_path}[/bold red]")
    else:
        console.print(f"\n[bold green][*] No misclassified flows to export![/bold green]")

    # Save correctly classified flows
    correct_mask = y_pred == y_test
    correct_count = correct_mask.sum()
    if correct_count > 0:
        correct_df = test_df[correct_mask].copy()
        correct_df['predicted_label'] = y_pred[correct_mask]
        correct_df['probability_malicious'] = y_proba[correct_mask]
        
        correct_path = os.path.join(out_dir, "correctly_classified.csv")
        correct_df.to_csv(correct_path, index=False)
        console.print(f"[bold green][*] Exported {correct_count} correctly classified flows to: {correct_path}[/bold green]")

    console.print("\n[bold green][+] Phase 3 Completed![/bold green]")
