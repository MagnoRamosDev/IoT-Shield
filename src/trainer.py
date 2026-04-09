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

def run_training(train_csv, test_csv, exclude_file):
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
    
    columns_to_drop = [col for col in excluded_features if col in X_train_df.columns]
    
    if columns_to_drop:
        console.print(f"[yellow]  - Dropping columns: {', '.join(columns_to_drop)}[/yellow]")
        X_train_df.drop(columns=columns_to_drop, inplace=True)
        X_test_df.drop(columns=columns_to_drop, inplace=True)
        
    feature_names = X_train_df.columns.tolist()
    X_train = X_train_df.values
    X_test = X_test_df.values
    
    console.print(f"[green]  - Training Records: {len(X_train)}  | Testing Records: {len(X_test)}[/green]")
    console.print(f"[green]  - Feature Space Dimension: {len(feature_names)}[/green]")
    
    console.print("[bold cyan][*] Training Random Forest model (with depth pruning)...[/bold cyan]")
    # Pruned tree to prevent memorization (overfitting)
    rf = RandomForestClassifier(n_estimators=100, max_depth=8, min_samples_split=5, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    
    # Calculate depth statistics
    depths = [tree.tree_.max_depth for tree in rf.estimators_]
    avg_depth = sum(depths) / len(depths)
    console.print(f"[bold green][+] Model fitted! (Avg Tree Depth: {avg_depth:.1f} / Max Allowed: 8)[/bold green]")
    
    console.print("[bold cyan][*] Evaluating on Testing Dataset...[/bold cyan]")
    y_pred = rf.predict(X_test)
    
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, average='weighted', zero_division=0)
    rec = recall_score(y_test, y_pred, average='weighted', zero_division=0)
    f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)
    
    metrics_table = Table(title="Performance Metrics", show_header=True, header_style="bold magenta")
    metrics_table.add_column("Metric", style="dim", width=20)
    metrics_table.add_column("Score")
    
    metrics_table.add_row("Accuracy", f"{acc * 100:.2f}%")
    metrics_table.add_row("Precision", f"{prec * 100:.2f}%")
    metrics_table.add_row("Recall", f"{rec * 100:.2f}%")
    metrics_table.add_row("F1-Score", f"{f1 * 100:.2f}%")
    
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
    
    console.print()
    console.print("[bold magenta]Classification Report:[/bold magenta]")
    console.print(classification_report(y_test, y_pred))
    
    console.print()
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
        
        # Shows percentage impact like 25.14% instead of 0.0001 probability drops
        feat_table.add_row(f"{i+1}", feat_name, f"{importance_val * 100:.2f}%")
        
    console.print(feat_table)
    console.print("[bold green][+] Phase 3 Completed![/bold green]")
