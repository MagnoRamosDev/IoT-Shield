import os
import joblib
from src.dashboard import print_ui

def run_export(out_dir):
    """
    Load the trained Random Forest model and export it to native C code.
    """
    model_path = os.path.join(out_dir, "rf_model.pkl")
    features_path = os.path.join(out_dir, "feature_names.txt")
    
    if not os.path.exists(model_path) or not os.path.exists(features_path):
        print_ui(f"[bold red][!] Phase 4 Requires Phase 3 to be executed first. {model_path} not found.[/bold red]")
        return
        
    try:
        import m2cgen as m2c
    except ImportError:
        print_ui("\n[bold yellow][!] Biblioteca 'm2cgen' não encontrada. O modelo não foi exportado para C.[/bold yellow]")
        print_ui("[dim]Para habilitar a exportação, rode: pip install m2cgen[/dim]")
        return

    print_ui("[bold cyan][*] Transpiling Random Forest to C code for IoT Firmware...[/bold cyan]")
    
    rf = joblib.load(model_path)
    with open(features_path, "r") as f:
        feature_names = f.read().split(",")
        
    # O m2cgen transpila os if/elses da árvore diretamente para C
    c_code = m2c.export_to_c(rf)
    c_path = os.path.join(out_dir, "iot_shield_model.c")
    
    # Injeta o mapeamento das features como comentário no cabeçalho do C
    header = "/* ===================================================\n"
    header += " * IoT-Shield Random Forest Model (Transpiled)\n"
    header += " * Mapeamento do array de Features (double input[]):\n"
    header += " * ===================================================\n"
    for i, fname in enumerate(feature_names):
        header += f" * input[{i}] = {fname}\n"
    header += " * ===================================================\n"
    header += " * Retorno > 0.5 indica tráfego Malicioso.\n"
    header += " */\n\n"
    
    with open(c_path, "w") as f:
        f.write(header + c_code)
        
    print_ui(f"[bold green][+] Model successfully exported to C: {c_path}[/bold green]")
    
    # Run Benchmark
    from src.benchmark import run_benchmark
    run_benchmark(out_dir=out_dir)
    
    print_ui("\n[bold green][+] Phase 4 Completed![/bold green]")
