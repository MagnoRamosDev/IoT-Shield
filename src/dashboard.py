import os
import math
import glob
import threading
import time
import psutil
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.console import Group, Console

_stop_event = threading.Event()
_dashboard_thread = None

# Global console for static prints outside Live mode
_console = Console()

def print_ui(msg):
    _console.print(msg)

def print_table(table):
    _console.print(table)

# Shared state updated by the main process before/during each phase
_phase_state = {
    "phase": "idle",       # "split" | "extract" | "idle"
    "split_tasks": [],     # list of (base_name, file_size_mb, splits_dir, max_bytes)
    "extract_tasks": [],   # list of (pcap_path, worker_id)
    "extract_tmp_dir": "",
}

def display_metrics(acc, prec, rec, f1):
    metrics_table = Table(title="Performance Metrics", show_header=True, header_style="bold magenta")
    metrics_table.add_column("Metric", style="dim", width=20)
    metrics_table.add_column("Score")
    metrics_table.add_row("Accuracy", f"{acc * 100:.5f}%")
    metrics_table.add_row("Precision", f"{prec * 100:.5f}%")
    metrics_table.add_row("Recall", f"{rec * 100:.5f}%")
    metrics_table.add_row("F1-Score", f"{f1 * 100:.5f}%")
    print_ui("\n")
    print_table(metrics_table)
    print_ui("\n")

def display_confusion_matrix(cm):
    cm_table = Table(title="Confusion Matrix", show_header=True, header_style="bold magenta")
    cm_table.add_column("Actual \\ Predicted")
    cm_table.add_column("Class 0 (Benign)")
    cm_table.add_column("Class 1 (Malicious)")
    cm_table.add_row("Class 0 (Benign)", str(cm[0][0]), str(cm[0][1]))
    cm_table.add_row("Class 1 (Malicious)", str(cm[1][0]), str(cm[1][1]))
    print_table(cm_table)
    print_ui("\n")

def display_protocol_confusion_matrix(proto_rows):
    proto_cm_table = Table(title="Confusion Matrix by Protocol", show_header=True, header_style="bold magenta")
    proto_cm_table.add_column("Protocol")
    proto_cm_table.add_column("TN (Benign -> Benign)", style="green")
    proto_cm_table.add_column("FP (Benign -> Mal)", style="red")
    proto_cm_table.add_column("FN (Mal -> Benign)", style="yellow")
    proto_cm_table.add_column("TP (Mal -> Mal)", style="green")
    for row in proto_rows:
        proto_cm_table.add_row(*row)
    print_table(proto_cm_table)
    print_ui("\n")

def display_threshold_sweep(sweep_rows, threshold):
    print_ui("[bold cyan][*] Threshold Sweep — tradeoff overview:[/bold cyan]")
    sweep_table = Table(show_header=True, header_style="bold yellow")
    sweep_table.add_column("Threshold",                      justify="center", style="cyan",   min_width=12)
    sweep_table.add_column("Benign Blocked (FP)",            justify="center", style="red",    min_width=20)
    sweep_table.add_column("Malicious Passed (FN)",          justify="center", style="yellow", min_width=22)
    sweep_table.add_column("Accuracy",                       justify="center", style="green",  min_width=10)
    
    for row in sweep_rows:
        sweep_table.add_row(*row)
        
    print_table(sweep_table)
    print_ui(
        "[dim]Tip: use [bold]--threshold 0.6[/bold] to block only high-confidence malicious flows,[/dim]\n"
        "[dim]     reducing benign false-positives at the cost of passing more malicious traffic.[/dim]\n"
    )

def display_feature_importance(feat_rows):
    feat_table = Table(title="Random Forest Feature Importance (MDI)", show_header=True, header_style="bold yellow")
    feat_table.add_column("Rank", justify="right", style="cyan", no_wrap=True)
    feat_table.add_column("Feature Name", style="magenta")
    feat_table.add_column("Importance (% of Tree Splits)", style="green")
    for row in feat_rows:
        feat_table.add_row(*row)
    print_table(feat_table)

def set_split_phase(tasks_info, splits_dir, max_bytes):
    """
    tasks_info: list of (base_name, file_size_bytes) for every file that will be split.
    """
    _phase_state["phase"] = "split"
    _phase_state["split_tasks"] = [(b, s, splits_dir, max_bytes) for b, s in tasks_info]

def set_extract_phase(pcap_tasks, tmp_dir):
    """
    pcap_tasks: list of (pcap_path, worker_id)
    """
    _phase_state["phase"] = "extract"
    _phase_state["extract_tasks"] = pcap_tasks
    _phase_state["extract_tmp_dir"] = tmp_dir

def _get_pipeline_procs():
    current = psutil.Process(os.getpid())
    procs = [current]
    try:
        procs += current.children(recursive=True)
    except psutil.NoSuchProcess:
        pass
    return procs

def _make_metrics_table(prev_state):
    """Build the top metrics row. Mutates prev_state dict for disk delta."""
    table = Table(show_header=True, header_style="bold magenta", expand=True)
    table.add_column("Metric", style="dim", min_width=20)
    table.add_column("Value", min_width=16)

    cpu_pct = psutil.cpu_percent()
    table.add_row("CPU Usage (%)", f"{cpu_pct:.1f}%")

    ram_mb = 0.0
    for p in _get_pipeline_procs():
        try:
            ram_mb += p.memory_info().rss / (1024 * 1024)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    table.add_row("Pipeline RAM (MB)", f"{ram_mb:.1f} MB")

    now = time.time()
    cur_disk = psutil.disk_io_counters()
    elapsed = max(now - prev_state["ts"], 0.001)
    read_rate  = (cur_disk.read_bytes  - prev_state["read"])  / (1024 * 1024) / elapsed
    write_rate = (cur_disk.write_bytes - prev_state["write"]) / (1024 * 1024) / elapsed
    prev_state["read"]  = cur_disk.read_bytes
    prev_state["write"] = cur_disk.write_bytes
    prev_state["ts"]    = now

    table.add_row("Disk Read  (MB/s)", f"{read_rate:.2f} MB/s")
    table.add_row("Disk Write (MB/s)", f"{write_rate:.2f} MB/s")

    return Panel(table, title="Pipeline Metrics (Real-Time)")

def _make_split_table():
    tasks = _phase_state["split_tasks"]
    if not tasks:
        return None

    table = Table(show_header=True, header_style="bold cyan", expand=True)
    table.add_column("File",        style="white",  no_wrap=True)
    table.add_column("Size",        style="dim",    justify="right", min_width=9)
    table.add_column("Parts Done",  style="green",  justify="center", min_width=10)
    table.add_column("Expected",    style="yellow", justify="center", min_width=9)
    table.add_column("Status",      justify="center", min_width=12)

    for base_name, file_size_bytes, splits_dir, max_bytes in tasks:
        size_mb = file_size_bytes / (1024 * 1024)

        if file_size_bytes <= max_bytes:
            # No split needed — will pass through as-is
            table.add_row(
                base_name[:42],
                f"{size_mb:.0f} MB",
                "-",
                "-",
                "[dim]No split[/dim]",
            )
            continue

        expected = math.ceil(file_size_bytes / max_bytes)
        # Count actual part files on disk
        pattern = os.path.join(splits_dir, f"{base_name}_part*")
        done = len(glob.glob(pattern))

        if done == 0:
            status = "[yellow]Waiting[/yellow]"
        elif done < expected:
            pct = done / expected * 100
            status = f"[cyan]{pct:.0f}%[/cyan]"
        else:
            status = "[green]Done ✓[/green]"

        table.add_row(
            base_name[:42],
            f"{size_mb:.0f} MB",
            str(done),
            str(expected),
            status,
        )

    return Panel(table, title="[bold]Phase 1a — Split Progress[/bold]")

def _make_extract_table():
    tasks = _phase_state["extract_tasks"]
    tmp_dir = _phase_state["extract_tmp_dir"]
    if not tasks or not tmp_dir:
        return None

    # Discovers which files are actively open in memory
    active_files = []
    for p in _get_pipeline_procs():
        try:
            for f in p.open_files():
                path = f.path
                if path.endswith(".pcap") or path.endswith(".pcapng"):
                    active_files.append(os.path.basename(path))
        except Exception:
            pass
    
    active_files = list(set(active_files))
    active_files.sort()

    table = Table(show_header=False, expand=True)
    table.add_column("Key", style="bold cyan", min_width=20)
    table.add_column("Value")

    total_tasks = len(tasks)
    completed_tasks = len(glob.glob(os.path.join(tmp_dir, "*.done")))
    error_tasks = len(glob.glob(os.path.join(tmp_dir, "*.err")))
    remaining_tasks = total_tasks - completed_tasks - error_tasks

    table.add_row("Total Splits in Queue", str(total_tasks))
    table.add_row("Finished", f"[green]{completed_tasks}[/green]")
    if error_tasks > 0:
        table.add_row("With Error", f"[red]{error_tasks}[/red]")
    table.add_row("Remaining", f"[yellow]{remaining_tasks}[/yellow]")

    if active_files:
        # Shows open file names so the user knows what's happening
        display_files = active_files[:14] # show up to 14
        active_str = "\n".join([f"[dim]>[/dim] {f[:70]}" for f in display_files])
        if len(active_files) > 14:
            active_str += f"\n[dim]... and {len(active_files) - 14} more[/dim]"
        table.add_row("Processing Now", f"[yellow]{active_str}[/yellow]")
    else:
        table.add_row("Processing Now", "[dim]Fetching tasks...[/dim]")

    return Panel(table, title="[bold]Phase 1b — Feature Extraction[/bold]")

def dashboard_loop():
    d = psutil.disk_io_counters()
    prev_state = {"ts": time.time(), "read": d.read_bytes, "write": d.write_bytes}

    def build_layout():
        parts = [_make_metrics_table(prev_state)]
        phase = _phase_state["phase"]
        if phase == "split":
            t = _make_split_table()
            if t:
                parts.append(t)
        elif phase == "extract":
            t = _make_extract_table()
            if t:
                parts.append(t)
        return Group(*parts)

    with Live(build_layout(), refresh_per_second=2, transient=True) as live:
        while not _stop_event.is_set():
            time.sleep(0.5)
            live.update(build_layout())

def start_dashboard():
    global _dashboard_thread
    _stop_event.clear()
    _dashboard_thread = threading.Thread(target=dashboard_loop, daemon=True)
    _dashboard_thread.start()

def stop_dashboard():
    _stop_event.set()
    if _dashboard_thread:
        _dashboard_thread.join(timeout=3)
