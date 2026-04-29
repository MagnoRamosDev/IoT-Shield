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
from rich.console import Group

_stop_event = threading.Event()
_dashboard_thread = None

# Shared state updated by the main process before/during each phase
_phase_state = {
    "phase": "idle",       # "split" | "extract" | "idle"
    "split_tasks": [],     # list of (base_name, file_size_mb, splits_dir, max_bytes)
    "extract_tasks": [],   # list of (pcap_path, worker_id)
    "extract_tmp_dir": "",
}

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

    table = Table(show_header=True, header_style="bold cyan", expand=True)
    table.add_column("Wk", style="dim",   justify="right", min_width=3)
    table.add_column("File",              no_wrap=True)
    table.add_column("Chunks Written",    style="green", justify="center", min_width=14)
    table.add_column("Status",            justify="center", min_width=12)

    for pcap_path, worker_id in tasks:
        base = os.path.basename(pcap_path)
        # Count .npy chunks this worker has already flushed
        pattern = os.path.join(tmp_dir, f"w{worker_id}_c*.npy")
        chunks = len(glob.glob(pattern))

        if chunks == 0:
            status = "[yellow]Working…[/yellow]"
        else:
            status = f"[cyan]{chunks} chunks[/cyan]"

        # Check if the pcap file is still open by any process (rough heuristic)
        table.add_row(
            str(worker_id),
            base[:48],
            str(chunks),
            status,
        )

    return Panel(table, title="[bold]Phase 1b — Extraction Progress[/bold]")

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
