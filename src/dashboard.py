import threading
import time
import psutil
from rich.live import Live
from rich.table import Table
from rich.layout import Layout
from rich.panel import Panel

_stop_event = threading.Event()
_dashboard_thread = None

def generate_table():
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Metric")
    table.add_column("Value")

    # CPU
    cpu_percent = psutil.cpu_percent()
    table.add_row("CPU Usage (%)", f"{cpu_percent}%")

    # RAM
    ram = psutil.virtual_memory()
    ram_mb = ram.used / (1024 * 1024)
    table.add_row("RAM Usage (MB)", f"{ram_mb:.2f} MB")

    # Disk
    disk = psutil.disk_io_counters()
    if disk:
        read_mb = disk.read_bytes / (1024 * 1024)
        write_mb = disk.write_bytes / (1024 * 1024)
        table.add_row("Disk Read (MB)", f"{read_mb:.2f} MB")
        table.add_row("Disk Write (MB)", f"{write_mb:.2f} MB")
    
    return Panel(table, title="System Metrics Real-Time")

def dashboard_loop():
    with Live(generate_table(), refresh_per_second=2, transient=True) as live:
        while not _stop_event.is_set():
            live.update(generate_table())
            time.sleep(0.5)

def start_dashboard():
    global _dashboard_thread
    _stop_event.clear()
    _dashboard_thread = threading.Thread(target=dashboard_loop, daemon=True)
    _dashboard_thread.start()

def stop_dashboard():
    _stop_event.set()
    if _dashboard_thread:
        _dashboard_thread.join()
