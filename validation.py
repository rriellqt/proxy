import sys
import os
import time
import shutil
import socket
import platform
import getpass
import subprocess
from datetime import datetime
from pathlib import Path

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.align import Align
    from rich.text import Text
    from rich.table import Table
    from rich import box
    import psutil
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "rich", "psutil"])
    from rich.console import Console
    from rich.panel import Panel
    from rich.align import Align
    from rich.text import Text
    from rich.table import Table
    from rich import box
    import psutil

launch = datetime.now().strftime("%Y-%m-%d %I:%M:%S %p")
console = Console()

border = "#D4C4A8"
title = "#C4A96A"
accent = "#A68A56"
text = "#F5EBD9"
dim = "#8B7A5B"
red = "#D96C6C"
green = "#A8B58A"

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def sigil():
    banner = r"""
 ██████╗ ██╗███████╗██╗     
 ██╔══██╗██║██╔════╝██║     
 ██████╔╝██║█████╗  ██║     
 ██╔══██╗██║██╔══╝  ██║     
 ██║  ██║██║███████╗███████╗
 ╚═╝  ╚═╝╚═╝╚══════╝╚══════╝
"""
    console.print(Align.center(Text(banner, style=f"bold {title}")))
    console.print()
    console.print(Align.center(Text("╔═[ SECURE GATEWAY / MAINTENANCE TERMINAL ]═╗", style=f"bold {accent}")))
    console.print()
    console.print(Align.center(Text("◆ SYSTEM CORE   ◆ NETWORK   ◆ SECURITY   ◆ SERVICES ◆", style=f"bold {dim}")))
    console.print(Align.center(Text("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", style=border)))
    console.print()

def human(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"

def listen(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
            return True
    except OSError:
        return False

def since():
    total = None
    try:
        with open("/proc/uptime", "r") as f:
            total = int(float(f.read().split()[0]))
    except Exception:
        pass
    if total is None:
        try:
            total = int(time.time() - psutil.boot_time())
        except Exception:
            pass
    if total is None or total < 60:
        return "session", launch
    d, rem = divmod(total, 86400)
    h, rem = divmod(rem, 3600)
    m, _ = divmod(rem, 60)
    try:
        boot = datetime.fromtimestamp(time.time() - total).strftime("%Y-%m-%d %I:%M %p")
    except Exception:
        boot = "unknown"
    return f"{d}d {h}h {m}m", boot

def scan():
    try:
        cpu = psutil.cpu_percent(interval=0.3)
    except Exception:
        cpu = 0.0
    try:
        cores = psutil.cpu_count(logical=True) or 0
    except Exception:
        cores = os.cpu_count() or 0
    model = (platform.processor() or platform.machine() or "unknown").strip()
    try:
        ram = psutil.virtual_memory()
    except Exception:
        ram = None
    try:
        disk = shutil.disk_usage(str(Path(__file__).parent))
    except Exception:
        disk = None
    try:
        host = socket.gethostname()
        ip = socket.gethostbyname(host)
    except Exception:
        host, ip = "unknown", "0.0.0.0"
    try:
        user = getpass.getuser()
    except Exception:
        user = "unknown"
    ports = {p: listen(p) for p in (80, 443, 3306, 5432)}
    uptime, boot = since()
    return {
        "cpu": cpu, "cores": cores, "model": model, "ram": ram, "disk": disk,
        "host": host, "ip": ip, "user": user, "ports": ports,
        "uptime": uptime, "boot": boot,
        "os": f"{platform.system()} {platform.release()}",
        "arch": platform.machine() or "unknown",
    }

def status():
    table = Table(show_header=False, box=None, padding=(0, 1), expand=True)
    table.add_column("Icon", width=5, justify="center")
    table.add_column("Component", width=23, style=f"bold {accent}")
    table.add_column("Value", style=text)
    table.add_row("💻", "SYSTEM CORE", "RIEL Secure Gateway")
    table.add_row("🔴", "SYSTEM STATUS", Text("OFFLINE", style=f"bold {red}"))
    table.add_row("⚙", "OPERATING MODE", "Maintenance")
    table.add_row("⛔", "SERVICES", Text("SUSPENDED", style=f"bold {red}"))
    table.add_row("💾", "DATA STATE", Text("PRESERVED", style=f"bold {green}"))
    table.add_row("🔒", "ACCESS", "Temporarily restricted")
    return table

def statuspanel():
    return Panel(status(), title=Text(" ◈ SYSTEM STATUS ◈ ", style=f"bold {title}"),
                 subtitle=Text("CORE::01", style=dim), border_style=border,
                 box=box.HEAVY, width=88, padding=(1, 2))

def maint():
    table = Table(show_header=False, box=None, padding=(0, 0), expand=True)
    table.add_column("Icon", width=5, justify="center")
    table.add_column("Message", style=accent)
    table.add_row("🔧", "Connection requests are temporarily disabled")
    table.add_row("🌐", "API gateway routes are currently offline")
    table.add_row("🔗", "Service URLs and callback routes are paused")
    table.add_row("🗄", "Database connections are protected")
    table.add_row("🔐", "Authentication sessions are temporarily suspended")
    table.add_row("🔄", "Services will return after maintenance completes")
    return table

def intro():
    content = Text()
    content.append("▲  MAINTENANCE PROTOCOL ACTIVE\n\n", style=f"bold {title}")
    content.append("The RIEL secure gateway is currently offline.\n", style=text)
    content.append("System components are undergoing maintenance,\n", style=text)
    content.append("API inspection, database checks, and endpoint review.", style=text)
    return content

def maintpanel():
    layout = Table(show_header=False, box=None, padding=(0, 0), expand=True)
    layout.add_column("Content", ratio=1)
    layout.add_row(Align.center(intro()))
    layout.add_row(Text(""))
    layout.add_row(maint())
    layout.add_row(Text(""))
    layout.add_row(Align.center(Text("⏳  Awaiting gateway restoration...", style=f"italic {dim}")))
    return Panel(layout, title=Text(" ══[ MAINTENANCE PROTOCOL ]══ ", style=f"bold {title}"),
                 border_style=title, box=box.DOUBLE, width=88, padding=(1, 3))

def diagnostic():
    d = scan()
    table = Table(show_header=False, box=None, padding=(0, 1), expand=True)
    table.add_column("Icon", width=5, justify="center")
    table.add_column("Module", width=23, style=f"bold {accent}")
    table.add_column("State", width=18)
    table.add_column("Description", style=text)
    cpu = d["cpu"]
    cpu_color = green if cpu < 50 else (accent if cpu < 85 else red)
    table.add_row("🧠", "CORE ENGINE", Text(f"● {d['cores']} CORES", style=f"bold {green}"), d["model"][:34])
    table.add_row("📊", "CPU LOAD", Text(f"● {cpu:.1f}%", style=f"bold {cpu_color}"), "Current utilization")
    ram = d["ram"]
    if ram:
        rc = green if ram.percent < 60 else (accent if ram.percent < 85 else red)
        table.add_row("🧮", "MEMORY", Text(f"● {ram.percent:.0f}%", style=f"bold {rc}"), f"{human(ram.used)} / {human(ram.total)}")
    else:
        table.add_row("🧮", "MEMORY", Text("● N/A", style=f"bold {dim}"), "Unavailable")
    disk = d["disk"]
    if disk:
        pct = (disk.used / disk.total * 100) if disk.total else 0
        dc = green if pct < 70 else (accent if pct < 90 else red)
        table.add_row("💿", "DISK", Text(f"● {pct:.0f}%", style=f"bold {dc}"), f"{human(disk.used)} / {human(disk.total)}")
    else:
        table.add_row("💿", "DISK", Text("● N/A", style=f"bold {dim}"), "Unavailable")
    table.add_row("🌐", "NETWORK GATEWAY", Text("● OFFLINE", style=f"bold {red}"), f"{d['host']} @ {d['ip']}")
    up = [str(p) for p, live in d["ports"].items() if live]
    if up:
        table.add_row("🔌", "API SERVICES", Text(f"● {len(up)} UP", style=f"bold {red}"), "Listening: " + ", ".join(up))
    else:
        table.add_row("🔌", "API SERVICES", Text("● STOPPED", style=f"bold {red}"), "None on 80/443/3306/5432")
    table.add_row("🔗", "URL ROUTING", Text("● PAUSED", style=f"bold {red}"), "Service URLs inactive")
    table.add_row("🔒", "SECURITY LAYER", Text("● ACTIVE", style=f"bold {green}"), f"Operator: {d['user']}")
    table.add_row("🗄", "DATABASE", Text("● SAFE", style=f"bold {green}"), "No external listeners")
    table.add_row("💾", "DATA STORAGE", Text("● SAFE", style=f"bold {green}"), f"{human(disk.free)} free" if disk else "Unavailable")
    if d["uptime"] == "session":
        table.add_row("⏱", "SESSION OPENED", Text(f"● {d['boot']}", style=f"bold {accent}"), "Current run start time")
    else:
        table.add_row("⏱", "UPTIME", Text(f"● {d['uptime']}", style=f"bold {accent}"), f"Since {d['boot']}")
    table.add_row("🐧", "PLATFORM", Text(f"● {d['arch']}", style=f"bold {accent}"), d["os"])
    return table

def diagnosticpanel():
    return Panel(diagnostic(), title=Text(" ◇ SYSTEM DIAGNOSTICS ◇ ", style=f"bold {accent}"),
                 border_style=border, box=box.HEAVY, width=88, padding=(1, 2))

def security():
    table = Table(show_header=False, box=None, padding=(0, 0), expand=True)
    table.add_column("Icon", width=5, justify="center")
    table.add_column("Notice", style=text)
    table.add_row("▲", "Avoid repeated requests while API services are offline.")
    table.add_row("▲", "Do not bypass the gateway maintenance state.")
    table.add_row("▲", "Inactive API and service URLs will reject requests.")
    table.add_row("▲", "Database operations remain restricted during maintenance.")
    table.add_row("▲", "Wait for the official restoration notice.")
    return table

def securitypanel():
    content = Table(show_header=False, box=None, padding=(0, 0), expand=True)
    content.add_column("Content", ratio=1)
    content.add_row(Align.center(Text("🔒  ACCESS CONTROL ACTIVE", style=f"bold {red}")))
    content.add_row(Text(""))
    content.add_row(Align.center(Text(
        "The maintenance state is enforced across the gateway,\n"
        "API routes, service URLs, authentication, and database interface.",
        style=text)))
    content.add_row(Text(""))
    content.add_row(security())
    return Panel(content, title=Text(" !!! ACCESS RESTRICTED !!! ", style=f"bold {red}"),
                 border_style=red, box=box.DOUBLE_EDGE, width=88, padding=(1, 3))

def bar():
    table = Table(show_header=False, box=None, padding=(0, 1), expand=True)
    table.add_column("Left", justify="center", ratio=1)
    table.add_column("Middle", justify="center", ratio=1)
    table.add_column("Right", justify="center", ratio=1)
    table.add_row(
        Text("🔴 SERVER OFFLINE", style=f"bold {accent}"),
        Text("⚙ MAINTENANCE", style=f"bold {accent}"),
        Text("⏳ AWAITING RESTORATION", style=f"bold {accent}"))
    return table

def footer():
    console.print()
    console.print(Align.center(Panel(bar(), border_style=border, box=box.HEAVY, width=76, padding=(0, 1))))
    console.print()
    console.print(Align.center(Text("✦  RIEL // SECURE SYSTEM ENVIRONMENT  ✦", style=f"bold {dim}")))
    console.print(Align.center(Text("connection terminated • API gateway offline • maintenance engaged", style=f"dim {dim}")))

def main():
    clear()
    sigil()
    console.print(Align.center(statuspanel()))
    console.print()
    console.print(Align.center(maintpanel()))
    console.print()
    console.print(Align.center(diagnosticpanel()))
    console.print()
    console.print(Align.center(securitypanel()))
    footer()
    sys.exit(0)

if __name__ == "__main__":
    main()