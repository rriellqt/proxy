import sys
import os
import time
import urllib.parse
import threading
import base64
import json
import re
from pathlib import Path
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding='utf-8', errors='backslashreplace')
    except:
        pass

try:
    from curl_cffi import requests
except ImportError:
    sys.exit("[!] Missing: pip install curl_cffi")

try:
    from rich import box
    from rich.align import Align
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
except ImportError as e:
    sys.exit(f"[!] Rich import failed: {e}")

checkers = [
    ("https://api.ipify.org?format=json", "json", "ip"),
    ("https://ipinfo.io/json", "json", "ip"),
    ("https://ifconfig.me/all.json", "json", "ip_addr"),
    ("https://checkip.amazonaws.com", "text", None),
    ("https://icanhazip.com", "text", None),
]

veils = ["ᴀᴘɪ ᴏɴᴇ", "ᴀᴘɪ ᴛᴡᴏ", "ᴀᴘɪ ᴛʜʀᴇᴇ", "ᴀᴘɪ ꜰᴏᴜʀ", "ᴀᴘɪ ꜰɪᴠᴇ"]

native = ("http", "https", "socks4", "socks4a", "socks5", "socks5h")
roster = frozenset({
    "http", "https", "socks", "socks4", "socks4a", "socks5", "socks5h",
    "ss", "ssr", "vmess", "vless", "trojan", "trojan-go",
    "hysteria", "hysteria2", "hy2", "tuic", "wg", "wireguard",
    "ssh", "mtproto", "snell", "brook", "naive", "naive+https",
    "juicity", "anytls", "mieru",
})
aliases = {
    "socks": "socks5",
    "hy2": "hysteria2",
    "wg": "wireguard",
    "naive+https": "naive",
}

catalog = {
    "floppydata.com": ("Floppydata", "residential"),
    "iproyal.com": ("IPRoyal", "residential"),
    "smartproxy.com": ("Smartproxy", "residential"),
    "smartproxy.io": ("Smartproxy", "residential"),
    "decodo.com": ("Decodo", "residential"),
    "oxylabs.io": ("Oxylabs", "residential"),
    "soax.com": ("SOAX", "residential"),
    "brightdata.com": ("Bright Data", "residential"),
    "brightdata.io": ("Bright Data", "residential"),
    "luminati.io": ("Bright Data", "residential"),
    "superproxy.io": ("Bright Data", "residential"),
    "webshare.io": ("Webshare", "datacenter"),
    "netnut.io": ("NetNut", "residential"),
    "packetstream.io": ("PacketStream", "residential"),
    "rayobyte.com": ("Rayobyte", "datacenter"),
    "proxyscrape.com": ("ProxyScrape", "datacenter"),
    "proxyempire.io": ("ProxyEmpire", "residential"),
    "infatica.io": ("Infatica", "residential"),
    "nodemaven.com": ("NodeMaven", "residential"),
    "evomi.com": ("Evomi", "residential"),
    "abcproxy.com": ("ABCProxy", "residential"),
    "922proxy.com": ("922 S5", "residential"),
    "piaproxy.com": ("PIA S5", "residential"),
    "kookeey.com": ("Kookeey", "residential"),
    "ipidea.io": ("IPIDEA", "residential"),
    "mpproxy.io": ("MPProxy", "residential"),
    "proxidize.com": ("Proxidize", "mobile"),
    "massive.io": ("Massive", "residential"),
    "proxy-cheap.com": ("Proxy-Cheap", "datacenter"),
    "nimbleway.com": ("Nimbleway", "residential"),
    "proxyless.io": ("Proxyless", "residential"),
    "geosurf.io": ("GeoSurf", "residential"),
    "geosurf.com": ("GeoSurf", "residential"),
    "proxy.io": ("Proxy.io", "residential"),
    "iproxy.online": ("iProxy", "mobile"),
    "brightdata.cn": ("Bright Data", "residential"),
}

prefixes = {
    "geo": ("geotarget", None),
    "res": ("residential", "residential"),
    "residential": ("residential", "residential"),
    "rotate": ("rotating", None),
    "rotating": ("rotating", None),
    "pool": ("pool", None),
    "gate": ("gateway", None),
    "gw": ("gateway", None),
    "brd": ("brightdata-convention", "residential"),
    "pr": ("oxylabs-convention", "residential"),
    "mobile": ("mobile", "mobile"),
    "mob": ("mobile", "mobile"),
    "lte": ("mobile", "mobile"),
    "dc": ("datacenter", "datacenter"),
    "datacenter": ("datacenter", "datacenter"),
    "server": ("datacenter", "datacenter"),
    "ipv4": ("ipv4", None),
    "ipv6": ("ipv6", None),
}

ranges = [
    (1, 1023, "well-known"),
    (1024, 9999, "ephemeral"),
    (10000, 29999, "residential-pool"),
    (30000, 49151, "provider"),
    (49152, 65535, "dynamic"),
]

keywords = [
    ("rotate", "rotating"),
    ("rotating", "rotating"),
    ("sticky", "sticky-session"),
    ("session", "sticky-session"),
    ("country", "geo-targeted"),
    ("region", "geo-targeted"),
    ("city", "geo-targeted"),
    ("asn", "asn-targeted"),
    ("isp", "isp-targeted"),
    ("residential", "residential"),
    ("datacenter", "datacenter"),
    ("mobile", "mobile"),
    ("lte", "mobile"),
    ("4g", "mobile"),
    ("5g", "mobile"),
    ("zone", "zone-scoped"),
]

limit = 15.0
hands = 100
proto = "http"
real_ip = ""
target = 0

term = Console()
lock = threading.Lock()

data = {
    'total': 0,
    'tick': 0,
    'good': 0,
    'bad': 0,
    'start': 0.0,
    'lats': [],
    'fast': 99999.0,
    'slow': 0.0,
    'feed': deque(maxlen=6),
    'best': [],
    'status': 'ACTIVE',
    'b2': 0,
    'b3': 0,
    'b4': 0,
    'b5': 0,
    'unsupported': 0
}

def show(item):
    if isinstance(item, str):
        try:
            item = Text.from_markup(item)
        except Exception:
            item = Text(item)
    term.print(Align.center(item))

def ctr(text):
    try:
        plain = Text.from_markup(text).plain
    except Exception:
        plain = text
    pad = max(0, (term.width - len(plain)) // 2)
    return " " * pad + text

def wipe():
    os.system('cls' if os.name == 'nt' else 'clear')

def banner():
    wipe()
    rows = [
        r"██████╗ ██████╗  ██████╗ ██╗  ██╗██╗   ██╗",
        r"██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝╚██╗ ██╔╝",
        r"██████╔╝██████╔╝██║   ██║ ╚███╔╝  ╚████╔╝ ",
        r"██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗   ╚██╔╝  ",
        r"██║     ██║  ██║╚██████╔╝██╔╝ ██╗   ██║   ",
        r"╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ",
    ]
    txt = Text("\n".join(rows), style="bold yellow")
    pnl = Panel(txt, border_style="yellow", box=box.ROUNDED, expand=False)
    term.print(Align.center(pnl))
    term.print()

def detect():
    global real_ip
    if real_ip:
        return
    for url, kind, key in checkers:
        try:
            r = requests.get(url, impersonate="chrome", timeout=8, verify=False)
            if r.status_code == 200:
                if kind == "json":
                    try:
                        ip = r.json().get(key, "").strip()
                    except:
                        ip = ""
                else:
                    ip = r.text.strip()
                if ip and len(ip) < 64:
                    real_ip = ip
                    return
        except:
            continue

def scan():
    paths = []
    folder = Path("Proxies")
    if folder.exists() and folder.is_dir():
        paths.extend(folder.glob("*.txt"))
    paths.extend(Path(".").glob("*.txt"))
    valid = []
    for p in paths:
        if "combo" in p.name.lower():
            continue
        if p.name in ("working.txt", "unsupported.txt", "datacenter.txt", "residential.txt", "mobile.txt", "http.txt", "socks4.txt", "socks5.txt"):
            continue
        valid.append(p)
    return list(set(valid))

def render(n):
    span = float(n)
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if span < 1024 or unit == 'TB':
            if unit == 'B':
                return f"{int(span)} B"
            return f"{span:.1f} {unit}"
        span /= 1024.0
    return f"{span:.1f} TB"

def choose(files):
    term.print()
    tb = Table(show_header=True, box=box.HORIZONTALS, border_style="yellow", header_style="bold bright_yellow")
    tb.add_column("#", style="bright_yellow")
    tb.add_column("Filename", style="bold white")
    tb.add_column("Size", style="white", justify="right")
    tb.add_column("Bar", style="bright_yellow")

    largest = max([f.stat().st_size for f in files]) if files else 1

    for i, f in enumerate(files, 1):
        size = f.stat().st_size
        bar_w = 16
        filled = int(size / largest * bar_w)
        bar = f"[bright_yellow]{'█' * filled}[/bright_yellow][dim]{'░' * (bar_w - filled)}[/dim]"
        tb.add_row(str(i), f.name, render(size), bar)

    term.print(Align.center(Panel(tb, title="[bold white]PROXY FILES[/bold white]", border_style="bright_yellow", box=box.DOUBLE_EDGE, expand=False)))

    while True:
        try:
            raw = term.input(ctr("[bold yellow]❯ Select file # or 'auto' ❯ [/bold yellow]")).strip().lower()
        except (KeyboardInterrupt, EOFError):
            sys.exit(0)

        if raw == 'auto':
            return max(files, key=lambda x: x.stat().st_size)
        try:
            idx = int(raw)
            if 1 <= idx <= len(files):
                return files[idx - 1]
        except ValueError:
            pass
        show("[red]Invalid selection.[/red]")

def head():
    now = time.time()
    span = max(now - data['start'], 0.001) if data['start'] > 0 else 0.001
    pace = data['tick'] / span
    tb = Table.grid(padding=(0, 2))
    tb.add_column(justify="left")
    tb.add_column(justify="left")
    tb.add_column(justify="left")
    tb.add_column(justify="left")
    tb.add_column(justify="right")
    tb.add_row(
        "[bold yellow]◆ PROXY CHECKER v2.0[/bold yellow]  [white]@rriellqt[/white]",
        f"[bold yellow]🎀 {pace:.1f}/s[/bold yellow]",
        f"[white]{data['tick']}/{data['total']}[/white]",
        f"[white]◷ {int(span//60):02d}:{int(span%60):02d}[/white]",
        f"[bold green]● {data['status']}[/bold green]"
    )
    return Panel(tb, box=box.HORIZONTALS, border_style="yellow", padding=(0, 1))

def meter():
    pct = (data['tick'] / data['total']) * 100 if data['total'] else 0
    now = time.time()
    span = max(now - data['start'], 0.001) if data['start'] > 0 else 0.001
    pace = data['tick'] / span
    eta = (data['total'] - data['tick']) / pace if pace > 0 else 0
    et = f"{int(eta//60):02d}m {int(eta%60):02d}s" if eta > 0 else "--"
    length = 40
    filled = int(pct / 100 * length)
    bar = f"[yellow]{'█' * filled}[/yellow][dim]{'░' * (length - filled)}[/dim]"
    txt = Text.from_markup(f"PROGRESS: [ [white]{pct:5.1f}%[/white] ]  {data['tick']}/{data['total']}  ETA: {et}\n{bar}")
    return Panel(txt, box=box.HORIZONTALS, border_style="dim", padding=(0, 1))

def tally():
    tb = Table.grid(padding=(0, 2), expand=True)
    tb.add_column(style="bold", justify="right", width=12)
    tb.add_column(style="bright_white", justify="right", width=8)
    tb.add_column(style="dim", justify="left")
    vpct = (data['good'] / data['tick'] * 100) if data['tick'] else 0
    ipct = (data['bad'] / data['tick'] * 100) if data['tick'] else 0
    cpct = (data['tick'] / data['total'] * 100) if data['total'] else 0
    rpct = (data['total'] - data['tick']) / data['total'] * 100 if data['total'] else 0
    tb.add_row("[green]✓ Strong[/green]", f"[green]{data['good']}[/green]", f"({vpct:.1f}%)")
    tb.add_row("[red]✗ Rejected[/red]", f"[red]{data['bad']}[/red]", f"({ipct:.1f}%)")
    tb.add_row("[cyan]◈ Checked[/cyan]", f"[cyan]{data['tick']}[/cyan]", f"({cpct:.1f}%)")
    tb.add_row("[yellow]◆ Remaining[/yellow]", f"[yellow]{data['total'] - data['tick']}[/yellow]", f"({rpct:.1f}%)")
    return Panel(tb, title="[bold yellow]◆ STATISTICS[/bold yellow]", title_align="left", border_style="yellow", box=box.ROUNDED)

def env():
    tb = Table.grid(padding=(0, 2), expand=True)
    tb.add_column(style="bold", justify="right", width=12)
    tb.add_column(style="bright_white", justify="right")
    tb.add_row("[cyan]⚙ Scheme[/cyan]", f"[cyan]{proto}[/cyan]")
    tb.add_row("[green]◉ Status[/green]", f"[green]{data['status']}[/green]")
    tb.add_row("[yellow]🎀 Threads[/yellow]", f"[yellow]{hands}[/yellow]")
    tb.add_row("[white]⏱ Timeout[/white]", f"[white]{limit}s[/white]")
    tb.add_row("[white]◆ APIs[/white]", f"[white]{len(checkers)}[/white]")
    return Panel(tb, title="[bold yellow]◉ SYSTEM[/bold yellow]", title_align="left", border_style="yellow", box=box.ROUNDED)

def buckets():
    tb = Table.grid(padding=(0, 2), expand=True)
    tb.add_column(style="bold", justify="right", width=14)
    tb.add_column(style="bright_white", justify="right", width=8)
    tb.add_column(style="dim", justify="left")

    tot = data['good'] if data['good'] else 1

    p2 = (data['b2'] / tot * 100)
    p3 = (data['b3'] / tot * 100)
    p4 = (data['b4'] / tot * 100)
    p5 = (data['b5'] / tot * 100)

    tb.add_row("[cyan]< 100ms[/cyan]", f"[cyan]{data['b2']}[/cyan]", f"({p2:.1f}%)")
    tb.add_row("[green]100 - 999ms[/green]", f"[green]{data['b3']}[/green]", f"({p3:.1f}%)")
    tb.add_row("[yellow]1000 - 9999ms[/yellow]", f"[yellow]{data['b4']}[/yellow]", f"({p4:.1f}%)")
    tb.add_row("[red]> 10000ms[/red]", f"[red]{data['b5']}[/red]", f"({p5:.1f}%)")

    return Panel(tb, title="[bold yellow]◆ LATENCY BUCKETS[/bold yellow]", title_align="left", border_style="yellow", box=box.ROUNDED)

def best():
    tb = Table.grid(padding=(0, 2), expand=True)
    tb.add_column(style="dim", justify="right", width=6)
    tb.add_column(style="bright_white")
    tb.add_column(style="green", justify="right")
    for i, (lat, (h, p, u, w, s)) in enumerate(data['best'][:4]):
        tb.add_row(f"{i+1}", f"{h}:{p}", f"{lat:.1f}ms")
    if not data['best']:
        tb.add_row("", "[dim]waiting...[/dim]", "")
    return Panel(tb, title="[bold yellow]▲ TOP PROXIES[/bold yellow]", title_align="left", border_style="yellow", box=box.ROUNDED)

def stream():
    tb = Table.grid(padding=(0, 1), expand=True)
    tb.add_column(style="dim", justify="right", width=6)
    tb.add_column(style="bright_white", width=3)
    tb.add_column(style="bright_white")
    for idx, st, msg, lat in reversed(list(data['feed'])):
        if st == 'ok':
            tb.add_row(str(idx), "[green]✓[/green]", f"[green]{msg}  {lat:.1f}ms[/green]")
        else:
            tb.add_row(str(idx), "[red]✗[/red]", f"[red]{msg}[/red]")
    if not data['feed']:
        tb.add_row("", "", "[dim]idle...[/dim]")
    return Panel(tb, title="[bold yellow]◆ LIVE FEED[/bold yellow]", title_align="left", border_style="yellow", box=box.ROUNDED)

def draw():
    layout = Layout()
    layout.split_column(
        Layout(name="head", size=3),
        Layout(name="bar", size=4),
        Layout(name="mid", size=10),
        Layout(name="top", size=8),
        Layout(name="feed", size=8)
    )
    layout["mid"].split_row(Layout(name="tally"), Layout(name="env"))
    layout["top"].split_row(Layout(name="buckets"), Layout(name="best"))

    layout["head"].update(head())
    layout["bar"].update(meter())
    layout["mid"]["tally"].update(tally())
    layout["mid"]["env"].update(env())
    layout["top"]["buckets"].update(buckets())
    layout["top"]["best"].update(best())
    layout["feed"].update(stream())
    return layout

def unvault(s):
    s = s.strip()
    if not s or len(s) < 8:
        return None
    for style in ('standard', 'urlsafe'):
        try:
            pad = s + '=' * (-len(s) % 4)
            if style == 'standard':
                out = base64.b64decode(pad, validate=False).decode('utf-8', 'ignore')
            else:
                out = base64.urlsafe_b64decode(pad).decode('utf-8', 'ignore')
            if out and any(c in out for c in (':', '@', '}', '{', '\n')):
                return out.strip()
        except Exception:
            continue
    return None

def cleave(s):
    s = s.strip()
    if not s:
        return None
    if s.startswith('['):
        end = s.find(']')
        if end < 0:
            return None
        host = s[1:end]
        rest = s[end+1:]
        if not rest.startswith(':'):
            return None
        try:
            port = int(rest[1:])
        except ValueError:
            return None
        if not host or not (1 <= port <= 65535):
            return None
        return host, port
    if ':' not in s:
        return None
    host, pstr = s.rsplit(':', 1)
    try:
        port = int(pstr)
    except ValueError:
        return None
    if not host or not (1 <= port <= 65535):
        return None
    return host, port

def pluck(fields, scheme):
    if len(fields) >= 4:
        try:
            port = int(fields[1])
            if 1 <= port <= 65535 and fields[0]:
                return (scheme, fields[0], port, fields[2], fields[3])
        except ValueError:
            pass
        try:
            port = int(fields[3])
            if 1 <= port <= 65535 and fields[2]:
                return (scheme, fields[2], port, fields[0], fields[1])
        except ValueError:
            return None
    elif len(fields) == 2:
        try:
            port = int(fields[1])
            if 1 <= port <= 65535 and fields[0]:
                return (scheme, fields[0], port, "", "")
        except ValueError:
            return None
    return None

def shard(rest):
    rest = rest.split('#', 1)[0]
    if "@" in rest:
        creds, hp = rest.rsplit("@", 1)
        decoded = unvault(creds)
        if decoded and ":" in decoded:
            method, pw = decoded.split(":", 1)
            pair = cleave(hp)
            if pair:
                return ("ss", pair[0], pair[1], method, pw)
        return None
    decoded = unvault(rest)
    if decoded and "@" in decoded:
        return shard(decoded)
    return None

def slab(rest):
    rest = rest.split('#', 1)[0]
    decoded = unvault(rest)
    if not decoded:
        return None
    parts = decoded.split(':')
    if len(parts) < 4:
        return None
    try:
        port = int(parts[1])
    except (ValueError, IndexError):
        return None
    if not parts[0] or not (1 <= port <= 65535):
        return None
    pw = parts[3] if len(parts) > 3 else ""
    return ("ssr", parts[0], port, "", pw)

def mote(rest):
    rest = rest.split('#', 1)[0]
    decoded = unvault(rest)
    if not decoded:
        return None
    try:
        blob = json.loads(decoded)
    except Exception:
        return None
    if not isinstance(blob, dict):
        return None
    host = blob.get("add", "")
    try:
        port = int(blob.get("port", 0))
    except (ValueError, TypeError):
        return None
    if not host or not (1 <= port <= 65535):
        return None
    return ("vmess", host, port, str(blob.get("id", "")), "")

def siphon(rest, scheme):
    rest = rest.split('#', 1)[0]
    if "?" in rest:
        rest = rest.split("?", 1)[0]
    user, pw = "", ""
    if "@" in rest:
        creds, rest = rest.rsplit("@", 1)
        if ":" in creds:
            user, pw = creds.split(":", 1)
        else:
            user = creds
    pair = cleave(rest.rstrip('/'))
    if not pair:
        return None
    return (scheme, pair[0], pair[1], user, pw)

def curio(scheme, rest):
    if scheme == "ss":
        return shard(rest)
    if scheme == "ssr":
        return slab(rest)
    if scheme == "vmess":
        return mote(rest)
    return siphon(rest, scheme)

def pebble(item):
    if not isinstance(item, dict):
        return None
    host = item.get("server") or item.get("add") or item.get("host") or item.get("address") or ""
    try:
        port = int(item.get("port") or item.get("server_port") or 0)
    except (ValueError, TypeError):
        return None
    if not host or not (1 <= port <= 65535):
        return None
    scheme = (item.get("type") or "http").lower()
    if scheme in aliases:
        scheme = aliases[scheme]
    user = item.get("username") or item.get("user") or item.get("uuid") or item.get("id") or ""
    pw = item.get("password") or ""
    return (scheme, str(host), port, str(user), str(pw))

def shuck(blob):
    out = []
    if isinstance(blob, list):
        for item in blob:
            p = pebble(item)
            if p:
                out.append(p)
        return out
    if isinstance(blob, dict):
        for key in ("servers", "proxies", "outbounds"):
            if key in blob and isinstance(blob[key], list):
                for item in blob[key]:
                    p = pebble(item)
                    if p:
                        out.append(p)
                return out
        p = pebble(blob)
        if p:
            out.append(p)
    return out

def shale(blob):
    if not isinstance(blob, dict):
        return []
    proxies = blob.get("proxies")
    if not isinstance(proxies, list):
        return []
    return [p for p in (pebble(item) for item in proxies) if p]

def pairing(raw, scheme):
    for mark in ('#', '?'):
        if mark in raw:
            raw = raw.split(mark, 1)[0]
    raw = raw.strip().rstrip('/')
    if not raw:
        return None

    user, pw = "", ""

    if raw.startswith('['):
        end = raw.find(']')
        if end < 0:
            return None
        host = raw[1:end]
        rest = raw[end+1:]
        if not rest.startswith(':'):
            return None
        rest = rest[1:]
        parts = rest.split(':')
        try:
            port = int(parts[0])
        except (ValueError, IndexError):
            return None
        if not host or not (1 <= port <= 65535):
            return None
        user = parts[1] if len(parts) > 1 else ""
        pw = parts[2] if len(parts) > 2 else ""
        return (scheme, host, port, user, pw)

    if "@" in raw:
        creds, hp = raw.rsplit("@", 1)
        if ":" in creds:
            user, pw = creds.split(":", 1)
        else:
            user = creds
        raw = hp

    pair = cleave(raw)
    if pair:
        return (scheme, pair[0], pair[1], user, pw)

    if user and pw:
        return None

    for d in (':', ' ', ';', ',', '|', '\t'):
        fields = raw.split(d) if d != ' ' else raw.split()
        if len(fields) >= 2:
            p = pluck(fields, scheme)
            if p:
                return p
    return None

def parse(raw):
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None

    if not any(c in raw for c in (':', '@', ' ')):
        if len(raw) >= 16:
            decoded = unvault(raw)
            if decoded:
                inner = parse(decoded)
                if inner:
                    return inner

    if "://" in raw:
        scheme, rest = raw.split("://", 1)
        scheme = scheme.lower()
        if scheme in aliases:
            scheme = aliases[scheme]
        if scheme in roster:
            if scheme in native:
                return pairing(rest, scheme)
            return curio(scheme, rest)
        return pairing(raw, "http")

    return pairing(raw, "http")

def forage(path):
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    stripped = text.strip()
    if not stripped:
        return []

    if not any(c in stripped[:200] for c in (':', '@', '\n')):
        decoded = unvault(stripped)
        if decoded:
            stripped = decoded

    if stripped.startswith('{') or stripped.startswith('['):
        try:
            blob = json.loads(stripped)
            entries = shuck(blob)
            if entries:
                return entries
        except Exception:
            pass

    try:
        import yaml
        blob = yaml.safe_load(stripped)
        entries = shale(blob)
        if entries:
            return entries
    except Exception:
        pass

    entries = []
    for ln in stripped.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith('#') or ln.startswith('//') or ln.startswith(';'):
            continue
        p = parse(ln)
        if p:
            entries.append(p)
    return entries

def sieve(text):
    stripped = text.strip()
    encoding = 'none'
    container = 'plain'
    body = stripped

    if not any(c in stripped[:200] for c in (':', '@', '\n')):
        decoded = unvault(stripped)
        if decoded:
            encoding = 'base64'
            body = decoded.strip()

    if body.startswith('{'):
        try:
            blob = json.loads(body)
            if isinstance(blob, dict):
                if 'servers' in blob:
                    container = 'json-sip008'
                elif 'proxies' in blob:
                    container = 'json-clash'
                elif 'outbounds' in blob:
                    container = 'json-v2rayn'
                else:
                    container = 'json-object'
            elif isinstance(blob, list):
                container = 'json-array'
        except Exception:
            pass
    elif body.startswith('['):
        try:
            json.loads(body)
            container = 'json-array'
        except Exception:
            pass
    elif 'proxies:' in body or 'proxy-groups:' in body:
        container = 'yaml-clash'
    elif '\n' in body:
        try:
            import yaml
            blob = yaml.safe_load(body)
            if isinstance(blob, dict):
                container = 'yaml-generic'
        except Exception:
            pass

    return encoding, container, body

def sniff(lines):
    if not lines:
        return []
    sample = lines[:200]
    results = []
    splitters = (
        ('colon', lambda s: s.split(':')),
        ('space', lambda s: s.split()),
        ('semicolon', lambda s: s.split(';')),
        ('comma', lambda s: s.split(',')),
        ('pipe', lambda s: s.split('|')),
        ('tab', lambda s: s.split('\t')),
    )
    for name, splitter in splitters:
        hits = 0
        for ln in sample:
            parts = splitter(ln)
            if len(parts) >= 2 and all(p.strip() for p in parts[:2]):
                hits += 1
        results.append((name, hits))
    results.sort(key=lambda x: -x[1])
    return results[:3]

def glean(path):
    entries = forage(path)
    schemes = {}
    for e in entries:
        s = e[0]
        schemes[s] = schemes.get(s, 0) + 1
    return entries, schemes

def profile(host, port, user, pw):
    host_l = host.lower()
    hints = []

    provider = None
    pool = None

    for fragment, (name, kind) in catalog.items():
        if fragment in host_l:
            provider = name
            pool = kind
            hints.append(f"host:{fragment}")
            break

    labels = host_l.split(".")
    prefix_hits = []
    for label in labels[:-1]:
        if label in prefixes:
            kind, implied = prefixes[label]
            prefix_hits.append(kind)
            hints.append(f"prefix:{label}→{kind}")
            if not pool and implied:
                pool = implied

    port_class = "custom"
    for lo, hi, cls in ranges:
        if lo <= port <= hi:
            port_class = cls
            break

    if port_class != "custom" and port_class != "well-known":
        hints.append(f"port:{port_class}")

    if not pool and port_class == "residential-pool":
        pool = "residential?"
        hints.append("infer:residential-from-port")

    combined = f"{user} {pw}".lower()
    tags = set()
    for kw, tag in keywords:
        if kw in combined:
            tags.add(tag)
            hints.append(f"cred:{tag}")

    if user and pw:
        if len(user) >= 16 and user.isalnum() and len(pw) >= 16 and pw.isalnum():
            hints.append("cred:long-alnum")
            if not provider and not pool:
                pool = "residential?"
                hints.append("infer:residential-from-cred")

    return {
        'provider': provider or 'unknown',
        'pool': pool or 'unknown',
        'port_class': port_class,
        'tags': sorted(tags),
        'hints': hints,
    }

def recon(path):
    try:
        raw = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        raw = ""
    size = path.stat().st_size
    body_lines = []
    for ln in raw.splitlines():
        st = ln.strip()
        if not st or st.startswith('#') or st.startswith('//') or st.startswith(';'):
            continue
        body_lines.append(st)

    encoding, container, _ = sieve(raw)
    delims = sniff(body_lines)
    entries, schemes = glean(path)
    native_ct = sum(1 for e in entries if e[0] in native)

    p_tally = {}
    p_samples = {}
    p_hints = {}
    for e in entries:
        s, h, p, u, w = e
        prof = profile(h, p, u, w)
        key = (prof['provider'], prof['pool'])
        p_tally[key] = p_tally.get(key, 0) + 1
        if key not in p_samples:
            p_samples[key] = (h, p, prof)
        for hint in prof['hints']:
            p_hints[hint] = p_hints.get(hint, 0) + 1

    return {
        'size': size,
        'lines': len(body_lines),
        'encoding': encoding,
        'container': container,
        'delims': delims,
        'entries': entries,
        'schemes': schemes,
        'native': native_ct,
        'unsupported': len(entries) - native_ct,
        'providers': p_tally,
        'samples_by_provider': p_samples,
        'hints': p_hints,
    }

def forge(scheme, host, port, user, pw):
    if scheme not in ("http", "https", "socks4", "socks4a", "socks5", "socks5h"):
        scheme = "http"
    if user and pw:
        u = urllib.parse.quote(user, safe='')
        p = urllib.parse.quote(pw, safe='')
        return f"{scheme}://{u}:{p}@{host}:{port}"
    return f"{scheme}://{host}:{port}"

def encode(host, port, user, pw, scheme="http"):
    if scheme in ("http", "https"):
        if user and pw:
            return f"{host}:{port}:{user}:{pw}"
        return f"{host}:{port}"
    if user and pw:
        return f"{scheme}://{user}:{pw}@{host}:{port}"
    return f"{scheme}://{host}:{port}"

def register(lat):
    if lat < 100:
        data['b2'] += 1
    elif lat < 1000:
        data['b3'] += 1
    elif lat < 10000:
        data['b4'] += 1
    else:
        data['b5'] += 1

def probe(scheme, host, port, user, pw, idx, total):
    global target
    if target > 0 and data['good'] >= target:
        return
    
    proxy = forge(scheme, host, port, user, pw)
    proxies = {"http": proxy, "https": proxy}
    passes = 0
    latencies = []
    ips = set()

    for url, kind, key in checkers:
        t0 = time.perf_counter()
        try:
            r = requests.get(
                url,
                proxies=proxies,
                impersonate="chrome",
                timeout=limit,
                verify=False
            )

            if r.status_code == 200:
                if kind == "json":
                    try:
                        ip = r.json().get(key, "").strip()
                    except:
                        ip = ""
                else:
                    ip = r.text.strip()

                if ip and len(ip) < 64:
                    lat = (time.perf_counter() - t0) * 1000
                    passes += 1
                    latencies.append(lat)
                    ips.add(ip)

            elif r.status_code == 429:
                continue

        except Exception:
            pass

    is_transparent = bool(real_ip and real_ip in ips)
    ok = passes >= 3 and bool(ips) and not is_transparent

    lat = sum(latencies) / len(latencies) if latencies else 0.0

    with lock:
        if target > 0 and data['good'] >= target:
            return
            
        data['tick'] += 1
        msg = encode(host, port, user, pw, scheme)

        if not ok:
            data['bad'] += 1

        data['feed'].append((idx, 'ok' if ok else 'fail', msg, lat))

        if ok:
            data['good'] += 1
            data['lats'].append(lat)
            if lat < data['fast']: data['fast'] = lat
            if lat > data['slow']: data['slow'] = lat
            register(lat)
            data['best'].append((lat, (host, port, user, pw, scheme)))
            data['best'].sort(key=lambda x: x[0])
            
            prof = profile(host, port, user, pw)
            pool = prof['pool'].lower()
            
            if "socks4" in scheme:
                fname = "socks4.txt"
            elif "socks5" in scheme:
                fname = "socks5.txt"
            elif "residential" in pool:
                fname = "residential.txt"
            elif "datacenter" in pool:
                fname = "datacenter.txt"
            elif "mobile" in pool:
                fname = "mobile.txt"
            else:
                fname = "http.txt"

            try:
                with open("working.txt", "a", encoding="utf-8") as f:
                    f.write(msg + "\n")
                with open(fname, "a", encoding="utf-8") as f:
                    f.write(msg + "\n")
            except Exception:
                pass

def paste(id="dAt7N9CC"):
    url = f"https://pastebin.com/raw/{id}"
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        return r.text
    except Exception:
        return ""

def hproxy():
    url = "https://hproxy.com/api/proxy-list?format=json&limit=500"
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        data = r.json()
        return [f"{p['host']}:{p['port']}" for p in data if 'host' in p and 'port' in p]
    except Exception:
        return []

def geonode():
    url = "https://proxylist.geonode.com/api/proxy-list?filterLastChecked=10&page=1&limit=100&sort_by=lastChecked&sort_type=desc"
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        data = r.json()
        return [f"{p['ip']}:{p['port']}" for p in data.get("data", [])]
    except Exception:
        return []

def github():
    urls = [
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt"
    ]
    out = []
    for u in urls:
        try:
            r = requests.get(u, timeout=10)
            r.raise_for_status()
            scheme = "http"
            if "socks5" in u:
                scheme = "socks5"
            elif "socks4" in u:
                scheme = "socks4"
            for line in r.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" in line:
                    h, p = line.rsplit(":", 1)
                    try:
                        port = int(p)
                        if 1 <= port <= 65535:
                            out.append((scheme, h, port, "", ""))
                    except ValueError:
                        pass
        except Exception:
            pass
    return out

def openproxy():
    urls = [
        "https://api.openproxy.space/lists/socks5",
        "https://api.openproxy.space/lists/socks4",
        "https://api.openproxy.space/lists/http"
    ]
    out = []
    for u in urls:
        try:
            r = requests.get(u, timeout=10)
            r.raise_for_status()
            data = r.json()
            if isinstance(data, list):
                for item in data:
                    host = item.get("ip")
                    port = int(item.get("port", 0))
                    scheme = item.get("protocol", "http").lower()
                    if host and 1 <= port <= 65535:
                        out.append((scheme, host, port, "", ""))
        except Exception:
            pass
    return out

def chisel(raw):
    patterns = {
        "http": re.compile(r"http://([0-9\.]+):(\d+)"),
        "socks4": re.compile(r"socks4://([0-9\.]+):(\d+)"),
        "socks5": re.compile(r"socks5://([0-9\.]+):(\d+)"),
        "bare": re.compile(r"([0-9\.]+):(\d+)")
    }
    entries = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        matched = False
        for scheme, pat in patterns.items():
            if scheme == "bare":
                continue
            m = pat.search(line)
            if m:
                entries.append((scheme, m.group(1), int(m.group(2)), "", ""))
                matched = True
                break
        if not matched:
            m = patterns["bare"].search(line)
            if m:
                entries.append(("http", m.group(1), int(m.group(2)), "", ""))
    return entries

def sift():
    all_entries = []
    seen = set()
    all_entries.extend(chisel(paste()))
    all_entries.extend(chisel("\n".join(hproxy())))
    all_entries.extend(chisel("\n".join(geonode())))
    all_entries.extend(github())
    all_entries.extend(openproxy())
    unique = []
    for e in all_entries:
        key = (e[1], e[2])
        if key not in seen:
            seen.add(key)
            unique.append(e)
    return unique

def solo():
    banner()
    detect()
    term.print()

    head_tb = Table.grid(padding=(0, 1))
    head_tb.add_column(justify="left")
    head_tb.add_row("[bold yellow]◈ sɪɴɢʟᴇ ᴄʜᴇᴄᴋ[/bold yellow]  [white]· full probe pipeline[/white]")
    head_tb.add_row(f"[dim]test against {len(checkers)} api endpoints · latency · transparency · validity[/dim]")
    term.print(Align.center(Panel(head_tb, border_style="yellow", box=box.ROUNDED, expand=False, padding=(0, 2))))

    term.print()

    fmt_tb = Table.grid(padding=(0, 3))
    fmt_tb.add_column(style="bright_white", no_wrap=True)
    fmt_tb.add_column(style="bright_white", no_wrap=True)
    fmt_tb.add_row("[dim]host:port[/dim]", "[dim]scheme://host:port[/dim]")
    fmt_tb.add_row("[dim]host:port:user:pass[/dim]", "[dim]ss:// · vmess:// · ssr://[/dim]")
    fmt_tb.add_row("[dim]user:pass@host:port[/dim]", "[dim]vless:// · trojan:// · trojan-go://[/dim]")
    fmt_tb.add_row("[dim][ipv6]:port[/dim]", "[dim]hysteria2:// · tuic:// · wg://[/dim]")
    fmt_tb.add_row("[dim]scheme://user:pass@host:port[/dim]", "[dim]ssh:// · mtproto:// · snell://[/dim]")
    
    box_width = 64
    fmt_panel = Panel(fmt_tb, title="[bold white]◈ sᴜᴘᴘᴏʀᴛᴇᴅ ꜰᴏʀᴍᴀᴛs[/bold white]", title_align="left", border_style="yellow", box=box.ROUNDED, expand=False, width=box_width, padding=(0, 2))
    term.print(Align.center(fmt_panel))

    term.print()

    left_pad = max(0, (term.width - box_width) // 2)
    try:
        raw = term.input(" " * left_pad + "[bold yellow]❯ ᴘᴀsᴛᴇ ᴘʀᴏxʏ ❯ [/bold yellow]").strip()
    except (KeyboardInterrupt, EOFError):
        sys.exit(0)

    if not raw:
        return

    parsed = parse(raw)
    if not parsed:
        show("[bold red]✖ Invalid format.[/bold red]")
        return

    scheme, host, port, user, pw = parsed

    term.print()

    def truncate(s, length=40):
        if not s:
            return s
        return s if len(s) <= length else s[:length-3] + "..."

    p_tb = Table.grid(padding=(0, 2))
    p_tb.add_column(style="dim", justify="right", width=12)
    p_tb.add_column(style="bright_white")
    p_tb.add_row("sᴄʜᴇᴍᴇ", f"[cyan]{scheme}[/cyan]")
    p_tb.add_row("ʜᴏsᴛ", f"[bright_white]{truncate(host)}[/bright_white]")
    p_tb.add_row("ᴘᴏʀᴛ", f"[bright_white]{port}[/bright_white]")
    if user:
        p_tb.add_row("ᴜsᴇʀ", f"[bright_white]{truncate(user)}[/bright_white]")
    if pw:
        p_tb.add_row("ᴘᴀss", f"[bright_white]{'*' * min(len(pw), 16)}[/bright_white]")
    if scheme not in native:
        p_tb.add_row("sᴛᴀᴛᴜs", "[bold yellow]parsed · not natively testable[/bold yellow]")
        p_tb.add_row("ʀᴇǫᴜɪʀᴇs", "[dim]client binary · ss-local / xray / trojan / hysteria / tuic[/dim]")
        term.print(Align.center(Panel(p_tb, title="[bold yellow]◈ ᴘᴀʀsᴇᴅ[/bold yellow]", title_align="left", border_style="yellow", box=box.ROUNDED, expand=False, padding=(0, 2))))
        term.print()
        try:
            term.input(ctr("[bold yellow]❯ Press Enter to return to menu ❯ [/bold yellow]"))
        except (KeyboardInterrupt, EOFError):
            pass
        return
    p_tb.add_row("sᴛᴀᴛᴜs", "[green]parsed · testable[/green]")
    term.print(Align.center(Panel(p_tb, title="[bold yellow]◈ ᴘᴀʀsᴇᴅ[/bold yellow]", title_align="left", border_style="yellow", box=box.ROUNDED, expand=False, padding=(0, 2))))

    term.print()

    proxy_url = forge(scheme, host, port, user, pw)
    passes = 0
    latencies = []
    ips = set()
    state = {"rows": []}

    def sketch():
        tb = Table.grid(padding=(0, 2))
        tb.add_column(style="dim", width=3, justify="center")
        tb.add_column(style="bright_white", width=20)
        tb.add_column(style="bright_white", width=12, justify="right")
        tb.add_column(style="bright_white", width=20)

        for st, name, lat, ip in state["rows"]:
            if st == "ok":
                tb.add_row("[green]✓[/green]", f"[white]{name}[/white]", f"[green]{lat:.0f}ms[/green]", f"[bright_white]{ip}[/bright_white]")
            elif st == "pending":
                tb.add_row("[yellow]◷[/yellow]", f"[white]{name}[/white]", "[dim]probing...[/dim]", "")
            else:
                tb.add_row("[red]✗[/red]", f"[dim]{name}[/dim]", "[red]failed[/red]", "")

        for qi in range(len(checkers) - len(state["rows"])):
            k = len(state["rows"]) + qi
            qname = veils[k] if k < len(veils) else f"ᴀᴘɪ {k+1}"
            tb.add_row("[dim]·[/dim]", f"[dim]{qname}[/dim]", "[dim]queued[/dim]", "")

        tb.add_row("", "", "", "")

        pct = (passes / len(checkers)) * 100 if checkers else 0
        bw = 30
        filled = int(pct / 100 * bw)
        bar = f"[green]{'█' * filled}[/green][dim]{'░' * (bw - filled)}[/dim]"
        tb.add_row("", f"[dim]ᴘᴀssᴇs[/dim]", f"{bar}", f"[white]{passes}/{len(checkers)}[/white]")

        return Align.center(Panel(tb, title=f"[bold yellow]◈ ᴘʀᴏʙɪɴɢ · {host}:{port}[/bold yellow]", title_align="left", border_style="yellow", box=box.ROUNDED, expand=False, padding=(0, 2)))

    with Live(sketch(), refresh_per_second=10, console=term) as live:
        for i, (url, kind, key) in enumerate(checkers):
            name = veils[i] if i < len(veils) else f"ᴀᴘɪ {i+1}"
            state["rows"].append(("pending", name, 0.0, ""))
            live.update(sketch())

            t0 = time.perf_counter()
            try:
                r = requests.get(
                    url,
                    proxies={"http": proxy_url, "https": proxy_url},
                    impersonate="chrome",
                    timeout=limit,
                    verify=False,
                )
                if r.status_code == 200:
                    if kind == "json":
                        try:
                            ip = r.json().get(key, "").strip()
                        except Exception:
                            ip = ""
                    else:
                        ip = r.text.strip()
                    if ip and len(ip) < 64:
                        lat = (time.perf_counter() - t0) * 1000
                        passes += 1
                        latencies.append(lat)
                        ips.add(ip)
                        state["rows"][-1] = ("ok", name, lat, ip)
                    else:
                        state["rows"][-1] = ("fail", name, 0.0, "")
                else:
                    state["rows"][-1] = ("fail", name, 0.0, "")
            except Exception:
                state["rows"][-1] = ("fail", name, 0.0, "")
            live.update(sketch())

    term.print()

    avg_lat = sum(latencies) / len(latencies) if latencies else 0.0
    is_transparent = bool(real_ip and real_ip in ips)
    quality = passes == len(checkers) and bool(ips) and not is_transparent

    if quality:
        verdict = "[bold green]HIGH QUALITY[/bold green]"
        title_style = "[bold bright_green]✔ sᴛʀᴏɴɢ ᴘʀᴏxʏ[/bold bright_green]"
        border = "green"
    elif is_transparent:
        verdict = "[bold red]TRANSPARENT[/bold red]"
        title_style = "[bold red]✖ ʟᴇᴀᴋɪɴɢ ᴘʀᴏxʏ[/bold red]"
        border = "red"
    elif passes == 0:
        verdict = "[bold red]DEAD[/bold red]"
        title_style = "[bold red]✖ ᴅᴇᴀᴅ ᴘʀᴏxʏ[/bold red]"
        border = "red"
    else:
        verdict = f"[bold yellow]PARTIAL · {passes}/{len(checkers)}[/bold yellow]"
        title_style = "[bold yellow]⚠ ᴡᴇᴀᴋ ᴘʀᴏxʏ[/bold yellow]"
        border = "yellow"

    sum_tb = Table.grid(padding=(0, 2))
    sum_tb.add_column(style="dim", justify="right", width=16)
    sum_tb.add_column(style="bright_white")
    sum_tb.add_row("sᴛᴀᴛᴜs", verdict)
    sum_tb.add_row("ᴀᴘɪs ᴘᴀssᴇᴅ", f"[white]{passes}/{len(checkers)}[/white]")
    if ips:
        sum_tb.add_row("ᴅᴇᴛᴇᴄᴛᴇᴅ ɪᴘs", "[bright_white]" + ", ".join(sorted(ips)) + "[/bright_white]")
    sum_tb.add_row("ᴀᴠɢ ʟᴀᴛᴇɴᴄʏ", f"[white]{avg_lat:.1f}ms[/white]" if avg_lat else "—")
    sum_tb.add_row("sᴄʜᴇᴍᴇ", f"[cyan]{scheme}[/cyan]")
    sum_tb.add_row("ᴇɴᴅᴘᴏɪɴᴛ", f"[bright_white]{truncate(host, 32)}:{port}[/bright_white]")

    term.print(Align.center(Panel(sum_tb, title=title_style, title_align="left", border_style=border, box=box.DOUBLE, expand=False, padding=(0, 2))))

    term.print()
    try:
        term.input(ctr("[bold yellow]❯ Press Enter to return to menu ❯ [/bold yellow]"))
    except (KeyboardInterrupt, EOFError):
        pass
    return

def report():
    tb = Table(show_header=False, box=None, padding=(0, 1), expand=False)
    tb.add_column(style="dim", no_wrap=True, min_width=14)
    tb.add_column(style="bright_white", no_wrap=True)
    tb.add_row("[dim]Total Tested[/dim]", f"[bright_white]{data['total']:,}[/bright_white]")
    tb.add_row("[dim]Strong Proxies[/dim]", f"[bright_green]{data['good']:,}[/bright_green]")
    tb.add_row("[dim]Rejected[/dim]", f"[bright_red]{data['bad']:,}[/bright_red]")
    if data.get('unsupported', 0):
        tb.add_row("[dim]Unsupported[/dim]", f"[bright_yellow]{data['unsupported']:,}[/bright_yellow]")
    tb.add_row("[dim]Saved To[/dim]", "[bright_cyan]working.txt + categorized[/bright_cyan]")

    term.print()
    term.print(Align.center(Panel(tb, title="[bold bright_cyan]◈ COMPLETE[/bold bright_cyan]", border_style="yellow", box=box.DOUBLE, padding=(0, 2), expand=False)))
    term.print()

def run(entries, goal=0):
    global hands, limit, proto, target
    target = goal
    native_entries = [e for e in entries if e[0] in native]
    unparsed = [e for e in entries if e[0] not in native]
    data['unsupported'] = len(unparsed)

    try:
        with open("working.txt", "w", encoding="utf-8") as f:
            pass
    except Exception:
        pass

    if unparsed:
        try:
            with open("unsupported.txt", "w", encoding="utf-8") as f:
                for scheme, host, port, user, pw in unparsed:
                    f.write(encode(host, port, user, pw, scheme) + "\n")
        except Exception:
            pass

    if not native_entries:
        show(f"[yellow]Parsed {len(entries)} proxies, 0 natively testable.[/yellow]")
        show("[dim]Non-native saved to unsupported.txt — needs client binary to validate.[/dim]")
        term.print()
        try:
            term.input(ctr("[bold yellow]❯ Press Enter to return to menu ❯ [/bold yellow]"))
        except (KeyboardInterrupt, EOFError):
            pass
        return

    data['total'] = len(native_entries)
    data['start'] = time.time()

    with Live(draw(), refresh_per_second=10) as live:
        def refresh():
            while data['tick'] < data['total'] and (target == 0 or data['good'] < target):
                live.update(draw())
                time.sleep(0.1)
            data['status'] = 'COMPLETE'
            live.update(draw())

        job = threading.Thread(target=refresh, daemon=True)
        job.start()

        with ThreadPoolExecutor(max_workers=hands) as executor:
            futures = [
                executor.submit(probe, s, h, p, u, w, i+1, len(native_entries))
                for i, (s, h, p, u, w) in enumerate(native_entries)
            ]
            for f in as_completed(futures):
                try:
                    f.result()
                except Exception:
                    pass
                if target > 0 and data['good'] >= target:
                    for pending in futures:
                        pending.cancel()
                    break

        if target > 0 and data['good'] >= target:
            data['total'] = data['tick']
            
        data['tick'] = data['total']
        data['status'] = 'COMPLETE'
        live.update(draw())
        job.join(timeout=0.3)
        time.sleep(0.5)

    report()

    term.print()
    try:
        term.input(ctr("[bold yellow]❯ Press Enter to return to menu ❯ [/bold yellow]"))
    except (KeyboardInterrupt, EOFError):
        pass
    return

def bulk():
    banner()
    detect()
    files = scan()
    if not files:
        show("[red]No .txt files found in current folder or Proxies folder.[/red]")
        term.print()
        try:
            term.input(ctr("[bold yellow]❯ Press Enter to return to menu ❯ [/bold yellow]"))
        except (KeyboardInterrupt, EOFError):
            pass
        return

    src = choose(files)
    entries = forage(src)
    if not entries:
        show("[red]No valid proxies found in any supported format.[/red]")
        term.print()
        try:
            term.input(ctr("[bold yellow]❯ Press Enter to return to menu ❯ [/bold yellow]"))
        except (KeyboardInterrupt, EOFError):
            pass
        return

    run(entries)

def inspect():
    banner()
    detect()
    files = scan()
    if not files:
        show("[red]No .txt files found in current folder or Proxies folder.[/red]")
        term.print()
        try:
            term.input(ctr("[bold yellow]❯ Press Enter to return to menu ❯ [/bold yellow]"))
        except (KeyboardInterrupt, EOFError):
            pass
        return

    src = choose(files)

    term.print()
    show("[dim]Sampling file — reading shape...[/dim]")
    term.print()

    info = recon(src)

    tb = Table.grid(padding=(0, 2), expand=False)
    tb.add_column(style="dim", justify="right", width=18)
    tb.add_column(style="bright_white")
    tb.add_row("File", f"[bold white]{src.name}[/bold white]")
    tb.add_row("Size", render(info['size']))
    tb.add_row("Content Lines", f"{info['lines']:,}")
    tb.add_row("Encoding", f"[cyan]{info['encoding']}[/cyan]")
    tb.add_row("Container", f"[cyan]{info['container']}[/cyan]")
    if info['delims']:
        dd = "  ".join(f"[dim]{d}:[/dim][white]{c}[/white]" for d, c in info['delims'])
        tb.add_row("Delimiter Hits", dd)
    tb.add_row("Parsed", f"[bright_white]{len(info['entries']):,}[/bright_white]")
    tb.add_row("Natively Testable", f"[green]{info['native']:,}[/green]")
    if info['unsupported']:
        tb.add_row("Needs Client", f"[yellow]{info['unsupported']:,}[/yellow]")
    if info['schemes']:
        sorted_s = sorted(info['schemes'].items(), key=lambda x: -x[1])
        display = "  ".join(f"[white]{s}[/white][dim]:[/dim][cyan]{c}[/cyan]" for s, c in sorted_s[:8])
        if len(sorted_s) > 8:
            display += f"  [dim](+{len(sorted_s)-8} more)[/dim]"
        tb.add_row("Detected Types", display)

    term.print(Align.center(Panel(tb, title="[bold yellow]◈ FILE RECON[/bold yellow]", border_style="yellow", box=box.ROUNDED, expand=False)))

    if info['providers']:
        pt = Table.grid(padding=(0, 2), expand=False)
        pt.add_column(style="dim", justify="right", width=4)
        pt.add_column(style="bright_white", width=22)
        pt.add_column(style="cyan", width=20)
        pt.add_column(style="dim", justify="right", width=10)
        pt.add_column(style="dim")
        sorted_p = sorted(info['providers'].items(), key=lambda x: -x[1])
        for i, ((prov, pool), cnt) in enumerate(sorted_p[:8], 1):
            hint_str = " ".join(info['samples_by_provider'][(prov, pool)][2]['hints'][:2])
            pt.add_row(str(i), prov, pool, f"{cnt:,}", f"[dim]{hint_str}[/dim]")
        if len(sorted_p) > 8:
            pt.add_row("…", f"[dim](+{len(sorted_p)-8} more)[/dim]", "", "", "")
        term.print()
        term.print(Align.center(Panel(pt, title="[bold yellow]◈ PROVIDER BREAKDOWN[/bold yellow]", border_style="yellow", box=box.ROUNDED, expand=False)))

    if info['entries']:
        samples = Table.grid(padding=(0, 2), expand=False)
        samples.add_column(style="dim", justify="right", width=4)
        samples.add_column(style="cyan", width=9)
        samples.add_column(style="bright_white", width=34)
        samples.add_column(style="dim")
        for i, e in enumerate(info['entries'][:6], 1):
            s, h, p, u, w = e
            prof = profile(h, p, u, w)
            tag = f"{prof['provider']}/{prof['pool']}"
            samples.add_row(str(i), f"[{s}]", f"{h}:{p}", tag)
        term.print()
        term.print(Align.center(Panel(samples, title="[bold white]SAMPLE ENTRIES[/bold white]", border_style="yellow", box=box.ROUNDED, expand=False)))

    term.print()
    try:
        term.input(ctr("[bold yellow]❯ Press Enter to return to menu ❯ [/bold yellow]"))
    except (KeyboardInterrupt, EOFError):
        pass
    return

def delve():
    banner()
    show("[dim]Fetching from deep web currents...[/dim]")
    term.print()
    entries = sift()
    if not entries:
        show("[red]No proxies found in those currents.[/red]")
        term.print()
        try:
            term.input(ctr("[bold yellow]❯ Press Enter to return to menu ❯ [/bold yellow]"))
        except (KeyboardInterrupt, EOFError):
            pass
        return
    
    tb = Table.grid(padding=(0, 2))
    tb.add_column(style="dim", justify="right", width=14)
    tb.add_column(style="bright_white")
    tb.add_row("sᴛᴀᴛᴜs", "[green]ꜱᴄʀᴀᴘᴇ ᴄᴏᴍᴘʟᴇᴛᴇ[/green]")
    tb.add_row("sᴏᴜʀᴄᴇs", "[cyan]ᴅᴇᴇᴘ ᴡᴇʙ ᴄᴜʀʀᴇɴᴛꜱ[/cyan]")
    tb.add_row("ᴘᴀʀꜱᴇᴅ", f"[white]{len(entries)} ᴘʀᴏxɪᴇꜱ[/white]")
    
    term.print(Align.center(Panel(tb, title="[bold bright_green]◈ ᴅᴇᴇᴘ sᴄʀᴀᴘᴇ[/bold bright_green]", title_align="left", border_style="green", box=box.ROUNDED, expand=False, padding=(0, 2))))
    term.print()
    
    limit_tb = Table.grid(padding=(0, 2))
    limit_tb.add_column(style="bold yellow")
    limit_tb.add_row("ᴀʟɪᴠᴇ ʟɪᴍɪᴛ (1-100):")
    term.print(Align.center(Panel(limit_tb, border_style="yellow", box=box.ROUNDED, expand=False, padding=(0, 2))))
    term.print()
    
    try:
        raw = term.input(ctr("[bold yellow]❯ ᴛᴀʀɢᴇᴛ ❯ [/bold yellow]")).strip()
        goal = int(raw) if raw else 100
        goal = min(100, max(1, goal))
    except (KeyboardInterrupt, EOFError):
        sys.exit(0)
    except ValueError:
        goal = 100
        
    term.print()
    show(f"[green]Targeting {goal} alive proxies...[/green]")
    time.sleep(1)
    run(entries, goal)

def douse():
    wipe()
    term.print()

    lines = [
        "sᴛᴏᴘᴘɪɴɢ ᴘʀᴏxʏ ᴄʜᴇᴄᴋᴇʀ ᴅᴀᴇᴍᴏɴ...",
        "ᴄʟᴇᴀɴɪɴɢ ᴡᴏʀᴋsᴘᴀᴄᴇ...",
        "ᴅᴏɴᴇ.",
        "",
        "ᴘᴏᴡᴇʀ ᴏғғ."
    ]

    current = ["", "", "", "", ""]

    def render(cursor=-1):
        tb = Table.grid(padding=(0, 2))
        tb.add_column(style="dim", justify="right", width=11)
        tb.add_column(style="bright_white")

        display = current.copy()
        if cursor != -1 and cursor < len(display):
            display[cursor] += "█"

        tb.add_row("[dim][sʏsᴛᴇᴍ][/dim]", f"[white]{display[0]}[/white]")
        tb.add_row("[dim][sʏsᴛᴇᴍ][/dim]", f"[white]{display[1]}[/white]")
        tb.add_row("[dim][sʏsᴛᴇᴍ][/dim]", f"[green]{display[2]}[/green]")
        tb.add_row("", "")
        tb.add_row("[bold yellow]❯[/bold yellow]", f"[bold yellow]{display[4]}[/bold yellow]")

        return Align.center(Panel(tb, title="[bold yellow]◈ sʏsᴛᴇᴍ ᴇxɪᴛ[/bold yellow]", title_align="left", border_style="yellow", box=box.ROUNDED, expand=False, padding=(0, 4)))

    with Live(render(0), refresh_per_second=30, console=term) as live:
        for i, text in enumerate(lines):
            if not text:
                continue
            for char in text:
                current[i] += char
                live.update(render(i))
                time.sleep(0.025)
            live.update(render(-1))
            time.sleep(0.3)

    time.sleep(1.0)
    sys.exit(0)

def launch():
    tb = Table(show_header=False, box=box.HORIZONTALS, border_style="yellow", padding=(0, 2))
    tb.add_column(style="bold yellow")
    tb.add_column(style="bright_white")
    tb.add_row("1.", "sɪɴɢʟᴇ ᴄʜᴇᴄᴋ")
    tb.add_row("2.", "ʙᴜʟᴋ ᴄʜᴇᴄᴋ")
    tb.add_row("3.", "ᴅᴇᴛᴇᴄᴛ ᴘʀᴏxʏ")
    tb.add_row("4.", "sᴄʀᴀᴘᴇ ᴅᴇᴇᴘ")
    tb.add_row("5.", "ᴇxɪᴛ")

    def home():
        banner()
        term.print()
        term.print(Align.center(Panel(tb, title="[bold white]MAIN MENU[/bold white]", border_style="yellow", box=box.DOUBLE_EDGE, expand=False)))
        term.print()

    home()

    while True:
        try:
            raw = term.input(ctr("[bold yellow]❯ Select ❯ [/bold yellow]")).strip()
        except (KeyboardInterrupt, EOFError):
            douse()

        if not raw:
            continue

        if raw == '1':
            solo()
            home()
        elif raw == '2':
            bulk()
            home()
        elif raw == '3':
            inspect()
            home()
        elif raw == '4':
            delve()
            home()
        elif raw == '5':
            douse()
        else:
            show("[red]Invalid selection.[/red]")

if __name__ == "__main__":
    try:
        launch()
    except (KeyboardInterrupt, EOFError):
        douse()
    except SystemExit:
        pass
    except Exception as e:
        wipe()
        show(f"\n[bold red]✖ Error: {e}[/bold red]")
        sys.exit(1)