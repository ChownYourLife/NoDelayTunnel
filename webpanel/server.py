#!/usr/bin/env python3
import argparse
import base64
import hmac
import json
import os
import re
import shutil
import subprocess
import threading
import time
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

ROOT_DIR = Path(__file__).resolve().parent
STATIC_DIR = ROOT_DIR / "static"

CONFIG_DIR = Path("/etc/nodelay")
SYSTEMD_DIR = Path("/etc/systemd/system")
INSTALL_DIR = Path("/usr/local/bin")
BINARY_PATH = INSTALL_DIR / "nodelay"

SERVER_SERVICE_NAME = "nodelay-server"
CLIENT_SERVICE_NAME = "nodelay-client"

SERVICE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
INSTANCE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")

THROUGHPUT_LOCK = threading.Lock()
THROUGHPUT_STATE = {}
RESOURCE_STATE = {
    "cpu": {"ts": 0.0, "idle": 0, "total": 0, "usage": 0.0},
    "net": {"ts": 0.0, "rx": 0, "tx": 0, "rx_bps": 0.0, "tx_bps": 0.0},
}
AUTH_ENABLED = False
AUTH_USERNAME = ""
AUTH_PASSWORD = ""


def run_cmd(args):
    result = subprocess.run(args, text=True, capture_output=True, check=False)
    return result.returncode, (result.stdout or "").strip(), (result.stderr or "").strip()


def json_response(handler, payload, status=HTTPStatus.OK):
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def error_response(handler, message, status=HTTPStatus.BAD_REQUEST):
    json_response(handler, {"ok": False, "error": str(message)}, status=status)


def load_dotenv(path):
    if not path.exists() or not path.is_file():
        return

    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        os.environ.setdefault(key, value)


def resolve_auth_config():
    username = (
        os.environ.get("NODELAY_WEBPANEL_USER", "").strip()
        or os.environ.get("NODELAY_WEBPANEL_USERNAME", "").strip()
    )
    password = os.environ.get("NODELAY_WEBPANEL_PASS", "")
    if password == "":
        password = os.environ.get("NODELAY_WEBPANEL_PASSWORD", "")

    enabled = bool(username and password)
    return enabled, username, password


def parse_role_instance(service_name):
    raw = service_name.strip().removesuffix(".service")
    if raw == SERVER_SERVICE_NAME:
        return "server", "default"
    if raw == CLIENT_SERVICE_NAME:
        return "client", "default"
    if raw.startswith(SERVER_SERVICE_NAME + "-"):
        return "server", raw[len(SERVER_SERVICE_NAME) + 1 :]
    if raw.startswith(CLIENT_SERVICE_NAME + "-"):
        return "client", raw[len(CLIENT_SERVICE_NAME) + 1 :]
    return None, None


def build_service_name(role, instance="default"):
    base = SERVER_SERVICE_NAME if role == "server" else CLIENT_SERVICE_NAME
    if instance == "default":
        return base
    return f"{base}-{instance}"


def normalize_instance(instance):
    value = str(instance or "").strip().lower()
    if not value:
        return "default"
    if value in {"default", "main", "primary"}:
        return "default"
    if INSTANCE_RE.fullmatch(value) is None:
        raise ValueError("instance must match [a-z0-9][a-z0-9_-]{0,31}")
    return value


def build_config_filename(role, instance="default"):
    if role == "server":
        return "config.yaml" if instance == "default" else f"config-{instance}.yaml"
    return "client_config.yaml" if instance == "default" else f"client_config-{instance}.yaml"


def config_path_for(role, instance="default"):
    return CONFIG_DIR / build_config_filename(role, instance)


def service_file_path(service_name):
    return SYSTEMD_DIR / f"{service_name}.service"


def list_tunnel_services():
    names = set()

    if SYSTEMD_DIR.exists():
        for name in os.listdir(SYSTEMD_DIR):
            if not name.endswith(".service"):
                continue
            service_name = name[:-8]
            role, _ = parse_role_instance(service_name)
            if role in {"server", "client"}:
                names.add(service_name)

    rc, out, _ = run_cmd(["systemctl", "list-unit-files", "--type=service", "--no-legend"])
    if rc == 0 and out:
        for line in out.splitlines():
            unit = line.split()[0].strip() if line.split() else ""
            if not unit.endswith(".service"):
                continue
            service_name = unit[:-8]
            role, _ = parse_role_instance(service_name)
            if role in {"server", "client"}:
                names.add(service_name)

    return sorted(names)


def service_status(service_name):
    unit = f"{service_name}.service"
    rc, out, err = run_cmd(
        [
            "systemctl",
            "show",
            unit,
            "--property=ActiveState,SubState,MainPID",
            "--value",
        ]
    )
    if rc != 0:
        return {
            "active": "unknown",
            "sub": "unknown",
            "main_pid": 0,
            "error": err or out or "systemctl show failed",
        }

    lines = out.splitlines()
    active = lines[0].strip() if len(lines) > 0 else "unknown"
    sub = lines[1].strip() if len(lines) > 1 else "unknown"
    pid_raw = lines[2].strip() if len(lines) > 2 else "0"
    try:
        pid = int(pid_raw)
    except ValueError:
        pid = 0
    return {"active": active, "sub": sub, "main_pid": max(pid, 0)}


def parse_text_value(text, key):
    m = re.search(rf"^\s*{re.escape(key)}:\s*\"?([^\n\"]+)\"?\s*$", text, flags=re.MULTILINE)
    if not m:
        return ""
    return m.group(1).strip()


def parse_endpoints_preview(text):
    types = re.findall(r'^\s*-\s*type:\s*"?([a-z0-9]+)"?\s*$', text, flags=re.MULTILINE | re.IGNORECASE)
    addresses = re.findall(r'^\s*address:\s*"?([^\n\"]+)"?\s*$', text, flags=re.MULTILINE)
    previews = []
    for idx, ep_type in enumerate(types[:4]):
        addr = addresses[idx] if idx < len(addresses) else ""
        previews.append(f"{ep_type}:{addr}")
    return previews


def read_config_summary(role, instance):
    cfg_path = config_path_for(role, instance)
    if not cfg_path.exists():
        return {
            "config_path": str(cfg_path),
            "exists": False,
            "mode": role,
            "tunnel_mode": "",
            "profile": "",
            "endpoints": [],
        }

    try:
        text = cfg_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {
            "config_path": str(cfg_path),
            "exists": True,
            "mode": role,
            "tunnel_mode": "",
            "profile": "",
            "endpoints": [],
        }

    return {
        "config_path": str(cfg_path),
        "exists": True,
        "mode": parse_text_value(text, "mode") or role,
        "tunnel_mode": parse_text_value(text, "tunnel_mode"),
        "profile": parse_text_value(text, "profile"),
        "endpoints": parse_endpoints_preview(text),
    }


def read_proc_stat_cpu():
    try:
        with open("/proc/stat", "r", encoding="utf-8") as f:
            line = f.readline().strip()
    except OSError:
        return 0, 0

    if not line.startswith("cpu "):
        return 0, 0

    fields = [int(v) for v in line.split()[1:] if v.isdigit()]
    if len(fields) < 4:
        return 0, 0

    idle = fields[3] + (fields[4] if len(fields) > 4 else 0)
    total = sum(fields)
    return idle, total


def read_uptime_seconds():
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as f:
            raw = f.read().strip().split()
            if not raw:
                return 0.0
            return float(raw[0])
    except Exception:
        return 0.0


def read_memory_info():
    data = {}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.split(":", 1)
                if len(parts) != 2:
                    continue
                key = parts[0].strip()
                value = parts[1].strip().split()[0]
                if value.isdigit():
                    data[key] = int(value) * 1024
    except OSError:
        return {"total": 0, "available": 0, "used": 0, "used_percent": 0.0}

    total = data.get("MemTotal", 0)
    available = data.get("MemAvailable", 0)
    used = max(total - available, 0)
    used_percent = (used * 100.0 / total) if total else 0.0
    return {
        "total": total,
        "available": available,
        "used": used,
        "used_percent": used_percent,
    }


def read_disk_info(path="/"):
    try:
        st = os.statvfs(path)
    except OSError:
        return {"total": 0, "used": 0, "free": 0, "used_percent": 0.0}

    total = st.f_frsize * st.f_blocks
    free = st.f_frsize * st.f_bavail
    used = max(total - free, 0)
    used_percent = (used * 100.0 / total) if total else 0.0
    return {"total": total, "used": used, "free": free, "used_percent": used_percent}


def read_network_totals():
    rx_total = 0
    tx_total = 0
    try:
        with open("/proc/net/dev", "r", encoding="utf-8") as f:
            lines = f.read().splitlines()[2:]
    except OSError:
        return 0, 0

    for line in lines:
        if ":" not in line:
            continue
        name, values_raw = line.split(":", 1)
        iface = name.strip()
        if iface == "lo":
            continue
        values = values_raw.split()
        if len(values) < 16:
            continue
        if values[0].isdigit():
            rx_total += int(values[0])
        if values[8].isdigit():
            tx_total += int(values[8])
    return rx_total, tx_total


def collect_resource_snapshot():
    now = time.time()
    load1, load5, load15 = os.getloadavg()
    uptime = read_uptime_seconds()
    memory = read_memory_info()
    disk = read_disk_info("/")

    idle, total = read_proc_stat_cpu()
    rx_total, tx_total = read_network_totals()

    with THROUGHPUT_LOCK:
        cpu_prev = RESOURCE_STATE["cpu"]
        net_prev = RESOURCE_STATE["net"]

        cpu_usage = cpu_prev.get("usage", 0.0)
        if cpu_prev["total"] > 0 and total > cpu_prev["total"]:
            dt_total = total - cpu_prev["total"]
            dt_idle = idle - cpu_prev["idle"]
            busy = max(dt_total - dt_idle, 0)
            cpu_usage = (busy * 100.0 / dt_total) if dt_total > 0 else cpu_usage

        net_rx_bps = 0.0
        net_tx_bps = 0.0
        if net_prev["ts"] > 0 and now > net_prev["ts"]:
            dt = now - net_prev["ts"]
            drx = max(rx_total - net_prev["rx"], 0)
            dtx = max(tx_total - net_prev["tx"], 0)
            net_rx_bps = drx / dt if dt > 0 else 0.0
            net_tx_bps = dtx / dt if dt > 0 else 0.0

        RESOURCE_STATE["cpu"] = {"ts": now, "idle": idle, "total": total, "usage": cpu_usage}
        RESOURCE_STATE["net"] = {
            "ts": now,
            "rx": rx_total,
            "tx": tx_total,
            "rx_bps": net_rx_bps,
            "tx_bps": net_tx_bps,
        }

    return {
        "timestamp": now,
        "uptime_seconds": uptime,
        "cpu_percent": cpu_usage,
        "load": {"1m": load1, "5m": load5, "15m": load15},
        "memory": memory,
        "disk": disk,
        "network": {
            "rx_total": rx_total,
            "tx_total": tx_total,
            "rx_bps": net_rx_bps,
            "tx_bps": net_tx_bps,
        },
    }


def parse_ss_bytes_blob(blob):
    sent_match = re.search(r"bytes_sent:(\d+)", blob)
    recv_match = re.search(r"bytes_received:(\d+)", blob)
    sent = int(sent_match.group(1)) if sent_match else 0
    recv = int(recv_match.group(1)) if recv_match else 0
    return recv, sent


def collect_pid_socket_totals():
    rc, out, _ = run_cmd(["ss", "-tinpH"])
    if rc != 0 or not out:
        return {}

    totals = {}
    lines = out.splitlines()
    current = None

    def flush_current():
        nonlocal current
        if not current:
            return
        pids = current.get("pids", [])
        blob = " ".join(current.get("blob", []))
        rx_bytes, tx_bytes = parse_ss_bytes_blob(blob)
        for pid in pids:
            row = totals.setdefault(pid, {"rx": 0, "tx": 0})
            row["rx"] += rx_bytes
            row["tx"] += tx_bytes
        current = None

    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        if "users:((" in line:
            flush_current()
            pids = [int(v) for v in re.findall(r"pid=(\d+)", line)]
            if not pids:
                current = None
                continue
            current = {"pids": pids, "blob": [line]}
            continue
        if current:
            # Keep all continuation lines (bbr/cubic/reno + skmem, etc).
            current["blob"].append(line)

    flush_current()

    return totals


def estimate_service_throughput(service_pid_map):
    now = time.time()
    pid_totals = collect_pid_socket_totals()
    result = {}

    with THROUGHPUT_LOCK:
        active_services = set(service_pid_map.keys())
        for stale in list(THROUGHPUT_STATE.keys()):
            if stale not in active_services:
                THROUGHPUT_STATE.pop(stale, None)

        for service_name, pid in service_pid_map.items():
            cur = pid_totals.get(pid, {"rx": 0, "tx": 0}) if pid > 0 else {"rx": 0, "tx": 0}
            prev = THROUGHPUT_STATE.get(service_name)

            rx_bps = 0.0
            tx_bps = 0.0
            same_pid = prev and int(prev.get("pid", 0) or 0) == int(pid or 0)
            if same_pid and now > prev.get("ts", 0):
                dt = now - prev["ts"]
                drx = cur["rx"] - prev.get("rx", 0)
                dtx = cur["tx"] - prev.get("tx", 0)
                if drx >= 0 and dt > 0:
                    rx_bps = drx / dt
                if dtx >= 0 and dt > 0:
                    tx_bps = dtx / dt

            THROUGHPUT_STATE[service_name] = {
                "ts": now,
                "pid": int(pid or 0),
                "rx": cur["rx"],
                "tx": cur["tx"],
                "rx_bps": rx_bps,
                "tx_bps": tx_bps,
            }

            result[service_name] = {
                "rx_bps": rx_bps,
                "tx_bps": tx_bps,
                "rx_total": cur["rx"],
                "tx_total": cur["tx"],
            }

    return result


def bool_value(value, default=False):
    raw = str(value).strip().lower()
    if raw in {"1", "true", "yes", "y", "on"}:
        return True
    if raw in {"0", "false", "no", "n", "off"}:
        return False
    return bool(default)


def normalize_transport(value):
    raw = str(value or "tcp").strip().lower()
    supported = {"tcp", "tls", "ws", "wss", "kcp", "quic", "httpmimicry", "httpsmimicry", "reality"}
    if raw in supported:
        return raw
    return "tcp"


def normalize_mux_type(value):
    raw = str(value or "smux").strip().lower()
    if raw in {"smux", "yamux", "h2mux"}:
        return raw
    return "smux"


def default_path_for_transport(transport):
    if transport in {"ws", "wss"}:
        return "/ws"
    if transport in {"httpmimicry", "httpsmimicry"}:
        return "/api/v1/upload"
    return "/tunnel"


def yaml_scalar(value):
    if value is None:
        return '""'
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    text = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{text}"'


def normalize_port(value, default):
    try:
        port = int(value)
    except (TypeError, ValueError):
        return default
    if port < 1 or port > 65535:
        return default
    return port


def normalize_mappings(value):
    if not isinstance(value, list):
        return []
    out = []
    for idx, item in enumerate(value, start=1):
        if not isinstance(item, dict):
            continue
        out.append(
            {
                "name": str(item.get("name", f"mapping-{idx}")),
                "mode": str(item.get("mode", "reverse")),
                "protocol": str(item.get("protocol", "tcp")),
                "bind": str(item.get("bind", "0.0.0.0:2200")),
                "target": str(item.get("target", "127.0.0.1:22")),
                "route": str(item.get("route", "")),
            }
        )
    return out


def render_mappings(lines, mappings, indent="  "):
    if not mappings:
        lines.append(f"{indent}mappings: []")
        return
    lines.append(f"{indent}mappings:")
    for mapping in mappings:
        lines.append(f"{indent}  - name: {yaml_scalar(mapping['name'])}")
        lines.append(f"{indent}    mode: {yaml_scalar(mapping['mode'])}")
        lines.append(f"{indent}    protocol: {yaml_scalar(mapping['protocol'])}")
        lines.append(f"{indent}    bind: {yaml_scalar(mapping['bind'])}")
        lines.append(f"{indent}    target: {yaml_scalar(mapping['target'])}")
        route = str(mapping.get("route", "")).strip()
        if route:
            lines.append(f"{indent}    route: {yaml_scalar(route)}")


def render_endpoint_block(lines, role, payload):
    transport = normalize_transport(payload.get("transport", "tcp"))
    path = str(payload.get("path", default_path_for_transport(transport))).strip() or default_path_for_transport(transport)
    if not path.startswith("/"):
        path = "/" + path

    port = normalize_port(payload.get("port", 9999), 9999)

    if role == "server":
        host = str(payload.get("listen_host", "")).strip()
        address = f"{host}:{port}" if host else f":{port}"
    else:
        host = str(payload.get("server_addr", "127.0.0.1")).strip() or "127.0.0.1"
        address = f"{host}:{port}"

    url = ""
    if transport in {"ws", "wss"}:
        scheme = "wss" if transport == "wss" else "ws"
        url = f"{scheme}://{address}{path}"

    lines.append(f"    - type: {yaml_scalar(transport)}")
    lines.append(f"      address: {yaml_scalar(address)}")
    lines.append(f"      url: {yaml_scalar(url)}")
    lines.append(f"      path: {yaml_scalar(path)}")

    tls_transports = {"tls", "wss", "quic", "httpsmimicry"}
    if transport in tls_transports:
        lines.append("      tls:")
        if role == "server":
            lines.append(f"        cert_file: {yaml_scalar(payload.get('cert_file', ''))}")
            lines.append(f"        key_file: {yaml_scalar(payload.get('key_file', ''))}")
        else:
            lines.append('        cert_file: ""')
            lines.append('        key_file: ""')
        lines.append('        ca_file: ""')
        if role == "client":
            lines.append(f"        server_name: {yaml_scalar(payload.get('sni', ''))}")
            lines.append(
                f"        insecure_skip_verify: {yaml_scalar(bool_value(payload.get('insecure_skip_verify', False), False))}"
            )
        else:
            lines.append('        server_name: ""')
            lines.append("        insecure_skip_verify: false")
            lines.append("        require_client_cert: false")

    if transport == "reality":
        dest = str(payload.get("reality_dest", "www.microsoft.com:443")).strip() or "www.microsoft.com:443"
        names_raw = str(payload.get("reality_server_names", "www.microsoft.com,microsoft.com"))
        server_names = [n.strip() for n in names_raw.split(",") if n.strip()]
        if not server_names:
            server_names = ["www.microsoft.com", "microsoft.com"]
        short_id = str(payload.get("reality_short_id", "")).strip().lower()
        private_key = str(payload.get("reality_private_key", "")).strip().lower()
        public_key = str(payload.get("reality_public_key", "")).strip().lower()
        lines.append("      reality:")
        lines.append(f"        dest: {yaml_scalar(dest)}")
        lines.append(f"        server_names: {json.dumps(server_names)}")
        lines.append(f"        short_id: {yaml_scalar(short_id)}")
        lines.append(f"        private_key: {yaml_scalar(private_key if role == 'server' else '')}")
        lines.append(f"        public_key: {yaml_scalar(public_key if role == 'client' else '')}")


def build_config_from_payload(payload):
    role = str(payload.get("role", "server")).strip().lower()
    if role not in {"server", "client"}:
        raise ValueError("role must be server or client")

    tunnel_mode = str(payload.get("tunnel_mode", "reverse")).strip().lower() or "reverse"
    if tunnel_mode not in {"reverse", "direct"}:
        tunnel_mode = "reverse"

    profile = str(payload.get("profile", "balanced")).strip() or "balanced"
    psk = str(payload.get("psk", "")).strip()
    license_id = str(payload.get("license", "")).strip()
    transport = normalize_transport(payload.get("transport", "tcp"))
    mux_type = normalize_mux_type(payload.get("mux_type", "smux"))

    lines = [
        f"mode: {role}",
        f"tunnel_mode: {yaml_scalar(tunnel_mode)}",
        f"profile: {yaml_scalar(profile)}",
        "",
    ]

    if role == "server":
        mappings = normalize_mappings(payload.get("mappings", []))

        lines.append("server:")
        lines.append("  listens:")
        render_endpoint_block(lines, "server", payload)
        lines.extend(
            [
                "  port_hopping:",
                "    enabled: false",
                "    start_port: 10000",
                "    end_port: 10100",
                "    count: 0",
                '    mode: "spread"',
            ]
        )
        if tunnel_mode == "direct":
            lines.append("  mappings: []")
        else:
            render_mappings(lines, mappings, indent="  ")
    else:
        pool_size = normalize_port(payload.get("pool_size", 3), 3)
        if pool_size < 1:
            pool_size = 1
        strategy = str(payload.get("connection_strategy", "parallel")).strip().lower()
        if strategy not in {"parallel", "priority"}:
            strategy = "parallel"
        mappings = normalize_mappings(payload.get("mappings", []))

        lines.append("client:")
        lines.append(f"  pool_size: {pool_size}")
        lines.append(f"  connection_strategy: {yaml_scalar(strategy)}")
        lines.append("  servers:")
        render_endpoint_block(lines, "client", payload)
        lines.extend(
            [
                "  port_hopping:",
                "    enabled: false",
                "    start_port: 10000",
                "    end_port: 10100",
                "    count: 0",
                '    mode: "spread"',
            ]
        )
        if tunnel_mode == "direct":
            render_mappings(lines, mappings, indent="  ")
        else:
            lines.append("  mappings: []")

    lines.extend(
        [
            "",
            "mux:",
            f"  type: {yaml_scalar(mux_type)}",
            "",
            "network:",
            "  mtu: 0",
            "",
            "security:",
            '  token: ""',
            f"  psk: {yaml_scalar(psk)}",
            '  auth_timeout: "10s"',
            "  acl:",
            "    enabled: false",
            "    allow:",
            '      - "*"',
            "",
            "health:",
            "  enabled: true",
            '  interval: "15s"',
            "",
            "obfuscation:",
            "  enabled: false",
            "  min_padding: 8",
            "  max_padding: 64",
            "  min_delay_ms: 0",
            "  max_delay_ms: 0",
            "  burst_chance: 0",
        ]
    )

    if transport in {"httpmimicry", "httpsmimicry"}:
        lines.extend(
            [
                "",
                "http_mimicry:",
                "  enabled: true",
                '  preset_region: "mixed"',
                '  transport_mode: "websocket"',
                f"  path: {yaml_scalar(str(payload.get('path', '/api/v1/upload')))}",
            ]
        )

    if transport == "reality":
        dest = str(payload.get("reality_dest", "www.microsoft.com:443")).strip() or "www.microsoft.com:443"
        names_raw = str(payload.get("reality_server_names", "www.microsoft.com,microsoft.com"))
        server_names = [n.strip() for n in names_raw.split(",") if n.strip()]
        if not server_names:
            server_names = ["www.microsoft.com", "microsoft.com"]
        short_id = str(payload.get("reality_short_id", "")).strip().lower()
        private_key = str(payload.get("reality_private_key", "")).strip().lower()
        public_key = str(payload.get("reality_public_key", "")).strip().lower()
        lines.extend(
            [
                "",
                "reality:",
                "  enabled: true",
                f"  dest: {yaml_scalar(dest)}",
                f"  server_names: {json.dumps(server_names)}",
                f"  short_id: {yaml_scalar(short_id)}",
                f"  private_key: {yaml_scalar(private_key if role == 'server' else '')}",
                f"  public_key: {yaml_scalar(public_key if role == 'client' else '')}",
            ]
        )

    lines.extend(["", f"license: {yaml_scalar(license_id)}", ""])
    return "\n".join(lines)


def write_config_file(role, instance, config_text):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    cfg_path = config_path_for(role, instance)
    cfg_path.write_text(config_text, encoding="utf-8")
    return cfg_path


def create_or_update_service(role, instance):
    if role not in {"server", "client"}:
        raise ValueError("invalid role")

    if not BINARY_PATH.exists():
        raise RuntimeError(f"{BINARY_PATH} not found. Install nodelay first.")

    service_name = build_service_name(role, instance)
    service_path = service_file_path(service_name)
    cfg_path = config_path_for(role, instance)

    exec_start = f"{BINARY_PATH} {role} -c {cfg_path}"
    description = (
        "NoDelay Tunnel Server" if role == "server" else "NoDelay Tunnel Client"
    )
    if instance != "default":
        description += f" [{instance}]"

    content = f"""[Unit]
Description={description}
After=network.target

[Service]
Type=simple
User=root
ExecStart={exec_start}
Restart=always
RestartSec=3
KillMode=control-group
TimeoutStopSec=8s
KillSignal=SIGTERM
FinalKillSignal=SIGKILL
SendSIGKILL=yes
LimitNOFILE=infinity
LogRateLimitIntervalSec=1h
LogRateLimitBurst=5000

[Install]
WantedBy=multi-user.target
"""

    service_path.write_text(content, encoding="utf-8")
    run_cmd(["systemctl", "daemon-reload"])
    run_cmd(["systemctl", "enable", f"{service_name}.service"])
    run_cmd(["systemctl", "restart", f"{service_name}.service"])
    return service_name


def remove_tunnel_service(service_name):
    role, instance = parse_role_instance(service_name)
    if role not in {"server", "client"}:
        raise ValueError("unsupported tunnel service")

    unit = f"{service_name}.service"
    run_cmd(["systemctl", "stop", unit])
    run_cmd(["systemctl", "disable", unit])

    spath = service_file_path(service_name)
    if spath.exists():
        spath.unlink()

    cpath = config_path_for(role, instance)
    if cpath.exists():
        cpath.unlink()

    run_cmd(["systemctl", "daemon-reload"])


def control_tunnel_service(service_name, action):
    if action not in {"start", "stop", "restart"}:
        raise ValueError("unsupported action")
    unit = f"{service_name}.service"
    rc, out, err = run_cmd(["systemctl", action, unit])
    if rc != 0:
        raise RuntimeError(err or out or f"failed to {action} {unit}")


def tunnel_rows():
    services = list_tunnel_services()
    pid_map = {}
    rows = []
    for service_name in services:
        role, instance = parse_role_instance(service_name)
        if role not in {"server", "client"}:
            continue
        status = service_status(service_name)
        summary = read_config_summary(role, instance)
        pid_map[service_name] = int(status.get("main_pid", 0) or 0)
        rows.append(
            {
                "service": service_name,
                "unit": f"{service_name}.service",
                "role": role,
                "instance": instance,
                "active": status.get("active", "unknown"),
                "sub": status.get("sub", "unknown"),
                "main_pid": pid_map[service_name],
                "config": summary,
            }
        )

    throughput = estimate_service_throughput(pid_map)
    for row in rows:
        stats = throughput.get(row["service"], {"rx_bps": 0.0, "tx_bps": 0.0, "rx_total": 0, "tx_total": 0})
        row["throughput"] = stats
    return rows


class PanelHandler(SimpleHTTPRequestHandler):
    server_version = "NoDelayWebPanel/1.0"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    def log_message(self, fmt, *args):
        # Keep logs concise for systemd journal.
        msg = fmt % args
        print(f"[webpanel] {self.address_string()} {msg}")

    def _read_json_body(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            raise ValueError("invalid JSON body")

    def _api_segments(self):
        parsed = urlparse(self.path)
        parts = [p for p in parsed.path.split("/") if p]
        if len(parts) < 2 or parts[0] != "api":
            return parsed, []
        return parsed, parts[1:]

    def _send_auth_required(self):
        body = b"Authentication required\n"
        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header("WWW-Authenticate", 'Basic realm="NoDelay Web Panel", charset="UTF-8"')
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _is_authorized(self):
        if not AUTH_ENABLED:
            return True

        header = self.headers.get("Authorization", "").strip()
        if not header.startswith("Basic "):
            return False

        token = header[6:].strip()
        if not token:
            return False

        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8")
        except Exception:
            return False
        if ":" not in decoded:
            return False
        username, password = decoded.split(":", 1)
        return hmac.compare_digest(username, AUTH_USERNAME) and hmac.compare_digest(
            password, AUTH_PASSWORD
        )

    def _enforce_auth(self):
        if self._is_authorized():
            return True
        self._send_auth_required()
        return False

    def do_GET(self):
        if not self._enforce_auth():
            return
        parsed, segments = self._api_segments()
        if segments:
            return self.handle_api_get(parsed, segments)

        # SPA fallback.
        if self.path in {"/", ""}:
            self.path = "/index.html"
            return super().do_GET()

        target = STATIC_DIR / self.path.lstrip("/")
        if target.exists() and target.is_file():
            return super().do_GET()

        self.path = "/index.html"
        return super().do_GET()

    def do_POST(self):
        if not self._enforce_auth():
            return
        parsed, segments = self._api_segments()
        if not segments:
            return error_response(self, "unknown API endpoint", HTTPStatus.NOT_FOUND)
        return self.handle_api_post(parsed, segments)

    def do_PUT(self):
        if not self._enforce_auth():
            return
        parsed, segments = self._api_segments()
        if not segments:
            return error_response(self, "unknown API endpoint", HTTPStatus.NOT_FOUND)
        return self.handle_api_put(parsed, segments)

    def do_DELETE(self):
        if not self._enforce_auth():
            return
        parsed, segments = self._api_segments()
        if not segments:
            return error_response(self, "unknown API endpoint", HTTPStatus.NOT_FOUND)
        return self.handle_api_delete(parsed, segments)

    def handle_api_get(self, parsed, segments):
        if segments == ["health"]:
            return json_response(
                self,
                {
                    "ok": True,
                    "time": time.time(),
                    "version": self.server_version,
                },
            )

        if segments == ["resources"]:
            return json_response(self, {"ok": True, "resources": collect_resource_snapshot()})

        if segments == ["tunnels"]:
            return json_response(self, {"ok": True, "tunnels": tunnel_rows()})

        if len(segments) == 3 and segments[0] == "tunnels" and segments[2] == "config":
            service = unquote(segments[1]).strip().removesuffix(".service")
            if not SERVICE_NAME_RE.fullmatch(service):
                return error_response(self, "invalid service name")
            role, instance = parse_role_instance(service)
            if role not in {"server", "client"}:
                return error_response(self, "unsupported tunnel service", HTTPStatus.NOT_FOUND)
            cfg_path = config_path_for(role, instance)
            if not cfg_path.exists():
                return error_response(self, f"config not found: {cfg_path}", HTTPStatus.NOT_FOUND)
            try:
                text = cfg_path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                return error_response(self, f"failed to read config: {exc}", HTTPStatus.INTERNAL_SERVER_ERROR)
            return json_response(self, {"ok": True, "service": service, "config_path": str(cfg_path), "config_text": text})

        if len(segments) == 3 and segments[0] == "tunnels" and segments[2] == "logs":
            service = unquote(segments[1]).strip().removesuffix(".service")
            if not SERVICE_NAME_RE.fullmatch(service):
                return error_response(self, "invalid service name")
            role, _ = parse_role_instance(service)
            if role not in {"server", "client"}:
                return error_response(self, "unsupported tunnel service", HTTPStatus.NOT_FOUND)
            q = parse_qs(parsed.query)
            try:
                lines = int(q.get("lines", ["120"])[0])
            except ValueError:
                lines = 120
            lines = max(20, min(lines, 1000))
            rc, out, err = run_cmd(["journalctl", "-u", f"{service}.service", "-n", str(lines), "--no-pager"])
            if rc != 0:
                return error_response(self, err or out or "failed to read logs", HTTPStatus.INTERNAL_SERVER_ERROR)
            return json_response(self, {"ok": True, "service": service, "logs": out})

        return error_response(self, "unknown API endpoint", HTTPStatus.NOT_FOUND)

    def handle_api_post(self, parsed, segments):
        if segments == ["tunnels"]:
            try:
                payload = self._read_json_body()
            except ValueError as exc:
                return error_response(self, str(exc))

            role = str(payload.get("role", "server")).strip().lower()
            if role not in {"server", "client"}:
                return error_response(self, "role must be server or client")

            try:
                instance = normalize_instance(payload.get("instance", "default"))
            except ValueError as exc:
                return error_response(self, str(exc))

            config_text = str(payload.get("config_text", "")).strip()
            if not config_text:
                try:
                    config_text = build_config_from_payload(payload)
                except Exception as exc:
                    return error_response(self, f"failed to build config: {exc}")

            try:
                cfg_path = write_config_file(role, instance, config_text)
                service_name = create_or_update_service(role, instance)
            except Exception as exc:
                return error_response(self, f"failed to create tunnel: {exc}", HTTPStatus.INTERNAL_SERVER_ERROR)

            return json_response(
                self,
                {
                    "ok": True,
                    "service": service_name,
                    "unit": f"{service_name}.service",
                    "config_path": str(cfg_path),
                },
                status=HTTPStatus.CREATED,
            )

        if len(segments) == 3 and segments[0] == "tunnels" and segments[2] == "action":
            service = unquote(segments[1]).strip().removesuffix(".service")
            if not SERVICE_NAME_RE.fullmatch(service):
                return error_response(self, "invalid service name")

            role, _ = parse_role_instance(service)
            if role not in {"server", "client"}:
                return error_response(self, "unsupported tunnel service", HTTPStatus.NOT_FOUND)

            try:
                payload = self._read_json_body()
            except ValueError as exc:
                return error_response(self, str(exc))

            action = str(payload.get("action", "")).strip().lower()
            if action not in {"start", "stop", "restart"}:
                return error_response(self, "action must be start/stop/restart")

            try:
                control_tunnel_service(service, action)
            except Exception as exc:
                return error_response(self, f"service action failed: {exc}", HTTPStatus.INTERNAL_SERVER_ERROR)

            return json_response(self, {"ok": True, "service": service, "action": action})

        return error_response(self, "unknown API endpoint", HTTPStatus.NOT_FOUND)

    def handle_api_put(self, parsed, segments):
        if len(segments) == 3 and segments[0] == "tunnels" and segments[2] == "config":
            service = unquote(segments[1]).strip().removesuffix(".service")
            if not SERVICE_NAME_RE.fullmatch(service):
                return error_response(self, "invalid service name")
            role, instance = parse_role_instance(service)
            if role not in {"server", "client"}:
                return error_response(self, "unsupported tunnel service", HTTPStatus.NOT_FOUND)

            try:
                payload = self._read_json_body()
            except ValueError as exc:
                return error_response(self, str(exc))

            config_text = str(payload.get("config_text", "")).strip()
            if not config_text:
                return error_response(self, "config_text is required")

            restart = bool_value(payload.get("restart", True), True)

            try:
                cfg_path = write_config_file(role, instance, config_text)
                if restart:
                    control_tunnel_service(service, "restart")
            except Exception as exc:
                return error_response(self, f"failed to update config: {exc}", HTTPStatus.INTERNAL_SERVER_ERROR)

            return json_response(
                self,
                {
                    "ok": True,
                    "service": service,
                    "config_path": str(cfg_path),
                    "restarted": restart,
                },
            )

        return error_response(self, "unknown API endpoint", HTTPStatus.NOT_FOUND)

    def handle_api_delete(self, parsed, segments):
        if len(segments) == 2 and segments[0] == "tunnels":
            service = unquote(segments[1]).strip().removesuffix(".service")
            if not SERVICE_NAME_RE.fullmatch(service):
                return error_response(self, "invalid service name")
            role, _ = parse_role_instance(service)
            if role not in {"server", "client"}:
                return error_response(self, "unsupported tunnel service", HTTPStatus.NOT_FOUND)

            try:
                remove_tunnel_service(service)
            except Exception as exc:
                return error_response(self, f"failed to delete tunnel: {exc}", HTTPStatus.INTERNAL_SERVER_ERROR)

            return json_response(self, {"ok": True, "deleted": service})

        return error_response(self, "unknown API endpoint", HTTPStatus.NOT_FOUND)


def parse_args():
    parser = argparse.ArgumentParser(description="NoDelay Web Panel")
    parser.add_argument("--host", default=os.environ.get("NODELAY_WEBPANEL_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("NODELAY_WEBPANEL_PORT", "8787")))
    return parser.parse_args()


def main():
    global AUTH_ENABLED, AUTH_USERNAME, AUTH_PASSWORD

    load_dotenv(ROOT_DIR / ".env")
    AUTH_ENABLED, AUTH_USERNAME, AUTH_PASSWORD = resolve_auth_config()
    args = parse_args()
    if not STATIC_DIR.exists():
        raise RuntimeError(f"static directory not found: {STATIC_DIR}")

    server = ThreadingHTTPServer((args.host, args.port), PanelHandler)
    auth_state = "enabled" if AUTH_ENABLED else "disabled"
    print(f"NoDelay webpanel authentication: {auth_state}")
    print(f"NoDelay webpanel listening on http://{args.host}:{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
