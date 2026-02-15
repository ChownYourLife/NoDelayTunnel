#!/usr/bin/env python3
import json
import os
import random
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import ipaddress
import unicodedata
import urllib.request
import uuid
import builtins

# Configuration
REPO_OWNER = "ChownYourLife"
REPO_NAME = "NoDelayTunnel"
BINARY_NAME = "nodelay"
INSTALL_DIR = "/usr/local/bin"
CONFIG_DIR = "/etc/nodelay"
SERVER_SERVICE_NAME = "nodelay-server"
CLIENT_SERVICE_NAME = "nodelay-client"
LEGACY_SERVICE_NAME = "nodelay"
SYSTEMD_DIR = "/etc/systemd/system"

SERVICE_PROFILES = {
    "server": {
        "name": SERVER_SERVICE_NAME,
        "description": "NoDelay Tunnel Server",
        "mode": "server",
    },
    "client": {
        "name": CLIENT_SERVICE_NAME,
        "description": "NoDelay Tunnel Client",
        "mode": "client",
    },
}

ROLE_LABELS = {
    "server": "Iran Server",
    "client": "Kharej Server",
}

# DER prefixes for extracting raw x25519 keys (last 32 bytes are key material)
X25519_PRIVATE_DER_PREFIX = bytes.fromhex("302e020100300506032b656e04220420")
X25519_PUBLIC_DER_PREFIX = bytes.fromhex("302a300506032b656e032100")


class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-9;]*m")


try:
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(errors="replace")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
except Exception:
    pass


_ORIGINAL_INPUT = builtins.input


def safe_input(prompt=""):
    try:
        return _ORIGINAL_INPUT(prompt)
    except UnicodeDecodeError:
        if prompt:
            print(prompt, end="", flush=True)
        raw = sys.stdin.buffer.readline()
        if raw == b"":
            raise EOFError
        encoding = getattr(sys.stdin, "encoding", None) or "utf-8"
        return raw.decode(encoding, errors="replace").rstrip("\r\n")


builtins.input = safe_input


def _char_display_width(ch):
    # Ignore zero-width / formatting code points and combining marks.
    if ch in {"\u200c", "\u200d", "\ufe0e", "\ufe0f"}:
        return 0
    if unicodedata.combining(ch):
        return 0
    if unicodedata.category(ch) in {"Cf", "Mn", "Me"}:
        return 0
    if unicodedata.east_asian_width(ch) in {"F", "W"}:
        return 2
    return 1


def visible_len(text):
    clean = ANSI_ESCAPE_PATTERN.sub("", str(text))
    return sum(_char_display_width(ch) for ch in clean)


def pad_visible(text, width):
    raw = str(text)
    return raw + (" " * max(0, width - visible_len(raw)))


def print_3d_panel(title, lines=None, color=Colors.CYAN, min_width=52):
    panel_lines = [f"{Colors.BOLD}{title}{Colors.ENDC}"]
    panel_lines.extend(str(line) for line in (lines or []))
    inner_width = max(min_width, max(visible_len(line) for line in panel_lines))
    horizontal = "━" * (inner_width + 2)

    print("")
    print(f"{color}┏{horizontal}┓{Colors.ENDC}")
    for line in panel_lines:
        print(
            f"{color}┃{Colors.ENDC} {pad_visible(line, inner_width)} "
            f"{color}┃{Colors.ENDC}{Colors.BLUE}▓{Colors.ENDC}"
        )
    print(f"{color}┗{horizontal}┛{Colors.ENDC}{Colors.BLUE}▓{Colors.ENDC}")
    print(f"{Colors.BLUE} {'▓' * (inner_width + 3)}{Colors.ENDC}")


def print_menu(title, lines, color=Colors.CYAN, min_width=52):
    print_3d_panel(title, lines=lines, color=color, min_width=min_width)


def print_header(text):
    print_3d_panel(text, color=Colors.HEADER, min_width=34)


def print_success(text):
    print(f"{Colors.GREEN}[+] {text}{Colors.ENDC}")


def print_info(text):
    print(f"{Colors.BLUE}[*] {text}{Colors.ENDC}")


def print_error(text):
    print(f"{Colors.FAIL}[!] {text}{Colors.ENDC}")


def run_command(command, check=True):
    try:
        subprocess.run(
            command,
            check=check,
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def run_command_output(command):
    result = subprocess.run(
        command,
        shell=True,
        text=True,
        capture_output=True,
    )
    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()
    return result.returncode, stdout, stderr


def run_command_stream(command):
    return subprocess.run(command, shell=True, check=False).returncode == 0


def command_succeeds(command):
    result = subprocess.run(
        command,
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def service_file_path(service_name):
    return os.path.join(SYSTEMD_DIR, f"{service_name}.service")


def service_exists(service_name):
    if os.path.exists(service_file_path(service_name)):
        return True
    quoted = shlex.quote(f"{service_name}.service")
    return command_succeeds(f"systemctl cat {quoted}")


def normalize_instance_name(raw):
    value = (raw or "").strip().lower()
    if not value:
        return "default"
    if value in {"default", "main", "primary"}:
        return "default"
    if re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,31}", value) is None:
        raise ValueError("Instance name must match [a-z0-9][a-z0-9_-]{0,31}")
    return value


def build_service_name(role, instance="default"):
    profile = SERVICE_PROFILES[role]
    if instance == "default":
        return profile["name"]
    return f"{profile['name']}-{instance}"


def role_display(role):
    return ROLE_LABELS.get(role, role)


def build_config_filename(role, instance="default"):
    if role == "server":
        return "config.yaml" if instance == "default" else f"config-{instance}.yaml"
    return "client_config.yaml" if instance == "default" else f"client_config-{instance}.yaml"


def parse_service_role_instance(service_name):
    for role in ("server", "client"):
        base = SERVICE_PROFILES[role]["name"]
        if service_name == base:
            return role, "default"
        prefix = f"{base}-"
        if service_name.startswith(prefix):
            instance = service_name[len(prefix):].strip()
            if instance:
                return role, instance
    return None, None


def service_matches_project(service_name):
    if service_name == LEGACY_SERVICE_NAME:
        return True
    for role in ("server", "client"):
        base = SERVICE_PROFILES[role]["name"]
        if service_name == base or service_name.startswith(f"{base}-"):
            return True
    return False


def installed_services():
    services = set()

    if os.path.isdir(SYSTEMD_DIR):
        for entry in os.listdir(SYSTEMD_DIR):
            if not entry.endswith(".service"):
                continue
            service = entry[:-8]
            if service_matches_project(service):
                services.add(service)

    known = [SERVER_SERVICE_NAME, CLIENT_SERVICE_NAME, LEGACY_SERVICE_NAME]
    for service in known:
        if service_exists(service):
            services.add(service)

    return sorted(services)


def choose_services(allow_all=False, action_label="service"):
    services = installed_services()
    if not services:
        print_error("No tunnel services are installed.")
        return []

    menu_lines = []
    for index, service in enumerate(services, start=1):
        menu_lines.append(f"{index}. {service}.service")
    if allow_all and len(services) > 1:
        menu_lines.append(f"{len(services) + 1}. all")
    print_menu(f"{action_label.title()} Target", menu_lines, color=Colors.CYAN, min_width=42)

    prompt = f"Select {action_label} [1-{len(services) + (1 if allow_all and len(services) > 1 else 0)}]: "
    while True:
        choice = input(prompt).strip()
        if not choice.isdigit():
            print_error("Invalid choice.")
            continue

        index = int(choice)
        if 1 <= index <= len(services):
            return [services[index - 1]]
        if allow_all and len(services) > 1 and index == len(services) + 1:
            return services
        print_error("Invalid choice.")


def service_state(service_name):
    quoted = shlex.quote(f"{service_name}.service")
    active_rc, active_out, active_err = run_command_output(f"systemctl is-active {quoted}")
    enabled_rc, enabled_out, enabled_err = run_command_output(f"systemctl is-enabled {quoted}")

    active = active_out if active_rc == 0 else (active_out or active_err or "unknown")
    enabled = enabled_out if enabled_rc == 0 else (enabled_out or enabled_err or "unknown")
    return active, enabled


def print_services_status():
    services = installed_services()
    if not services:
        print_error("No tunnel services are installed.")
        return

    print_header("📈 Tunnel Status")
    for service in services:
        active, enabled = service_state(service)
        print(f"{service}.service")
        print(f"  active:  {active}")
        print(f"  enabled: {enabled}")

def check_root():
    if os.geteuid() != 0:
        print_error("This script must be run as root.")
        sys.exit(1)


def apply_linux_network_tuning(profile_key="balanced"):
    if not sys.platform.startswith("linux"):
        print_info("Skipping network tuning: only supported on Linux.")
        return False

    profile = str(profile_key or "balanced").strip().lower()
    tuning_profiles = {
        "balanced": {
            "title": "🚀 Linux Network Tuning (Balanced)",
            "sysctl": [
                # Stable bidirectional throughput under mixed paths (recommended).
                ("net.core.rmem_max", "16777216"),
                ("net.core.wmem_max", "16777216"),
                ("net.core.rmem_default", "262144"),
                ("net.core.wmem_default", "262144"),
                ("net.ipv4.tcp_rmem", "4096 131072 16777216"),
                ("net.ipv4.tcp_wmem", "4096 131072 16777216"),
                ("net.ipv4.tcp_window_scaling", "1"),
                ("net.ipv4.tcp_timestamps", "1"),
                ("net.ipv4.tcp_sack", "1"),
                ("net.core.netdev_max_backlog", "8192"),
                ("net.core.somaxconn", "4096"),
                ("net.ipv4.tcp_fastopen", "1"),
                ("net.ipv4.tcp_mtu_probing", "1"),
                ("net.ipv4.tcp_keepalive_time", "120"),
                ("net.ipv4.tcp_keepalive_intvl", "10"),
                ("net.ipv4.tcp_keepalive_probes", "3"),
                ("net.ipv4.tcp_fin_timeout", "20"),
            ],
            "congestion_control": "bbr",
            "qdisc": "fq_codel",
        },
        "aggressive": {
            "title": "🚀 Linux Network Tuning (Aggressive)",
            "sysctl": [
                # Higher throughput bias; may reduce stability on some uplinks.
                ("net.core.rmem_max", "33554432"),
                ("net.core.wmem_max", "33554432"),
                ("net.core.rmem_default", "262144"),
                ("net.core.wmem_default", "262144"),
                ("net.ipv4.tcp_rmem", "4096 131072 33554432"),
                ("net.ipv4.tcp_wmem", "4096 131072 33554432"),
                ("net.ipv4.tcp_window_scaling", "1"),
                ("net.ipv4.tcp_timestamps", "1"),
                ("net.ipv4.tcp_sack", "1"),
                ("net.core.netdev_max_backlog", "16384"),
                ("net.core.somaxconn", "8192"),
                ("net.ipv4.tcp_fastopen", "3"),
                ("net.ipv4.tcp_mtu_probing", "1"),
                ("net.ipv4.tcp_slow_start_after_idle", "0"),
                ("net.ipv4.tcp_no_metrics_save", "1"),
                ("net.ipv4.tcp_autocorking", "0"),
                ("net.ipv4.tcp_keepalive_time", "90"),
                ("net.ipv4.tcp_keepalive_intvl", "10"),
                ("net.ipv4.tcp_keepalive_probes", "3"),
                ("net.ipv4.tcp_fin_timeout", "15"),
            ],
            "congestion_control": "bbr",
            "qdisc": "fq_codel",
        },
    }
    if profile not in tuning_profiles:
        profile = "balanced"
    selected = tuning_profiles[profile]

    print_header(selected["title"])
    sysctl_settings = selected["sysctl"]

    failed = []
    for key, value in sysctl_settings:
        cmd = f"sysctl -w {key}={shlex.quote(value)}"
        if not run_command(cmd, check=False):
            failed.append(key)

    bbr_ok = run_command("modprobe tcp_bbr", check=False)
    if bbr_ok:
        bbr_ok = run_command(
            f"sysctl -w net.ipv4.tcp_congestion_control={shlex.quote(selected['congestion_control'])}",
            check=False,
        )
    qdisc_ok = run_command(
        f"sysctl -w net.core.default_qdisc={shlex.quote(selected['qdisc'])}",
        check=False,
    )

    _, iface, _ = run_command_output("ip -o link show up | awk -F': ' '$2 != \"lo\" {print $2; exit}'")
    iface = iface.strip() or "eth0"
    tc_ok = run_command(
        f"tc qdisc replace dev {shlex.quote(iface)} root {shlex.quote(selected['qdisc'])}",
        check=False,
    )

    conf_lines = ["# NoDelay Tunnel Linux network tuning"]
    conf_lines.extend([f"{k}={v}" for k, v in sysctl_settings])
    conf_lines.append(f"net.ipv4.tcp_congestion_control={selected['congestion_control']}")
    conf_lines.append(f"net.core.default_qdisc={selected['qdisc']}")
    conf_path = "/etc/sysctl.d/99-nodelay.conf"
    try:
        with open(conf_path, "w") as handle:
            handle.write("\n".join(conf_lines) + "\n")
        run_command("sysctl --system", check=False)
        print_success(f"Persisted sysctl settings to {conf_path}")
    except OSError as exc:
        print_error(f"Could not write {conf_path}: {exc}")

    if failed:
        print_error(f"Some sysctl keys could not be applied: {', '.join(failed)}")
    if bbr_ok:
        print_success("BBR enabled")
    else:
        print_info("BBR not enabled (kernel/module may not support it).")
    if qdisc_ok and tc_ok:
        print_success(f"{selected['qdisc']} configured on {iface}")
    else:
        print_info(
            f"{selected['qdisc']} could not be fully applied; verify `tc` and interface state."
        )
    return True


def restore_linux_network_defaults():
    if not sys.platform.startswith("linux"):
        print_info("Skipping network defaults restore: only supported on Linux.")
        return False

    print_header("♻️ Restore Linux Network Defaults")
    conf_path = "/etc/sysctl.d/99-nodelay.conf"
    if os.path.exists(conf_path):
        try:
            os.remove(conf_path)
            print_success(f"Removed tuning file: {conf_path}")
        except OSError as exc:
            print_error(f"Could not remove {conf_path}: {exc}")
            return False
    else:
        print_info("No persisted NoDelay tuning file found.")

    run_command("sysctl --system", check=False)
    run_command("sysctl -w net.ipv4.tcp_congestion_control=cubic", check=False)
    _, iface, _ = run_command_output("ip -o link show up | awk -F': ' '$2 != \"lo\" {print $2; exit}'")
    iface = iface.strip() or "eth0"
    run_command(f"tc qdisc del dev {shlex.quote(iface)} root", check=False)
    print_success("Restored Linux network defaults (best effort).")
    return True


def maybe_apply_linux_network_tuning():
    print_menu(
        "⚙️ Linux Optimization",
        [
            "1. Balanced (Recommended)",
            "2. Aggressive",
            "3. Restore Linux Defaults",
            "0. Skip",
        ],
        color=Colors.CYAN,
        min_width=42,
    )
    while True:
        choice = input_default("Select optimization [0-3]", "1").strip()
        if choice == "0":
            return
        if choice == "1":
            apply_linux_network_tuning("balanced")
            return
        if choice == "2":
            apply_linux_network_tuning("aggressive")
            return
        if choice == "3":
            restore_linux_network_defaults()
            return
        print_error("Invalid choice.")


def get_latest_release():
    url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/releases/latest"
    try:
        with urllib.request.urlopen(url) as response:
            data = json.loads(response.read().decode())
            return data
    except Exception as e:
        print_error(f"Failed to fetch release info: {e}")
        return None


def print_banner():
    os.system("clear" if os.name == "posix" else "cls")
    print_3d_panel(
        "✨ NoDelay Tunnel Made By Hosi ✨",
        [
            "📢 Channel: @NodelayTunnel",
            "🔧 Fast, stable, stealth-focused deployment",
        ],
        color=Colors.CYAN,
        min_width=56,
    )


def ensure_binary():
    bin_path = os.path.join(INSTALL_DIR, BINARY_NAME)
    if os.path.exists(bin_path):
        print_success(f"✅ Binary found at {bin_path}")
        return True
    return download_binary()


def download_binary():
    print_header("🔽 Downloading NoDelay Binary")
    release = get_latest_release()
    if release and release.get("tag_name"):
        print_info(f"Latest version: {release['tag_name']}")

    # Always download the latest release binary by fixed asset name.
    # No compatibility/architecture filtering is applied by design.
    download_url = (
        f"https://github.com/{REPO_OWNER}/{REPO_NAME}/releases/latest/download/{BINARY_NAME}"
    )

    print_info(f"Downloading: {download_url}")
    try:
        temp_path = "/tmp/nodelay_dl"
        urllib.request.urlretrieve(download_url, temp_path)
        os.chmod(temp_path, 0o755)
        shutil.move(temp_path, os.path.join(INSTALL_DIR, BINARY_NAME))
        print_success("✅ Download complete.")
        return True
    except Exception as e:
        print_error(f"❌ Download failed: {e}")
        return False


def generate_uuid():
    return str(uuid.uuid4())


def random_hex(chars):
    return "".join(random.choice("0123456789abcdef") for _ in range(chars))


def input_default(prompt, default):
    val = input(f"{prompt} [{default}]: ").strip()
    return val if val else str(default)


def input_required(prompt):
    while True:
        val = input(f"{prompt}: ").strip()
        if val:
            return val
        print_error("This field is required.")


def parse_bool(value, default=False):
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "t", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "f", "no", "n", "off"}:
        return False
    return default


def parse_csv(value):
    return [item.strip() for item in value.split(",") if item.strip()]


def normalize_path(path, fallback):
    path = (path or "").strip()
    if not path:
        path = fallback
    if not path.startswith("/"):
        path = f"/{path}"
    return path


def is_valid_hex_bytes(value, byte_len):
    return re.fullmatch(rf"[0-9a-f]{{{byte_len * 2}}}", value or "") is not None


def is_valid_short_id(value):
    if not value:
        return False
    if re.fullmatch(r"[0-9a-f]+", value) is None:
        return False
    if len(value) < 8:
        return False
    return len(value) % 2 == 0


def generate_self_signed_cert(common_name="www.example.com"):
    cert_dir = os.path.join(CONFIG_DIR, "certs")
    if not os.path.exists(cert_dir):
        os.makedirs(cert_dir)

    key_path = os.path.join(cert_dir, "selfsigned.key")
    cert_path = os.path.join(cert_dir, "selfsigned.crt")

    print_info(f"Generating self-signed certificate for {common_name}...")
    cmd = f'openssl req -x509 -newkey rsa:2048 -keyout "{key_path}" -out "{cert_path}" -days 3650 -nodes -subj "/CN={common_name}"'
    if run_command(cmd):
        print_success("Certificate generated.")
        return cert_path, key_path
    print_error("Failed to generate certificate via openssl.")
    return "", ""


def run_args_stream(args):
    try:
        return subprocess.run(args, check=False).returncode == 0
    except Exception:
        return False


def normalize_domain_name(value):
    return str(value or "").strip().lower().rstrip(".")


def is_valid_domain_name(value):
    host = normalize_domain_name(value)
    if not host or len(host) > 253:
        return False
    if re.fullmatch(r"[a-z0-9.-]+", host) is None:
        return False
    labels = host.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
    return True


def normalize_ip_identifier(value):
    raw = str(value or "").strip()
    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1]
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return ""


def cert_base_name(identifier):
    safe = re.sub(r"[^a-z0-9._-]+", "_", str(identifier or "").strip().lower())
    return safe or "trusted_cert"


def purge_existing_ip_cert_state(acme_sh, identifier, cert_path, key_path):
    removed_any = False

    # Remove previously installed local certificate/key files.
    for path in (cert_path, key_path):
        if path and os.path.exists(path):
            try:
                os.remove(path)
                removed_any = True
                print_info(f"Removed existing file: {path}")
            except OSError as exc:
                print_error(f"Could not remove existing file {path}: {exc}")

    # Remove existing ACME renewal record if it exists.
    if run_args_stream([acme_sh, "--remove", "-d", identifier]):
        removed_any = True
        print_info(f"Removed existing ACME record for IP: {identifier}")

    # Remove local acme.sh state directories for this identifier.
    acme_home = os.path.expanduser("~/.acme.sh")
    if os.path.isdir(acme_home):
        candidates = (
            identifier,
            f"{identifier}_ecc",
            f"{identifier}_rsa",
        )
        for name in candidates:
            entry = os.path.join(acme_home, name)
            if os.path.isdir(entry):
                try:
                    shutil.rmtree(entry)
                    removed_any = True
                    print_info(f"Removed existing ACME state: {entry}")
                except OSError as exc:
                    print_error(f"Could not remove ACME state {entry}: {exc}")

    if removed_any:
        print_info(f"Existing IP certificate state was cleared for {identifier}. Reissuing...")


def find_acme_sh():
    candidates = [
        os.path.expanduser("~/.acme.sh/acme.sh"),
        "/root/.acme.sh/acme.sh",
    ]
    from_path = shutil.which("acme.sh")
    if from_path:
        candidates.append(from_path)
    for path in candidates:
        if path and os.path.exists(path):
            return path
    return ""


def ensure_acme_sh_installed(email):
    acme_sh = find_acme_sh()
    if acme_sh:
        return acme_sh
    if shutil.which("curl") is None:
        print_error("curl is required to install acme.sh automatically.")
        return ""
    print_info("acme.sh not found. Installing acme.sh...")
    cmd = f"curl -fsSL https://get.acme.sh | sh -s email={shlex.quote(email)}"
    if not run_command_stream(cmd):
        print_error("Failed to install acme.sh.")
        return ""
    acme_sh = find_acme_sh()
    if not acme_sh:
        print_error("acme.sh installation completed but binary was not found.")
        return ""
    return acme_sh


def stop_active_tunnel_services():
    stopped = []
    for service in installed_services():
        active, _ = service_state(service)
        if active.strip().lower() != "active":
            continue
        quoted = shlex.quote(f"{service}.service")
        if run_command(f"systemctl stop {quoted}", check=False):
            stopped.append(service)
            print_info(f"Stopped {service}.service for ACME challenge.")
        else:
            print_error(f"Could not stop {service}.service.")
    return stopped


def start_tunnel_services(services):
    for service in services:
        quoted = shlex.quote(f"{service}.service")
        if run_command(f"systemctl start {quoted}", check=False):
            print_info(f"Started {service}.service.")
        else:
            print_error(f"Could not restart {service}.service.")


def generate_trusted_cert_acme():
    print_menu(
        "Trusted Certificate (ACME)",
        [
            "1. Domain certificate (Let's Encrypt, HTTP-01 on port 80)",
            "2. IP certificate (Let's Encrypt, TLS-ALPN-01 on port 443)",
        ],
        color=Colors.CYAN,
        min_width=74,
    )

    while True:
        mode = input_default("Select mode [1/2]", "1").strip()
        if mode in {"1", "2"}:
            break
        print_error("Invalid choice. Select 1 or 2.")

    cert_profile = ""
    if mode == "1":
        while True:
            identifier = normalize_domain_name(
                input_default("Domain for certificate (must resolve to this server)", "example.com")
            )
            if is_valid_domain_name(identifier):
                break
            print_error("Invalid domain format.")
        ca_server = "letsencrypt"
        issue_args = ["--issue", "--standalone", "-d", identifier, "--server", ca_server]
    else:
        while True:
            identifier = normalize_ip_identifier(
                input_default("Public IP for certificate", "")
            )
            if identifier:
                break
            print_error("Invalid IP address.")
        ca_server = "letsencrypt"
        issue_args = ["--issue", "--alpn", "-d", identifier, "--server", ca_server]
        cert_profile = "shortlived"

    email = input_required("ACME account email")
    acme_sh = ensure_acme_sh_installed(email)
    if not acme_sh:
        return "", ""

    cert_dir = os.path.join(CONFIG_DIR, "certs")
    if not os.path.exists(cert_dir):
        os.makedirs(cert_dir)

    base = cert_base_name(identifier)
    cert_path = os.path.join(cert_dir, f"trusted-{base}.crt")
    key_path = os.path.join(cert_dir, f"trusted-{base}.key")

    if mode == "2":
        purge_existing_ip_cert_state(acme_sh, identifier, cert_path, key_path)

    stop_services = input_default(
        "Temporarily stop nodelay services for ACME challenge? (Y/n)",
        "y",
    ).strip().lower()
    stopped = []
    if stop_services in {"", "y", "yes"}:
        stopped = stop_active_tunnel_services()

    try:
        # Register account if needed (safe to re-run).
        run_args_stream([acme_sh, "--register-account", "-m", email, "--server", ca_server])

        if cert_profile:
            issue_args.extend(["--cert-profile", cert_profile])
            print_info(
                f"Issuing trusted certificate for {identifier} using ACME ({ca_server}, profile={cert_profile})..."
            )
        else:
            print_info(
                f"Issuing trusted certificate for {identifier} using ACME ({ca_server})..."
            )
        if not run_args_stream([acme_sh] + issue_args):
            print_error("ACME issue failed. Ensure challenge ports are reachable from the internet.")
            return "", ""

        install_args = [
            acme_sh,
            "--install-cert",
            "-d",
            identifier,
            "--key-file",
            key_path,
            "--fullchain-file",
            cert_path,
        ]
        if not run_args_stream(install_args):
            print_error("ACME certificate install failed.")
            return "", ""

        print_success(f"Trusted certificate generated: {cert_path}")
        print_success(f"Private key generated      : {key_path}")
        return cert_path, key_path
    finally:
        if stopped:
            start_tunnel_services(stopped)


def ask_cert_options():
    print_menu(
        "Certificate Options",
        [
            "1. Use existing certificate path",
            "2. Generate self-signed certificate (Auto)",
            "3. Generate trusted certificate (ACME)",
        ],
        color=Colors.CYAN,
        min_width=54,
    )
    choice = input_default("Select option [1/2/3]", "1").strip()
    if choice == "3":
        return generate_trusted_cert_acme()
    if choice == "2":
        domain = input_default("Enter domain for certificate", "www.bing.com")
        return generate_self_signed_cert(domain)
    cert = input_required("Certificate Path")
    key = input_required("Private Key Path")
    return cert, key


def extract_x25519_key_from_der(der_data, prefix):
    if len(der_data) < len(prefix) + 32:
        return ""
    if der_data.startswith(prefix):
        return der_data[-32:].hex()
    return ""


def generate_reality_keypair():
    if shutil.which("openssl") is None:
        print_error("OpenSSL is required to generate REALITY keys but was not found.")
        return "", ""

    try:
        with tempfile.TemporaryDirectory() as tmp_dir:
            priv_pem = os.path.join(tmp_dir, "reality_private.pem")
            priv_der = os.path.join(tmp_dir, "reality_private.der")
            pub_der = os.path.join(tmp_dir, "reality_public.der")

            subprocess.run(
                ["openssl", "genpkey", "-algorithm", "X25519", "-out", priv_pem],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                ["openssl", "pkey", "-in", priv_pem, "-outform", "DER", "-out", priv_der],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                [
                    "openssl",
                    "pkey",
                    "-in",
                    priv_pem,
                    "-pubout",
                    "-outform",
                    "DER",
                    "-out",
                    pub_der,
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            with open(priv_der, "rb") as f:
                private_der = f.read()
            with open(pub_der, "rb") as f:
                public_der = f.read()

            private_key = extract_x25519_key_from_der(
                private_der, X25519_PRIVATE_DER_PREFIX
            )
            public_key = extract_x25519_key_from_der(public_der, X25519_PUBLIC_DER_PREFIX)
            if not private_key or not public_key:
                raise ValueError("Unexpected OpenSSL DER format for x25519 keys")

            return private_key, public_key
    except Exception as e:
        print_error(f"Failed to generate REALITY keypair: {e}")
        return "", ""


def derive_reality_public_key(private_key_hex):
    if not is_valid_hex_bytes(private_key_hex, 32):
        return ""
    if shutil.which("openssl") is None:
        return ""

    try:
        with tempfile.TemporaryDirectory() as tmp_dir:
            priv_der = os.path.join(tmp_dir, "reality_private.der")
            pub_der = os.path.join(tmp_dir, "reality_public.der")

            with open(priv_der, "wb") as f:
                f.write(X25519_PRIVATE_DER_PREFIX + bytes.fromhex(private_key_hex))

            subprocess.run(
                [
                    "openssl",
                    "pkey",
                    "-inform",
                    "DER",
                    "-in",
                    priv_der,
                    "-pubout",
                    "-outform",
                    "DER",
                    "-out",
                    pub_der,
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            with open(pub_der, "rb") as f:
                public_der = f.read()

            return extract_x25519_key_from_der(public_der, X25519_PUBLIC_DER_PREFIX)
    except Exception:
        return ""


def prompt_short_id():
    while True:
        short_id = input_default("Short ID (hex, min 8 chars)", random_hex(8)).lower()
        if is_valid_short_id(short_id):
            return short_id
        print_error("Invalid Short ID. Use even-length hex with at least 8 characters.")


def prompt_server_names():
    while True:
        names = parse_csv(
            input_default(
                "Server Names (comma separated)", "www.microsoft.com,microsoft.com"
            )
        )
        if names:
            return names
        print_error("At least one server name is required.")


def prompt_reality_private_key():
    while True:
        key = input(
            "Private Key (x25519, 64 hex chars) [leave empty to auto-generate]: "
        ).strip().lower()
        if not key:
            private_key, public_key = generate_reality_keypair()
            if not private_key or not public_key:
                continue
            print_success("REALITY keypair generated automatically.")
            print_info(f"REALITY Private Key: {private_key}")
            print_info(f"REALITY Public Key : {public_key}")
            return private_key, public_key, True

        if is_valid_hex_bytes(key, 32):
            public_key = derive_reality_public_key(key)
            if public_key:
                print_info(f"Derived REALITY Public Key: {public_key}")
            else:
                print_info(
                    "Could not derive public key from private key automatically. "
                    "You can still proceed with this server private key."
                )
            return key, public_key, False

        print_error("Invalid private key. Expected exactly 64 hex characters.")


def prompt_reality_public_key():
    while True:
        key = input(
            "Server Public Key (x25519, 64 hex chars) [leave empty to auto-generate pair]: "
        ).strip().lower()
        if not key:
            private_key, public_key = generate_reality_keypair()
            if not private_key or not public_key:
                continue
            print_success("REALITY keypair generated automatically.")
            print_info(f"REALITY Private Key: {private_key}")
            print_info(f"REALITY Public Key : {public_key}")
            print_info(
                "Use the private key on the server and this public key on the client."
            )
            return public_key, private_key, True

        if is_valid_hex_bytes(key, 32):
            return key, "", False

        print_error("Invalid public key. Expected exactly 64 hex characters.")


def split_host_port(value, fallback_port):
    raw = str(value or "").strip()
    m = re.search(r"^(.*):(\d+)$", raw)
    if not m:
        return "", int(fallback_port)
    host = m.group(1).strip()
    try:
        port = int(m.group(2))
    except ValueError:
        port = int(fallback_port)
    return host, port


def prompt_server_mappings(
    existing=None,
    fixed_mode=None,
    bind_side_label="This node",
    target_side_label="Remote node",
):
    print_header("🔀 Configure Tunnel Mappings")
    if fixed_mode in {"reverse", "direct"}:
        print_info(
            f"Mapping mode is fixed to '{fixed_mode}' by tunnel type. "
            f"Bind side: {bind_side_label} | Target side: {target_side_label}"
        )
    else:
        print_info(
            "At least one mapping is required. You only enter ports; bind/target IPs are auto-filled."
        )
    mappings = []
    if isinstance(existing, list):
        mappings = deep_copy(existing)
    if mappings:
        keep_existing = input_default("Keep current mappings and skip editing? (Y/n)", "y").strip().lower()
        if keep_existing in {"y", "yes"}:
            return mappings
        mappings = []
    index = 1

    while True:
        print(f"\n{Colors.CYAN}Mapping #{index}{Colors.ENDC}")
        name = input_default("Name", f"mapping-{index}")

        if fixed_mode in {"reverse", "direct"}:
            mode = fixed_mode
            print_info(f"Mode: {mode} (locked)")
        else:
            while True:
                mode = input_default("Mode (reverse/direct)", "reverse").strip().lower()
                if mode in {"reverse", "direct"}:
                    break
                print_error("Mode must be 'reverse' or 'direct'.")

        while True:
            protocol = input_default("Protocol (tcp/udp)", "tcp").strip().lower()
            if protocol in {"tcp", "udp"}:
                break
            print_error("Protocol must be 'tcp' or 'udp'.")

        if mode == "reverse":
            bind_default = 2200 if protocol == "tcp" else 15353
            target_default = 22 if protocol == "tcp" else 53
        else:
            bind_default = 18080 if protocol == "tcp" else 15353
            target_default = 80 if protocol == "tcp" else 53

        bind_port = prompt_int("Bind port (auto bind IP = 0.0.0.0)", bind_default)
        while bind_port < 1 or bind_port > 65535:
            print_error("Port must be between 1 and 65535.")
            bind_port = prompt_int("Bind port (auto bind IP = 0.0.0.0)", bind_default)

        target_port = prompt_int("Target port (auto target IP = 127.0.0.1)", target_default)
        while target_port < 1 or target_port > 65535:
            print_error("Port must be between 1 and 65535.")
            target_port = prompt_int("Target port (auto target IP = 127.0.0.1)", target_default)

        bind = f"0.0.0.0:{bind_port}"
        target = f"127.0.0.1:{target_port}"

        mappings.append(
            {
                "name": name,
                "mode": mode,
                "protocol": protocol,
                "bind": bind,
                "target": target,
            }
        )

        more = input_default("Add another mapping? (y/N)", "n").strip().lower()
        if more not in {"y", "yes"}:
            break
        index += 1

    return mappings


def prompt_client_tls_settings(server_addr, default_sni="", default_skip_verify=True):
    sni_default = default_sni or server_addr
    sni = input_default("Server Name (SNI)", sni_default).strip()
    skip_verify_raw = input_default(
        "Insecure Skip Verify (true/false)",
        "true" if default_skip_verify else "false",
    )
    skip_verify = parse_bool(skip_verify_raw, default=True)
    return sni, skip_verify


def normalize_mimicry_preset_region(value, default="mixed"):
    raw = str(value or "").strip().lower()
    if raw in {"iran", "ir", "domestic"}:
        return "iran"
    if raw in {"foreign", "intl", "international", "global", "outside"}:
        return "foreign"
    if raw in {"mixed", "both", "combined", "all"}:
        return "mixed"
    return default


def normalize_network_mtu(value, default=0):
    try:
        mtu = int(value)
    except (TypeError, ValueError):
        return default
    if mtu <= 0:
        return 0
    if mtu < 576:
        return 576
    if mtu > 9000:
        return 9000
    return mtu


def prompt_network_mtu(default=0):
    normalized_default = normalize_network_mtu(default, 0)
    while True:
        mtu = prompt_int(
            "Path MTU override (0=disabled, set same on both sides; suggested 1200-1400)",
            normalized_default,
        )
        if mtu == 0:
            return 0
        if 576 <= mtu <= 9000:
            return mtu
        print_error("Path MTU must be 0 or between 576 and 9000.")


def normalize_mimicry_transport_mode(value, default="websocket"):
    raw = str(value or "").strip().lower()
    if raw in {"", "websocket", "ws", "wss"}:
        return "websocket"
    if raw in {"http2", "h2"}:
        return "http2"
    return default


def prompt_mimicry_transport_mode(default="websocket"):
    normalized_default = normalize_mimicry_transport_mode(default, "websocket")
    default_choice = "2" if normalized_default == "http2" else "1"
    print_menu(
        "🎛️ Mimicry Transport Mode",
        [
            f"{Colors.GREEN}[1]{Colors.ENDC} WebSocket ({Colors.BOLD}ws/wss{Colors.ENDC})",
            f"{Colors.GREEN}[2]{Colors.ENDC} HTTP/2 stream tunnel",
        ],
        color=Colors.CYAN,
        min_width=44,
    )
    while True:
        choice = input_default("Mode [1-2]", default_choice).strip()
        if choice == "1":
            return "websocket"
        if choice == "2":
            return "http2"
        print_error("Invalid choice. Pick 1 or 2.")


def prompt_client_destination(default_host="127.0.0.1", default_port=443):
    while True:
        host = input_default("Destination Host (IP/Domain)", default_host).strip()
        if host:
            break
        print_error("Destination host is required.")

    while True:
        port = prompt_int("Destination Port", default_port)
        if 1 <= port <= 65535:
            return host, port
        print_error("Destination port must be between 1 and 65535.")


def prompt_license_id():
    while True:
        value = input("License ID: ").strip()
        if value:
            return value
        print_error("License ID is required.")


def menu_protocol(role, server_addr="", defaults=None):
    options = [
        ("1", "🌐 TCP"),
        ("2", "🔒 TLS"),
        ("3", "🕸️ WebSocket (WS)"),
        ("4", "🛡️ WebSocket Secure (WSS)"),
        ("5", "⚡ KCP"),
        ("6", "🚄 QUIC"),
        ("7", "🎭 HTTPS Mimicry"),
        ("8", "📄 HTTP Mimicry"),
        ("9", "🌌 REALITY"),
    ]
    print_menu(
        "📜 Select Protocol",
        [f"{Colors.GREEN}[{key}]{Colors.ENDC} {name}" for key, name in options],
        color=Colors.CYAN,
        min_width=44,
    )

    type_to_choice = {
        "tcp": "1",
        "tls": "2",
        "ws": "3",
        "wss": "4",
        "kcp": "5",
        "quic": "6",
        "httpsmimicry": "7",
        "httpmimicry": "8",
        "reality": "9",
    }
    default_choice = "1"
    if isinstance(defaults, dict):
        default_choice = type_to_choice.get(str(defaults.get("type", "")).strip().lower(), "1")

    while True:
        choice = input_default(f"\n{Colors.BOLD}Enter choice [1-9]{Colors.ENDC}", default_choice).strip()
        if choice in {str(i) for i in range(1, 10)}:
            break
        print_error("Invalid choice. Pick a number between 1 and 9.")

    config = {
        "port": "443",
        "path": "/tunnel",
        "network_mtu": 0,
        "mimicry_preset_region": "mixed",
        "mimicry_transport_mode": "websocket",
        "pool_size": 3,
        "cert": "",
        "key": "",
        "psk": "",
        "sni": "",
        "insecure_skip_verify": False,
        "dest": "",
        "server_names": [],
        "short_id": "",
        "private_key": "",
        "public_key": "",
        "generated_private_key": "",
        "reality_key_generated": False,
    }

    if isinstance(defaults, dict):
        for k, v in defaults.items():
            config[k] = v

    if role == "server":
        config["psk"] = input_default(
            "PSK (shared secret, leave empty to disable)",
            config.get("psk") or generate_uuid(),
        )
    else:
        while True:
            config["psk"] = input_default(
                "PSK (must match server, leave empty if disabled on server)",
                config.get("psk", ""),
            ).strip()
            if config["psk"]:
                break
            confirm_empty = input_default(
                "Client PSK is empty. Continue only if server PSK is disabled (y/N)", "n"
            ).strip().lower()
            if confirm_empty in {"y", "yes"}:
                break
        try:
            default_pool_size = int(config.get("pool_size", 3))
        except (TypeError, ValueError):
            default_pool_size = 3
        while True:
            pool_size = prompt_int("Connection Pool Size", default_pool_size)
            if pool_size >= 1:
                config["pool_size"] = pool_size
                break
            print_error("Connection Pool Size must be at least 1.")

    if choice == "1":
        config["type"] = "tcp"
        config["port"] = input_default("Port", config.get("port", 8080))

    elif choice == "2":
        config["type"] = "tls"
        config["port"] = input_default("Port", config.get("port", 443))
        if role == "server":
            keep_current = input_default("Keep current certificate files? (Y/n)", "y").strip().lower()
            if keep_current in {"y", "yes"} and config.get("cert") and config.get("key"):
                pass
            else:
                config["cert"], config["key"] = ask_cert_options()
        else:
            config["sni"], config["insecure_skip_verify"] = prompt_client_tls_settings(
                server_addr or config.get("server_addr", ""),
                default_sni=config.get("sni", ""),
                default_skip_verify=bool(config.get("insecure_skip_verify", True)),
            )

    elif choice == "3":
        config["type"] = "ws"
        config["port"] = input_default("Port", config.get("port", 80))
        config["path"] = normalize_path(input_default("Path", config.get("path", "/ws")), "/ws")

    elif choice == "4":
        config["type"] = "wss"
        config["port"] = input_default("Port", config.get("port", 443))
        config["path"] = normalize_path(input_default("Path", config.get("path", "/ws")), "/ws")
        if role == "server":
            keep_current = input_default("Keep current certificate files? (Y/n)", "y").strip().lower()
            if keep_current in {"y", "yes"} and config.get("cert") and config.get("key"):
                pass
            else:
                config["cert"], config["key"] = ask_cert_options()
        else:
            config["sni"], config["insecure_skip_verify"] = prompt_client_tls_settings(
                server_addr or config.get("server_addr", ""),
                default_sni=config.get("sni", ""),
                default_skip_verify=bool(config.get("insecure_skip_verify", True)),
            )

    elif choice == "5":
        config["type"] = "kcp"
        config["port"] = input_default("Port", config.get("port", 4000))

    elif choice == "6":
        config["type"] = "quic"
        config["port"] = input_default("Port", config.get("port", 443))
        if role == "server":
            keep_current = input_default("Keep current certificate files? (Y/n)", "y").strip().lower()
            if keep_current in {"y", "yes"} and config.get("cert") and config.get("key"):
                pass
            else:
                config["cert"], config["key"] = ask_cert_options()
        else:
            config["sni"], config["insecure_skip_verify"] = prompt_client_tls_settings(
                server_addr or config.get("server_addr", ""),
                default_sni=config.get("sni", ""),
                default_skip_verify=bool(config.get("insecure_skip_verify", True)),
            )

    elif choice == "7":
        config["type"] = "httpsmimicry"
        config["port"] = input_default("Port", config.get("port", 443))
        config["path"] = normalize_path(
            input_default("Mimic Path", config.get("path", "/api/v1/upload")), "/api/v1/upload"
        )
        config["mimicry_preset_region"] = "mixed"
        config["mimicry_transport_mode"] = prompt_mimicry_transport_mode(
            config.get("mimicry_transport_mode", "websocket")
        )
        if role == "server":
            keep_current = input_default("Keep current certificate files? (Y/n)", "y").strip().lower()
            if keep_current in {"y", "yes"} and config.get("cert") and config.get("key"):
                pass
            else:
                config["cert"], config["key"] = ask_cert_options()
        else:
            config["sni"], config["insecure_skip_verify"] = prompt_client_tls_settings(
                server_addr or config.get("server_addr", ""),
                default_sni=config.get("sni", ""),
                default_skip_verify=bool(config.get("insecure_skip_verify", True)),
            )

    elif choice == "8":
        config["type"] = "httpmimicry"
        config["port"] = input_default("Port", config.get("port", 80))
        config["path"] = normalize_path(
            input_default("Mimic Path", config.get("path", "/api/v1/upload")), "/api/v1/upload"
        )
        config["mimicry_preset_region"] = "mixed"
        config["mimicry_transport_mode"] = prompt_mimicry_transport_mode(
            config.get("mimicry_transport_mode", "websocket")
        )
        config["sni"] = ""
        config["insecure_skip_verify"] = False

    elif choice == "9":
        config["type"] = "reality"
        config["port"] = input_default("Port", config.get("port", 443))
        existing_names = config.get("server_names", [])
        config["server_names"] = parse_csv(
            input_default(
                "Server Names (comma separated)",
                ",".join(existing_names) if existing_names else "www.microsoft.com,microsoft.com",
            )
        )
        config["short_id"] = input_default(
            "Short ID (hex, min 8 chars)",
            config.get("short_id") or random_hex(8),
        ).lower()
        if role == "server":
            config["dest"] = input_default(
                "Dest (real target site:port)", config.get("dest", "www.microsoft.com:443")
            )
            key = input_default(
                "Private Key (x25519, 64 hex chars) [leave empty to auto-generate]",
                config.get("private_key", ""),
            ).strip().lower()
            if key:
                config["private_key"] = key
                derived = derive_reality_public_key(key)
                if derived:
                    config["public_key"] = derived
            else:
                (
                    config["private_key"],
                    config["public_key"],
                    config["reality_key_generated"],
                ) = prompt_reality_private_key()
        else:
            key = input_default(
                "Server Public Key (x25519, 64 hex chars) [leave empty to auto-generate pair]",
                config.get("public_key", ""),
            ).strip().lower()
            if key:
                config["public_key"] = key
            else:
                (
                    config["public_key"],
                    config["generated_private_key"],
                    config["reality_key_generated"],
                ) = prompt_reality_public_key()

    config["network_mtu"] = prompt_network_mtu(config.get("network_mtu", 0))

    return config


PROFILE_PRESETS = [
    "high-load",
    "performance",
    "latency",
    "balanced",
    "aggressive",
    "cpu-efficient",
    "gaming",
]

OBFUSCATION_PRESETS = [
    {
        "key": "speed",
        "label": "Speed",
        "enabled": False,
        "min_padding": 8,
        "max_padding": 64,
        "min_delay_ms": 0,
        "max_delay_ms": 0,
        "burst_chance": 0,
    },
    {
        "key": "maximum-stealth",
        "label": "Maximum Stealth",
        "enabled": True,
        "min_padding": 16,
        "max_padding": 128,
        "min_delay_ms": 8,
        "max_delay_ms": 60,
        "burst_chance": 12,
    },
    {
        "key": "balanced",
        "label": "Balanced",
        "enabled": True,
        "min_padding": 8,
        "max_padding": 96,
        "min_delay_ms": 2,
        "max_delay_ms": 20,
        "burst_chance": 5,
    },
    {
        "key": "performance",
        "label": "Performance",
        "enabled": True,
        "min_padding": 8,
        "max_padding": 72,
        "min_delay_ms": 0,
        "max_delay_ms": 8,
        "burst_chance": 2,
    },
    {
        "key": "light",
        "label": "Light",
        "enabled": True,
        "min_padding": 8,
        "max_padding": 64,
        "min_delay_ms": 0,
        "max_delay_ms": 0,
        "burst_chance": 0,
    },
    {
        "key": "gaming-voip",
        "label": "Gaming/VoIP",
        "enabled": False,
        "min_padding": 8,
        "max_padding": 64,
        "min_delay_ms": 0,
        "max_delay_ms": 0,
        "burst_chance": 0,
    },
]


def yaml_scalar(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps("" if value is None else str(value))


def parse_yaml_scalar(raw):
    value = (raw or "").strip()
    if value == "":
        return ""
    if value in {"true", "false"}:
        return value == "true"
    if re.fullmatch(r"-?\d+", value):
        try:
            return int(value)
        except ValueError:
            pass
    if re.fullmatch(r"-?\d+\.\d+", value):
        try:
            return float(value)
        except ValueError:
            pass
    if (
        (value.startswith('"') and value.endswith('"'))
        or (value.startswith("[") and value.endswith("]"))
        or value in {"null", "[]", "{}"}
    ):
        try:
            return json.loads(value)
        except Exception:
            pass
    return value


def parse_simple_yaml(text):
    lines = text.splitlines()
    root = {}
    stack = [(-1, root)]

    def strip_inline_comment(raw_line):
        in_quotes = False
        escaped = False
        out = []
        for ch in raw_line:
            if escaped:
                out.append(ch)
                escaped = False
                continue
            if ch == "\\":
                out.append(ch)
                escaped = True
                continue
            if ch == '"':
                in_quotes = not in_quotes
                out.append(ch)
                continue
            if ch == "#" and not in_quotes:
                break
            out.append(ch)
        return "".join(out).rstrip()

    def next_nonempty(idx):
        for j in range(idx + 1, len(lines)):
            nxt = strip_inline_comment(lines[j]).strip()
            if not nxt or nxt.startswith("#"):
                continue
            return strip_inline_comment(lines[j])
        return None

    for i, raw in enumerate(lines):
        raw = strip_inline_comment(raw)
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        content = raw.strip()

        while len(stack) > 1 and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]

        if content.startswith("- "):
            if not isinstance(parent, list):
                continue
            item_content = content[2:].strip()
            if ":" in item_content:
                key, _, val = item_content.partition(":")
                key = key.strip()
                val = val.strip()
                item = {}
                if val == "":
                    item[key] = {}
                else:
                    item[key] = parse_yaml_scalar(val)
                parent.append(item)
                stack.append((indent, item))
                if val == "":
                    stack.append((indent + 1, item[key]))
            else:
                parent.append(parse_yaml_scalar(item_content))
            continue

        key, sep, val = content.partition(":")
        if sep == "":
            continue
        key = key.strip()
        val = val.strip()
        if not isinstance(parent, dict):
            continue

        if val == "":
            nxt = next_nonempty(i)
            if nxt is not None:
                nxt_indent = len(nxt) - len(nxt.lstrip(" "))
                nxt_content = nxt.strip()
                if nxt_indent > indent and nxt_content.startswith("- "):
                    node = []
                else:
                    node = {}
            else:
                node = {}
            parent[key] = node
            stack.append((indent, node))
        else:
            parent[key] = parse_yaml_scalar(val)

    return root


def parse_port_from_address(address, default_port):
    raw = str(address or "").strip()
    m = re.search(r":(\d+)$", raw)
    if not m:
        return int(default_port)
    try:
        return int(m.group(1))
    except ValueError:
        return int(default_port)


def parse_host_from_address(address, default_host):
    raw = str(address or "").strip()
    m = re.search(r"^(.*):\d+$", raw)
    if not m:
        return default_host
    host = m.group(1).strip()
    if host in {"", "0.0.0.0"}:
        return default_host
    return host


def deep_copy(value):
    return json.loads(json.dumps(value))


def load_instance_runtime_settings(role, instance):
    config_path = os.path.join(CONFIG_DIR, build_config_filename(role, instance))
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config not found: {config_path}")

    with open(config_path, "r") as f:
        parsed = parse_simple_yaml(f.read())

    mode_expected = "server" if role == "server" else "client"
    mode = str(parsed.get("mode", "")).strip().lower()
    if mode and mode != mode_expected:
        raise ValueError(
            f"Config mode mismatch: expected '{mode_expected}' but got '{mode}'"
        )

    profile = str(parsed.get("profile", "balanced"))
    tunnel_mode = str(parsed.get("tunnel_mode", "reverse")).strip().lower() or "reverse"
    security = parsed.get("security", {}) if isinstance(parsed.get("security"), dict) else {}
    psk = str(security.get("psk", ""))
    license_id = str(parsed.get("license", ""))
    network_cfg = parsed.get("network", {}) if isinstance(parsed.get("network"), dict) else {}
    network_mtu = normalize_network_mtu(network_cfg.get("mtu", 0), 0)
    http_mimicry_cfg = (
        parsed.get("http_mimicry", {}) if isinstance(parsed.get("http_mimicry"), dict) else {}
    )
    mimicry_preset_region = "mixed"
    mimicry_transport_mode = normalize_mimicry_transport_mode(
        http_mimicry_cfg.get("transport_mode", "websocket"),
        "websocket",
    )

    if role == "server":
        listen = (
            parsed.get("server", {}).get("listen", {})
            if isinstance(parsed.get("server"), dict)
            else {}
        )
        tls_cfg = listen.get("tls", {}) if isinstance(listen.get("tls"), dict) else {}
        reality = parsed.get("reality", {}) if isinstance(parsed.get("reality"), dict) else {}
        protocol_cfg = {
            "type": str(listen.get("type", "tcp")),
            "tunnel_mode": tunnel_mode,
            "port": parse_port_from_address(listen.get("address", ":8443"), 8443),
            "path": str(listen.get("path", "/tunnel")),
            "network_mtu": network_mtu,
            "mimicry_preset_region": mimicry_preset_region,
            "mimicry_transport_mode": mimicry_transport_mode,
            "cert": str(tls_cfg.get("cert_file", "")),
            "key": str(tls_cfg.get("key_file", "")),
            "psk": psk,
            "dest": str(reality.get("dest", "www.microsoft.com:443")),
            "server_names": reality.get("server_names", []),
            "short_id": str(reality.get("short_id", "")),
            "private_key": str(reality.get("private_key", "")),
            "public_key": "",
            "generated_private_key": "",
            "reality_key_generated": False,
            "license": license_id,
            "profile": profile,
        }
        mappings = (
            parsed.get("server", {}).get("mappings", [])
            if isinstance(parsed.get("server"), dict)
            else []
        )
        if not isinstance(mappings, list):
            mappings = []
        cleaned_mappings = []
        for idx, m in enumerate(mappings, start=1):
            if not isinstance(m, dict):
                continue
            cleaned_mappings.append(
                {
                    "name": str(m.get("name", f"mapping-{idx}")),
                    "mode": str(m.get("mode", "reverse")),
                    "protocol": str(m.get("protocol", "tcp")),
                    "bind": str(m.get("bind", "0.0.0.0:2200")),
                    "target": str(m.get("target", "127.0.0.1:22")),
                }
            )
        protocol_cfg["mappings"] = cleaned_mappings
    else:
        client = parsed.get("client", {}) if isinstance(parsed.get("client"), dict) else {}
        server_ep = client.get("server", {}) if isinstance(client.get("server"), dict) else {}
        tls_cfg = server_ep.get("tls", {}) if isinstance(server_ep.get("tls"), dict) else {}
        reality = parsed.get("reality", {}) if isinstance(parsed.get("reality"), dict) else {}
        addr = str(server_ep.get("address", "127.0.0.1:8443"))
        protocol_cfg = {
            "type": str(server_ep.get("type", "tcp")),
            "tunnel_mode": tunnel_mode,
            "port": parse_port_from_address(addr, 8443),
            "server_addr": parse_host_from_address(addr, "127.0.0.1"),
            "pool_size": int(client.get("pool_size", 3) or 3),
            "path": str(server_ep.get("path", "/tunnel")),
            "network_mtu": network_mtu,
            "mimicry_preset_region": mimicry_preset_region,
            "mimicry_transport_mode": mimicry_transport_mode,
            "cert": "",
            "key": "",
            "psk": psk,
            "sni": str(tls_cfg.get("server_name", "")),
            "insecure_skip_verify": bool(tls_cfg.get("insecure_skip_verify", False)),
            "dest": "",
            "server_names": reality.get("server_names", []),
            "short_id": str(reality.get("short_id", "")),
            "private_key": "",
            "public_key": str(reality.get("public_key", "")),
            "generated_private_key": "",
            "reality_key_generated": False,
            "license": license_id,
            "profile": profile,
        }
        mappings = client.get("mappings", [])
        if not isinstance(mappings, list):
            mappings = []
        cleaned_mappings = []
        for idx, m in enumerate(mappings, start=1):
            if not isinstance(m, dict):
                continue
            cleaned_mappings.append(
                {
                    "name": str(m.get("name", f"mapping-{idx}")),
                    "mode": str(m.get("mode", "direct")),
                    "protocol": str(m.get("protocol", "tcp")),
                    "bind": str(m.get("bind", "0.0.0.0:2200")),
                    "target": str(m.get("target", "127.0.0.1:22")),
                }
            )
        protocol_cfg["mappings"] = cleaned_mappings

    tuning = deep_copy(base_tuning(role))
    for section in ["smux", "tcp", "udp", "kcp", "quic", "reconnect"]:
        incoming = parsed.get(section, {})
        if not isinstance(incoming, dict):
            continue
        for k, v in incoming.items():
            tuning[section][k] = v

    obfuscation_default = select_obfuscation_profile_by_key("speed")
    incoming_obf = parsed.get("obfuscation", {})
    if isinstance(incoming_obf, dict):
        for k in obfuscation_default.keys():
            if k in incoming_obf:
                obfuscation_default[k] = incoming_obf[k]

    return {
        "config_path": config_path,
        "protocol_config": protocol_cfg,
        "tuning": tuning,
        "obfuscation_cfg": obfuscation_default,
    }


def prompt_int(prompt, default):
    while True:
        value = input_default(prompt, default)
        try:
            return int(value)
        except ValueError:
            print_error("Please enter a valid integer.")


def prompt_float(prompt, default):
    while True:
        value = input_default(prompt, default)
        try:
            return float(value)
        except ValueError:
            print_error("Please enter a valid number.")


def prompt_typed_value(prompt, default):
    if isinstance(default, bool):
        raw = input_default(prompt, "true" if default else "false")
        return parse_bool(raw, default)
    if isinstance(default, int):
        return prompt_int(prompt, default)
    if isinstance(default, float):
        return prompt_float(prompt, default)
    return input_default(prompt, default)


def prompt_instance_name(role):
    role_label = role_display(role)
    while True:
        raw = input_default(
            f"{role_label} instance name (default or custom)",
            "default",
        )
        try:
            instance = normalize_instance_name(raw)
        except ValueError as exc:
            print_error(str(exc))
            continue

        service_name = build_service_name(role, instance)
        if service_exists(service_name):
            overwrite = input_default(
                f"{service_name}.service already exists. Overwrite? (y/N)",
                "n",
            ).strip().lower()
            if overwrite not in {"y", "yes"}:
                continue
        return instance


def select_config_profile(default_profile="balanced"):
    menu_lines = []
    for index, profile in enumerate(PROFILE_PRESETS, start=1):
        suffix = " (current)" if profile == default_profile else ""
        menu_lines.append(f"{index}. {profile}{suffix}")
    print_menu("🎛️ Config Profile Preset", menu_lines, color=Colors.CYAN, min_width=44)
    while True:
        default_index = 1
        if default_profile in PROFILE_PRESETS:
            default_index = PROFILE_PRESETS.index(default_profile) + 1
        choice = input_default(f"Select profile [1-{len(PROFILE_PRESETS)}]", default_index).strip()
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(PROFILE_PRESETS):
                return PROFILE_PRESETS[idx - 1]
        print_error("Invalid choice.")


def select_deployment_mode():
    print_menu(
        "🚀 Deployment Mode",
        [
            "1. Default Optimized (recommended)",
            "2. Advanced (customize smux/tcp/udp/kcp/quic/reconnect)",
        ],
        color=Colors.CYAN,
        min_width=56,
    )
    while True:
        choice = input("Select mode [1/2]: ").strip()
        if choice == "1":
            return "default"
        if choice == "2":
            return "advanced"
        print_error("Invalid choice.")


def select_obfuscation_profile_by_key(key):
    for preset in OBFUSCATION_PRESETS:
        if preset["key"] == key:
            return {
                "enabled": preset["enabled"],
                "min_padding": preset["min_padding"],
                "max_padding": preset["max_padding"],
                "min_delay_ms": preset["min_delay_ms"],
                "max_delay_ms": preset["max_delay_ms"],
                "burst_chance": preset["burst_chance"],
                # Legacy fields for backward compatibility with old binaries.
                "max_timing_ms": preset["max_delay_ms"],
                "min_chunk": 0,
                "max_chunk": 0,
                "burst_enabled": False,
                "burst_interval": "5s",
                "burst_count": 0,
            }
    return {
        "enabled": False,
        "min_padding": 8,
        "max_padding": 64,
        "min_delay_ms": 0,
        "max_delay_ms": 0,
        "burst_chance": 0,
        "max_timing_ms": 0,
        "min_chunk": 0,
        "max_chunk": 0,
        "burst_enabled": False,
        "burst_interval": "5s",
        "burst_count": 0,
    }


def match_obfuscation_preset_key(current):
    if not isinstance(current, dict):
        return "speed"
    target = {
        "enabled": bool(current.get("enabled", False)),
        "min_padding": int(current.get("min_padding", 8)),
        "max_padding": int(current.get("max_padding", 64)),
        "min_delay_ms": int(current.get("min_delay_ms", 0)),
        "max_delay_ms": int(current.get("max_delay_ms", 0)),
        "burst_chance": int(current.get("burst_chance", 0)),
    }
    for preset in OBFUSCATION_PRESETS:
        if (
            target["enabled"] == preset["enabled"]
            and target["min_padding"] == preset["min_padding"]
            and target["max_padding"] == preset["max_padding"]
            and target["min_delay_ms"] == preset["min_delay_ms"]
            and target["max_delay_ms"] == preset["max_delay_ms"]
            and target["burst_chance"] == preset["burst_chance"]
        ):
            return preset["key"]
    return "speed"


def select_obfuscation_profile(default_key="speed"):
    default_index = 1
    for idx, preset in enumerate(OBFUSCATION_PRESETS, start=1):
        if preset["key"] == default_key:
            default_index = idx
            break
    menu_lines = []
    for index, preset in enumerate(OBFUSCATION_PRESETS, start=1):
        current_suffix = " (current)" if index == default_index else ""
        if not preset["enabled"]:
            suffix = " (Recommended for speed)" if preset["key"] == "speed" else ""
            menu_lines.append(
                f"{index}. {preset['label']:<16} | enabled=false{suffix}{current_suffix}"
            )
            continue
        menu_lines.append(
            f"{index}. {preset['label']:<16} | enabled=true  "
            f"padding={preset['min_padding']}-{preset['max_padding']}  "
            f"delay={preset['min_delay_ms']}-{preset['max_delay_ms']}ms  "
            f"burst_chance={preset['burst_chance']}%{current_suffix}"
        )
    print_menu("🕶️ Obfuscation Profile", menu_lines, color=Colors.CYAN, min_width=68)
    while True:
        choice = input_default(f"Select profile [1-{len(OBFUSCATION_PRESETS)}]", default_index).strip()
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(OBFUSCATION_PRESETS):
                selected = OBFUSCATION_PRESETS[idx - 1]
                return select_obfuscation_profile_by_key(selected["key"])
        print_error("Invalid choice.")


def base_tuning(role):
    smux_values = {
        "version": 2,
        "keepalive_enabled": True,
        "keepalive_every": "5s",
        "keepalive_timeout": "15s",
        "max_frame_size": 32768,
        # Symmetric larger buffers to avoid one-way throughput collapse on higher RTT links.
        "max_receive_buffer": 16777216,
        "max_stream_buffer": 16777216,
    }
    return {
        "smux": smux_values,
        "tcp": {
            "no_delay": True,
            "keepalive": "15s",
            "read_buffer": 8388608,
            "write_buffer": 8388608,
            "conn_limit": 5000,
            "copy_buffer": 65536,
            "auto_tune": True,
        },
        "udp": {
            "read_buffer": 8388608,
            "write_buffer": 8388608,
            "max_datagram_size": 65507,
            "session_idle_timeout": "2m",
        },
        "kcp": {
            "data_shards": 10,
            "parity_shards": 3,
            "no_delay": 1,
            "interval": 20,
            "resend": 2,
            "no_congestion": 1,
            "mtu": 1200,
            "send_window": 512,
            "recv_window": 512,
        },
        "quic": {
            "alpn": "nodelay-quic-v1",
            "handshake_timeout": "10s",
            "max_idle_timeout": "60s",
            "keepalive_period": "15s",
        },
        "reconnect": {
            "min_delay": "500ms",
            "max_delay": "15s",
            "factor": 1.8,
            "jitter": True,
        },
    }


def configure_tuning(role, deployment_mode):
    tuning = json.loads(json.dumps(base_tuning(role)))
    if deployment_mode != "advanced":
        return tuning

    print_header("⚙️ Advanced Tuning")
    for section in ["smux", "tcp", "udp", "kcp", "quic", "reconnect"]:
        edit = input_default(f"Edit {section} settings? (y/N)", "n").strip().lower()
        if edit not in {"y", "yes"}:
            continue
        print(f"\n{Colors.CYAN}{section.upper()} settings{Colors.ENDC}")
        for key, default in tuning[section].items():
            tuning[section][key] = prompt_typed_value(f"{section}.{key}", default)
    return tuning


def render_mappings_lines(mappings):
    if not mappings:
        return ["    []"]
    lines = []
    for item in mappings:
        lines.append(f"    - name: {yaml_scalar(item['name'])}")
        lines.append(f"      mode: {yaml_scalar(item['mode'])}")
        lines.append(f"      protocol: {yaml_scalar(item['protocol'])}")
        lines.append(f"      bind: {yaml_scalar(item['bind'])}")
        lines.append(f"      target: {yaml_scalar(item['target'])}")
    return lines


def resolve_http_mimicry_path(protocol_config):
    if protocol_config["type"] in {"httpmimicry", "httpsmimicry"}:
        return normalize_path(protocol_config.get("path", "/api/v1/upload"), "/api/v1/upload")
    return "/api/v1/upload"


def build_http_mimicry_profiles(primary_path, preset_region="mixed"):
    primary_path = normalize_path(primary_path, "/api/v1/upload")
    preset_region = normalize_mimicry_preset_region(preset_region, "mixed")

    combined_profiles = {
        "zoomg_articles": {
            "path": primary_path,
            "browser": "chrome",
            "fake_host": "www.zoomg.ir",
            "cookie_enabled": True,
            "chunked_encoding": False,
            "custom_headers": {
                "X-Requested-With": "XMLHttpRequest",
                "Referer": "https://www.zoomg.ir/",
                "Cache-Control": "max-age=0",
            },
        },
        "virgool_read": {
            "path": "/",
            "browser": "chrome",
            "fake_host": "virgool.io",
            "cookie_enabled": True,
            "chunked_encoding": False,
            "custom_headers": {
                "Referer": "https://virgool.io/",
                "Sec-Fetch-Site": "same-origin",
                "Pragma": "no-cache",
            },
        },
        "hamyarwp_blog": {
            "path": "/blog/",
            "browser": "firefox",
            "fake_host": "hamyarwp.com",
            "cookie_enabled": True,
            "chunked_encoding": False,
            "custom_headers": {
                "Referer": "https://hamyarwp.com/",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Connection": "keep-alive",
            },
        },
        "rasaneh3_feed": {
            "path": "/",
            "browser": "chrome",
            "fake_host": "www.rasanetv.com",
            "cookie_enabled": True,
            "chunked_encoding": False,
            "custom_headers": {
                "Referer": "https://www.rasanetv.com/",
                "Sec-Fetch-Site": "same-origin",
                "Cache-Control": "no-cache",
            },
        },
        "mizbanfa_docs": {
            "path": "/blog/",
            "browser": "edge",
            "fake_host": "mizbanfa.net",
            "cookie_enabled": True,
            "chunked_encoding": False,
            "custom_headers": {
                "Referer": "https://mizbanfa.net/",
                "Sec-Fetch-Site": "same-origin",
                "Pragma": "no-cache",
            },
        },
        "f_droid_packages": {
            "path": "/packages/",
            "browser": "firefox",
            "fake_host": "f-droid.org",
            "cookie_enabled": True,
            "chunked_encoding": False,
            "custom_headers": {
                "Referer": "https://f-droid.org/",
                "Sec-Fetch-Site": "same-origin",
                "Cache-Control": "max-age=0",
            },
        },
        "archwiki_page": {
            "path": "/title/Main_page",
            "browser": "edge",
            "fake_host": "wiki.archlinux.org",
            "cookie_enabled": True,
            "chunked_encoding": False,
            "custom_headers": {
                "Referer": "https://wiki.archlinux.org/",
                "Sec-Fetch-Site": "same-origin",
                "Pragma": "no-cache",
            },
        },
        "mdn_docs": {
            "path": "/en-US/docs/Web",
            "browser": "chrome",
            "fake_host": "developer.mozilla.org",
            "cookie_enabled": True,
            "chunked_encoding": False,
            "custom_headers": {
                "Referer": "https://developer.mozilla.org/",
                "Sec-Fetch-Site": "none",
                "Pragma": "no-cache",
            },
        },
        "linode_docs": {
            "path": "/docs/",
            "browser": "firefox",
            "fake_host": "www.linode.com",
            "cookie_enabled": True,
            "chunked_encoding": False,
            "custom_headers": {
                "Referer": "https://www.linode.com/",
                "Sec-Fetch-Site": "none",
                "Cache-Control": "max-age=0",
            },
        },
        "gnu_manuals": {
            "path": "/software/",
            "browser": "chrome",
            "fake_host": "www.gnu.org",
            "cookie_enabled": True,
            "chunked_encoding": False,
            "custom_headers": {
                "Referer": "https://www.gnu.org/",
                "Sec-Fetch-Site": "same-origin",
                "Connection": "keep-alive",
            },
        },
    }

    return combined_profiles


def render_http_mimicry_lines(protocol_config, http_path):
    enabled = protocol_config["type"] in {"httpmimicry", "httpsmimicry"}
    preset_region = "mixed"
    mimicry_transport_mode = normalize_mimicry_transport_mode(
        protocol_config.get("mimicry_transport_mode", "websocket"),
        "websocket",
    )
    profiles = build_http_mimicry_profiles(http_path, preset_region)
    primary_profile = next(iter(profiles.values()))
    lines = [
        "http_mimicry:",
        f"  enabled: {yaml_scalar(enabled)}",
        f"  preset_region: {yaml_scalar(preset_region)}",
        f"  transport_mode: {yaml_scalar(mimicry_transport_mode)}",
        f"  path: {yaml_scalar(http_path)}",
        f"  browser: {yaml_scalar(primary_profile['browser'])}",
        f"  fake_host: {yaml_scalar(primary_profile['fake_host'])}",
        f"  cookie_enabled: {yaml_scalar(primary_profile['cookie_enabled'])}",
        f"  chunked_encoding: {yaml_scalar(primary_profile['chunked_encoding'])}",
        "  custom_headers:",
    ]
    for hk, hv in primary_profile["custom_headers"].items():
        lines.append(f"    {hk}: {yaml_scalar(hv)}")
    lines.append("  profiles:")
    for name, profile in profiles.items():
        lines.append(f"    {name}:")
        lines.append(f"      path: {yaml_scalar(profile['path'])}")
        lines.append(f"      browser: {yaml_scalar(profile['browser'])}")
        lines.append(f"      fake_host: {yaml_scalar(profile['fake_host'])}")
        lines.append(f"      cookie_enabled: {yaml_scalar(profile['cookie_enabled'])}")
        lines.append(f"      chunked_encoding: {yaml_scalar(profile['chunked_encoding'])}")
        lines.append("      custom_headers:")
        for hk, hv in profile["custom_headers"].items():
            lines.append(f"        {hk}: {yaml_scalar(hv)}")
    return lines


def resolve_ws_url(protocol_config, address, path):
    if protocol_config["type"] == "ws":
        return f"ws://{address}{path}"
    if protocol_config["type"] == "wss":
        return f"wss://{address}{path}"
    return ""


def build_server_config_text(protocol_config, tuning, obfuscation_cfg):
    if not os.path.exists(CONFIG_DIR):
        os.makedirs(CONFIG_DIR)

    path = normalize_path(protocol_config.get("path", "/tunnel"), "/tunnel")
    http_path = resolve_http_mimicry_path(protocol_config)
    network_mtu = normalize_network_mtu(protocol_config.get("network_mtu", 0), 0)
    reality_enabled = protocol_config["type"] == "reality"
    reality_dest = protocol_config.get("dest", "www.microsoft.com:443") if reality_enabled else "www.microsoft.com:443"
    reality_server_names = protocol_config.get("server_names", []) if reality_enabled else []
    reality_short_id = protocol_config.get("short_id", "") if reality_enabled else ""
    reality_private_key = protocol_config.get("private_key", "") if reality_enabled else ""
    lines = [
        "mode: server",
        f"tunnel_mode: {yaml_scalar(protocol_config.get('tunnel_mode', 'reverse'))}",
        f"profile: {yaml_scalar(protocol_config.get('profile', 'balanced'))}",
        "",
        "server:",
        "  listen:",
        f"    type: {yaml_scalar(protocol_config['type'])}",
        f"    address: {yaml_scalar(':' + str(protocol_config['port']))}",
        f"    path: {yaml_scalar(path)}",
        "    tls:",
        f"      cert_file: {yaml_scalar(protocol_config.get('cert', ''))}",
        f"      key_file: {yaml_scalar(protocol_config.get('key', ''))}",
        '      ca_file: ""',
        "      require_client_cert: false",
    ]
    if str(protocol_config.get("tunnel_mode", "reverse")).strip().lower() == "direct":
        lines.append("  mappings: []")
    else:
        mappings = protocol_config.get("mappings", [])
        if mappings:
            lines.append("  mappings:")
            lines.extend(render_mappings_lines(mappings))
        else:
            lines.append("  mappings: []")
    lines.extend(
        [
            "",
            "smux:",
            f"  version: {yaml_scalar(tuning['smux']['version'])}",
            f"  keepalive_enabled: {yaml_scalar(tuning['smux']['keepalive_enabled'])}",
            f"  keepalive_every: {yaml_scalar(tuning['smux']['keepalive_every'])}",
            f"  keepalive_timeout: {yaml_scalar(tuning['smux']['keepalive_timeout'])}",
            f"  max_frame_size: {yaml_scalar(tuning['smux']['max_frame_size'])}",
            f"  max_receive_buffer: {yaml_scalar(tuning['smux']['max_receive_buffer'])}",
            f"  max_stream_buffer: {yaml_scalar(tuning['smux']['max_stream_buffer'])}",
            "",
            "tcp:",
            f"  no_delay: {yaml_scalar(tuning['tcp']['no_delay'])}",
            f"  keepalive: {yaml_scalar(tuning['tcp']['keepalive'])}",
            f"  read_buffer: {yaml_scalar(tuning['tcp']['read_buffer'])}",
            f"  write_buffer: {yaml_scalar(tuning['tcp']['write_buffer'])}",
            f"  conn_limit: {yaml_scalar(tuning['tcp']['conn_limit'])}",
            f"  copy_buffer: {yaml_scalar(tuning['tcp']['copy_buffer'])}",
            f"  auto_tune: {yaml_scalar(tuning['tcp']['auto_tune'])}",
            "",
            "udp:",
            f"  read_buffer: {yaml_scalar(tuning['udp']['read_buffer'])}",
            f"  write_buffer: {yaml_scalar(tuning['udp']['write_buffer'])}",
            f"  max_datagram_size: {yaml_scalar(tuning['udp']['max_datagram_size'])}",
            f"  session_idle_timeout: {yaml_scalar(tuning['udp']['session_idle_timeout'])}",
            "",
            "kcp:",
            f"  data_shards: {yaml_scalar(tuning['kcp']['data_shards'])}",
            f"  parity_shards: {yaml_scalar(tuning['kcp']['parity_shards'])}",
            f"  no_delay: {yaml_scalar(tuning['kcp']['no_delay'])}",
            f"  interval: {yaml_scalar(tuning['kcp']['interval'])}",
            f"  resend: {yaml_scalar(tuning['kcp']['resend'])}",
            f"  no_congestion: {yaml_scalar(tuning['kcp']['no_congestion'])}",
            f"  mtu: {yaml_scalar(tuning['kcp']['mtu'])}",
            f"  send_window: {yaml_scalar(tuning['kcp']['send_window'])}",
            f"  recv_window: {yaml_scalar(tuning['kcp']['recv_window'])}",
            "",
            "quic:",
            f"  alpn: {yaml_scalar(tuning['quic']['alpn'])}",
            f"  handshake_timeout: {yaml_scalar(tuning['quic']['handshake_timeout'])}",
            f"  max_idle_timeout: {yaml_scalar(tuning['quic']['max_idle_timeout'])}",
            f"  keepalive_period: {yaml_scalar(tuning['quic']['keepalive_period'])}",
            "",
            "network:",
            f"  mtu: {yaml_scalar(network_mtu)}",
            "",
            "security:",
            '  token: ""',
            f"  psk: {yaml_scalar(protocol_config.get('psk', ''))}",
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
            "reconnect:",
            f"  min_delay: {yaml_scalar(tuning['reconnect']['min_delay'])}",
            f"  max_delay: {yaml_scalar(tuning['reconnect']['max_delay'])}",
            f"  factor: {yaml_scalar(tuning['reconnect']['factor'])}",
            f"  jitter: {yaml_scalar(tuning['reconnect']['jitter'])}",
            "",
            "obfuscation:",
            f"  enabled: {yaml_scalar(obfuscation_cfg['enabled'])}",
            f"  min_padding: {yaml_scalar(obfuscation_cfg['min_padding'])}",
            f"  max_padding: {yaml_scalar(obfuscation_cfg['max_padding'])}",
            f"  min_delay_ms: {yaml_scalar(obfuscation_cfg['min_delay_ms'])}",
            f"  max_delay_ms: {yaml_scalar(obfuscation_cfg['max_delay_ms'])}",
            f"  burst_chance: {yaml_scalar(obfuscation_cfg['burst_chance'])}",
            "",
        ]
    )
    lines.extend(render_http_mimicry_lines(protocol_config, http_path))
    lines.extend(
        [
            "",
            "frag:",
            "  enabled: false",
            "  split_pos: 0",
            "  fake_ttl: 0",
            "  reverse_order: false",
            "",
            "utls:",
            "  enabled: false",
            '  fingerprint: "chrome"',
            "",
            "reality:",
            f"  enabled: {yaml_scalar(reality_enabled)}",
            f"  dest: {yaml_scalar(reality_dest)}",
            f"  server_names: {json.dumps(reality_server_names)}",
            f"  short_id: {yaml_scalar(reality_short_id)}",
            f"  private_key: {yaml_scalar(reality_private_key)}",
            '  public_key: ""',
            "",
            f"license: {yaml_scalar(protocol_config.get('license', ''))}",
        ]
    )
    return "\n".join(lines) + "\n"


def build_client_config_text(protocol_config, tuning, obfuscation_cfg):
    if not os.path.exists(CONFIG_DIR):
        os.makedirs(CONFIG_DIR)

    path = normalize_path(protocol_config.get("path", "/tunnel"), "/tunnel")
    http_path = resolve_http_mimicry_path(protocol_config)
    network_mtu = normalize_network_mtu(protocol_config.get("network_mtu", 0), 0)
    server_addr = protocol_config.get("server_addr", "127.0.0.1")
    address = f"{server_addr}:{protocol_config['port']}"
    url = resolve_ws_url(protocol_config, address, path)
    tls_enabled = protocol_config["type"] in {"tls", "wss", "quic", "httpsmimicry"}
    tls_server_name = protocol_config.get("sni", "") if tls_enabled else ""
    tls_insecure_skip_verify = (
        bool(protocol_config.get("insecure_skip_verify", False))
        if tls_enabled
        else False
    )
    reality_enabled = protocol_config["type"] == "reality"
    reality_server_names = protocol_config.get("server_names", []) if reality_enabled else []
    reality_short_id = protocol_config.get("short_id", "") if reality_enabled else ""
    reality_public_key = protocol_config.get("public_key", "") if reality_enabled else ""
    try:
        pool_size = int(protocol_config.get("pool_size", 3))
    except (TypeError, ValueError):
        pool_size = 3
    if pool_size < 1:
        pool_size = 1
    lines = [
        "mode: client",
        f"tunnel_mode: {yaml_scalar(protocol_config.get('tunnel_mode', 'reverse'))}",
        f"profile: {yaml_scalar(protocol_config.get('profile', 'balanced'))}",
        "",
        "client:",
        f"  pool_size: {yaml_scalar(pool_size)}",
        "  server:",
        f"    type: {yaml_scalar(protocol_config['type'])}",
        f"    address: {yaml_scalar(address)}",
        f"    url: {yaml_scalar(url)}",
        f"    path: {yaml_scalar(path)}",
        "    tls:",
        '      cert_file: ""',
        '      key_file: ""',
        '      ca_file: ""',
        f"      server_name: {yaml_scalar(tls_server_name)}",
        f"      insecure_skip_verify: {yaml_scalar(tls_insecure_skip_verify)}",
    ]
    if str(protocol_config.get("tunnel_mode", "reverse")).strip().lower() == "direct":
        mappings = protocol_config.get("mappings", [])
        if mappings:
            lines.append("  mappings:")
            lines.extend(render_mappings_lines(mappings))
        else:
            lines.append("  mappings: []")
    else:
        lines.append("  mappings: []")
    lines.extend(
        [
        "",
        "smux:",
        f"  version: {yaml_scalar(tuning['smux']['version'])}",
        f"  keepalive_enabled: {yaml_scalar(tuning['smux']['keepalive_enabled'])}",
        f"  keepalive_every: {yaml_scalar(tuning['smux']['keepalive_every'])}",
        f"  keepalive_timeout: {yaml_scalar(tuning['smux']['keepalive_timeout'])}",
        f"  max_frame_size: {yaml_scalar(tuning['smux']['max_frame_size'])}",
        f"  max_receive_buffer: {yaml_scalar(tuning['smux']['max_receive_buffer'])}",
        f"  max_stream_buffer: {yaml_scalar(tuning['smux']['max_stream_buffer'])}",
        "",
        "tcp:",
        f"  no_delay: {yaml_scalar(tuning['tcp']['no_delay'])}",
        f"  keepalive: {yaml_scalar(tuning['tcp']['keepalive'])}",
        f"  read_buffer: {yaml_scalar(tuning['tcp']['read_buffer'])}",
        f"  write_buffer: {yaml_scalar(tuning['tcp']['write_buffer'])}",
        f"  conn_limit: {yaml_scalar(tuning['tcp']['conn_limit'])}",
        f"  copy_buffer: {yaml_scalar(tuning['tcp']['copy_buffer'])}",
        f"  auto_tune: {yaml_scalar(tuning['tcp']['auto_tune'])}",
        "",
        "udp:",
        f"  read_buffer: {yaml_scalar(tuning['udp']['read_buffer'])}",
        f"  write_buffer: {yaml_scalar(tuning['udp']['write_buffer'])}",
        f"  max_datagram_size: {yaml_scalar(tuning['udp']['max_datagram_size'])}",
        f"  session_idle_timeout: {yaml_scalar(tuning['udp']['session_idle_timeout'])}",
        "",
        "kcp:",
        f"  data_shards: {yaml_scalar(tuning['kcp']['data_shards'])}",
        f"  parity_shards: {yaml_scalar(tuning['kcp']['parity_shards'])}",
        f"  no_delay: {yaml_scalar(tuning['kcp']['no_delay'])}",
        f"  interval: {yaml_scalar(tuning['kcp']['interval'])}",
        f"  resend: {yaml_scalar(tuning['kcp']['resend'])}",
        f"  no_congestion: {yaml_scalar(tuning['kcp']['no_congestion'])}",
        f"  mtu: {yaml_scalar(tuning['kcp']['mtu'])}",
        f"  send_window: {yaml_scalar(tuning['kcp']['send_window'])}",
        f"  recv_window: {yaml_scalar(tuning['kcp']['recv_window'])}",
        "",
        "quic:",
        f"  alpn: {yaml_scalar(tuning['quic']['alpn'])}",
        f"  handshake_timeout: {yaml_scalar(tuning['quic']['handshake_timeout'])}",
        f"  max_idle_timeout: {yaml_scalar(tuning['quic']['max_idle_timeout'])}",
        f"  keepalive_period: {yaml_scalar(tuning['quic']['keepalive_period'])}",
        "",
        "network:",
        f"  mtu: {yaml_scalar(network_mtu)}",
        "",
        "security:",
        '  token: ""',
        f"  psk: {yaml_scalar(protocol_config.get('psk', ''))}",
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
        "reconnect:",
        f"  min_delay: {yaml_scalar(tuning['reconnect']['min_delay'])}",
        f"  max_delay: {yaml_scalar(tuning['reconnect']['max_delay'])}",
        f"  factor: {yaml_scalar(tuning['reconnect']['factor'])}",
        f"  jitter: {yaml_scalar(tuning['reconnect']['jitter'])}",
        "",
        "obfuscation:",
        f"  enabled: {yaml_scalar(obfuscation_cfg['enabled'])}",
        f"  min_padding: {yaml_scalar(obfuscation_cfg['min_padding'])}",
        f"  max_padding: {yaml_scalar(obfuscation_cfg['max_padding'])}",
        f"  min_delay_ms: {yaml_scalar(obfuscation_cfg['min_delay_ms'])}",
        f"  max_delay_ms: {yaml_scalar(obfuscation_cfg['max_delay_ms'])}",
        f"  burst_chance: {yaml_scalar(obfuscation_cfg['burst_chance'])}",
        "",
        ]
    )
    lines.extend(render_http_mimicry_lines(protocol_config, http_path))
    lines.extend(
        [
            "",
            "frag:",
            "  enabled: false",
            "  split_pos: 0",
            "  fake_ttl: 0",
            "  reverse_order: false",
            "",
            "utls:",
            "  enabled: true",
            '  fingerprint: "chrome"',
            "",
            "reality:",
            f"  enabled: {yaml_scalar(reality_enabled)}",
            '  dest: "www.microsoft.com:443"',
            f"  server_names: {json.dumps(reality_server_names)}",
            f"  short_id: {yaml_scalar(reality_short_id)}",
            '  private_key: ""',
            f"  public_key: {yaml_scalar(reality_public_key)}",
            "",
            f"license: {yaml_scalar(protocol_config.get('license', ''))}",
        ]
    )
    return "\n".join(lines) + "\n"


def generate_config(protocol_config, tuning, obfuscation_cfg, config_filename):
    config_path = os.path.join(CONFIG_DIR, config_filename)
    final_content = build_server_config_text(protocol_config, tuning, obfuscation_cfg)
    with open(config_path, "w") as f:
        f.write(final_content)
    print_success(f"💾 Configuration generated at {config_path}")
    return config_path


def generate_client_config(protocol_config, tuning, obfuscation_cfg, config_filename):
    config_path = os.path.join(CONFIG_DIR, config_filename)
    final_content = build_client_config_text(protocol_config, tuning, obfuscation_cfg)
    with open(config_path, "w") as f:
        f.write(final_content)
    print_success(f"💾 Client Configuration generated at {config_path}")
    return config_path


def create_service(role, instance="default"):
    profile = SERVICE_PROFILES[role]
    service_name = build_service_name(role, instance)
    service_path = service_file_path(service_name)
    config_path = os.path.join(CONFIG_DIR, build_config_filename(role, instance))
    exec_start = f"{os.path.join(INSTALL_DIR, BINARY_NAME)} {profile['mode']} -c {config_path}"
    description = profile["description"] if instance == "default" else f"{profile['description']} [{instance}]"
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

[Install]
WantedBy=multi-user.target
"""
    with open(service_path, "w") as f:
        f.write(content)

    run_command("systemctl daemon-reload")
    run_command(f"systemctl enable {service_name}")
    run_command(f"systemctl restart {service_name}")
    print_success(f"✅ Systemd service installed and started: {service_name}.service")


def stop_service_fast(service_name, grace_seconds=5.0):
    unit = f"{service_name}.service"
    quoted = shlex.quote(unit)

    # For quick shutdown, terminate the whole cgroup and do not block on systemd's full timeout.
    run_command(f"systemctl kill --signal=SIGTERM --kill-who=all {quoted}", check=False)
    run_command(f"systemctl stop --no-block {quoted}", check=False)

    deadline = time.time() + grace_seconds
    while time.time() < deadline:
        _, active_out, active_err = run_command_output(f"systemctl is-active {quoted}")
        state = (active_out or active_err or "").strip().lower()
        if state in {"inactive", "failed", "unknown"}:
            return True
        time.sleep(0.25)

    run_command(f"systemctl kill --signal=SIGKILL --kill-who=all {quoted}", check=False)
    run_command(f"systemctl stop --no-block {quoted}", check=False)
    time.sleep(0.3)
    _, active_out, active_err = run_command_output(f"systemctl is-active {quoted}")
    state = (active_out or active_err or "").strip().lower()
    return state in {"inactive", "failed", "unknown"}


def control_services(action):
    services = choose_services(allow_all=True, action_label=action)
    if not services:
        return
    action_labels = {
        "start": "Started",
        "stop": "Stopped",
        "restart": "Restarted",
    }
    for service in services:
        unit = f"{service}.service"
        role, _ = parse_service_role_instance(service)
        if action == "stop" and role == "client":
            ok = stop_service_fast(service)
        else:
            ok = run_command(f"systemctl {action} {shlex.quote(unit)}", check=False)
        if ok and action == "restart":
            active_rc, _, _ = run_command_output(f"systemctl is-active {shlex.quote(unit)}")
            ok = active_rc == 0
        if ok:
            print_success(f"{action_labels.get(action, action)} {unit}")
        else:
            print_error(f"Failed to {action} {unit}")


def show_service_logs(follow=False):
    services = choose_services(allow_all=False, action_label="logs")
    if not services:
        return
    service = services[0]
    if follow:
        print_info(f"Following logs for {service}.service (Ctrl+C to exit)...")
        try:
            run_command_stream(f"journalctl -fu {shlex.quote(service)}.service")
        except KeyboardInterrupt:
            pass
    else:
        run_command_stream(f"journalctl -u {shlex.quote(service)}.service -n 120 --no-pager")


def service_control_menu():
    while True:
        print_menu(
            "📊 Tunnel Monitor & Service Control",
            [
                "1. Show tunnel/service status",
                "2. Show recent logs",
                "3. Follow live logs",
                "4. Start service",
                "5. Stop service",
                "6. Restart service",
                "0. Back",
            ],
            color=Colors.CYAN,
            min_width=50,
        )

        choice = input("Select option: ").strip()
        if choice == "1":
            print_services_status()
            input("\nPress Enter to continue...")
        elif choice == "2":
            show_service_logs(follow=False)
            input("\nPress Enter to continue...")
        elif choice == "3":
            show_service_logs(follow=True)
            input("\nPress Enter to continue...")
        elif choice == "4":
            control_services("start")
            input("\nPress Enter to continue...")
        elif choice == "5":
            control_services("stop")
            input("\nPress Enter to continue...")
        elif choice == "6":
            control_services("restart")
            input("\nPress Enter to continue...")
        elif choice == "0":
            return
        else:
            print_error("Invalid choice.")


def restart_installed_services():
    services = installed_services()
    if not services:
        print_info("No installed services to restart.")
        return
    run_command("systemctl daemon-reload", check=False)
    restarted = 0
    failed = []
    for service in services:
        unit = f"{service}.service"
        if not run_command(f"systemctl restart {shlex.quote(unit)}", check=False):
            failed.append(service)
            continue
        active_rc, _, _ = run_command_output(f"systemctl is-active {shlex.quote(unit)}")
        if active_rc == 0:
            restarted += 1
        else:
            failed.append(service)
    if restarted:
        print_success(f"✅ Restarted {restarted} service(s).")
    if failed:
        print_error(f"❌ Failed to restart: {', '.join(f'{s}.service' for s in failed)}")


def remove_service_instance(service_name):
    role, instance = parse_service_role_instance(service_name)
    if role is None:
        print_error(f"Unsupported instance type: {service_name}.service")
        return

    config_path = os.path.join(CONFIG_DIR, build_config_filename(role, instance))
    run_command(f"systemctl stop {shlex.quote(service_name)}")
    run_command(f"systemctl disable {shlex.quote(service_name)}")
    service_path = service_file_path(service_name)
    if os.path.exists(service_path):
        os.remove(service_path)
    if os.path.exists(config_path):
        os.remove(config_path)
    run_command("systemctl daemon-reload")
    print_success(f"Removed {service_name}.service (binary kept)")
    if not os.path.exists(config_path):
        print_info(f"Removed config: {config_path}")


def configure_tuning_from_existing(tuning):
    updated = deep_copy(tuning)
    print_header("⚙️ Edit Tuning")
    for section in ["smux", "tcp", "udp", "kcp", "quic", "reconnect"]:
        edit = input_default(f"Edit {section} settings? (y/N)", "n").strip().lower()
        if edit not in {"y", "yes"}:
            continue
        print(f"\n{Colors.CYAN}{section.upper()} settings{Colors.ENDC}")
        for key, default in updated[section].items():
            updated[section][key] = prompt_typed_value(f"{section}.{key}", default)
    return updated


def edit_service_instance(service_name):
    role, instance = parse_service_role_instance(service_name)
    if role not in {"server", "client"}:
        print_error(f"Unsupported instance: {service_name}.service")
        return

    try:
        loaded = load_instance_runtime_settings(role, instance)
    except Exception as exc:
        print_error(f"Failed to load current config: {exc}")
        return

    protocol_cfg = loaded["protocol_config"]
    tuning = loaded["tuning"]
    obfuscation_cfg = loaded["obfuscation_cfg"]
    config_path = loaded["config_path"]

    while True:
        client_direct_mode = (
            role == "client"
            and str(protocol_cfg.get("tunnel_mode", "reverse")).strip().lower() == "direct"
        )
        menu_lines = [
            f"Role:        {role} ({role_display(role)})",
            f"Instance:    {instance}",
            f"Config:      {config_path}",
            f"Protocol:    {protocol_cfg.get('type')}:{protocol_cfg.get('port')}",
            f"TunnelMode:  {protocol_cfg.get('tunnel_mode', 'reverse')}",
            f"Profile:     {protocol_cfg.get('profile', 'balanced')}",
            f"Obfuscation: {'enabled' if obfuscation_cfg.get('enabled') else 'disabled'}",
        ]
        if role == "server":
            menu_lines.append(f"Mappings:    {len(protocol_cfg.get('mappings', []))}")
        else:
            menu_lines.append(
                f"Server:      {protocol_cfg.get('server_addr')}:{protocol_cfg.get('port')}"
            )
            if client_direct_mode:
                menu_lines.append(f"Mappings:    {len(protocol_cfg.get('mappings', []))}")
        menu_lines.append("")
        menu_lines.append("1. Edit protocol / listen port / transport settings")
        menu_lines.append("2. Edit profile preset")
        menu_lines.append("3. Edit obfuscation preset")
        if role == "server":
            menu_lines.extend(
                [
                    "4. Edit port mappings",
                    "5. Edit advanced tuning",
                    "6. Edit license ID",
                    "7. Save changes and restart service",
                    "0. Cancel",
                ]
            )
        elif client_direct_mode:
            menu_lines.extend(
                [
                    "4. Edit port mappings",
                    "5. Edit advanced tuning",
                    "6. Edit license ID",
                    "7. Save changes and restart service",
                    "0. Cancel",
                ]
            )
        else:
            menu_lines.extend(
                [
                    "4. Edit advanced tuning",
                    "5. Edit license ID",
                    "6. Save changes and restart service",
                    "0. Cancel",
                ]
            )
        print_menu(f"✏️ Edit Tunnel: {service_name}.service", menu_lines, color=Colors.CYAN, min_width=62)

        choice = input("Select option: ").strip()

        if choice == "1":
            if role == "client":
                current_port = protocol_cfg.get("port", 443)
                try:
                    current_port = int(current_port)
                except (TypeError, ValueError):
                    current_port = 443
                destination_host, destination_port = prompt_client_destination(
                    protocol_cfg.get("server_addr", "127.0.0.1"),
                    current_port,
                )
                protocol_cfg["server_addr"] = destination_host
                protocol_cfg["port"] = destination_port
            protocol_cfg = menu_protocol(
                role,
                server_addr=protocol_cfg.get("server_addr", ""),
                defaults=protocol_cfg,
            )
            protocol_cfg["tunnel_mode"] = loaded["protocol_config"].get("tunnel_mode", "reverse")
            if role == "server" and "mappings" in loaded["protocol_config"]:
                protocol_cfg["mappings"] = protocol_cfg.get(
                    "mappings", loaded["protocol_config"].get("mappings", [])
                )
            if role == "client" and "mappings" in loaded["protocol_config"]:
                protocol_cfg["mappings"] = protocol_cfg.get(
                    "mappings", loaded["protocol_config"].get("mappings", [])
                )
            protocol_cfg["profile"] = protocol_cfg.get("profile", loaded["protocol_config"].get("profile", "balanced"))
            protocol_cfg["license"] = protocol_cfg.get("license", loaded["protocol_config"].get("license", ""))
        elif choice == "2":
            protocol_cfg["profile"] = select_config_profile(
                default_profile=protocol_cfg.get("profile", "balanced")
            )
        elif choice == "3":
            default_obf_key = match_obfuscation_preset_key(obfuscation_cfg)
            obfuscation_cfg = select_obfuscation_profile(default_key=default_obf_key)
        elif choice == "4" and role == "server":
            protocol_cfg["mappings"] = prompt_server_mappings(
                existing=protocol_cfg.get("mappings", [])
            )
        elif choice == "4" and client_direct_mode:
            protocol_cfg["mappings"] = prompt_server_mappings(
                existing=protocol_cfg.get("mappings", []),
                fixed_mode="direct",
                bind_side_label="Client side",
                target_side_label="Server side",
            )
        elif (choice == "5" and role == "server") or (choice == "5" and client_direct_mode) or (choice == "4" and role == "client" and not client_direct_mode):
            tuning = configure_tuning_from_existing(tuning)
        elif (choice == "6" and role == "server") or (choice == "6" and client_direct_mode) or (choice == "5" and role == "client" and not client_direct_mode):
            protocol_cfg["license"] = prompt_license_id()
        elif (choice == "7" and role == "server") or (choice == "7" and client_direct_mode) or (choice == "6" and role == "client" and not client_direct_mode):
            config_file = build_config_filename(role, instance)
            if role == "server":
                generate_config(protocol_cfg, tuning, obfuscation_cfg, config_file)
            else:
                generate_client_config(protocol_cfg, tuning, obfuscation_cfg, config_file)
            run_command("systemctl daemon-reload", check=False)
            unit = f"{service_name}.service"
            if run_command(f"systemctl restart {shlex.quote(unit)}", check=False):
                active_rc, _, _ = run_command_output(
                    f"systemctl is-active {shlex.quote(unit)}"
                )
                if active_rc == 0:
                    print_success(f"✅ Saved and restarted {unit}")
                else:
                    print_error(f"❌ Config saved, but {unit} is not active after restart.")
            else:
                print_error(f"❌ Config saved, but failed to restart {unit}")
            return
        elif choice == "0":
            print_info("Edit cancelled.")
            return
        else:
            print_error("Invalid choice.")


def multi_tunnel_menu():
    while True:
        services = installed_services()
        print_menu(
            "🧩 Multi Tunnel Management",
            [
                f"Installed tunnel services: {len(services)}",
                "1. List tunnel instances",
                "2. Remove one instance",
                "3. Edit one instance",
                "0. Back",
            ],
            color=Colors.CYAN,
            min_width=54,
        )
        choice = input("Select option: ").strip()

        if choice == "1":
            if not services:
                print_error("No tunnel services are installed.")
            else:
                for service in services:
                    role, instance = parse_service_role_instance(service)
                    if role is None:
                        print(f"- {service}.service (legacy)")
                        continue
                    cfg = os.path.join(CONFIG_DIR, build_config_filename(role, instance))
                    print(
                        f"- {service}.service  role={role} ({role_display(role)})  "
                        f"instance={instance}  config={cfg}"
                    )
            input("\nPress Enter to continue...")
        elif choice == "2":
            role_services = [s for s in services if parse_service_role_instance(s)[0] in {"server", "client"}]
            if not role_services:
                print_error("No removable server/client instances found.")
                input("\nPress Enter to continue...")
                continue
            removal_lines = []
            for index, service in enumerate(role_services, start=1):
                role, instance = parse_service_role_instance(service)
                removal_lines.append(f"{index}. {service}.service ({role_display(role)}:{instance})")
            print_menu("Removable Instances", removal_lines, color=Colors.CYAN, min_width=56)
            raw = input(f"Select instance [1-{len(role_services)}]: ").strip()
            if not raw.isdigit() or not (1 <= int(raw) <= len(role_services)):
                print_error("Invalid choice.")
                input("\nPress Enter to continue...")
                continue
            target = role_services[int(raw) - 1]
            confirm = input_default(f"Remove {target}.service and its config? (y/N)", "n").strip().lower()
            if confirm in {"y", "yes"}:
                remove_service_instance(target)
            input("\nPress Enter to continue...")
        elif choice == "3":
            role_services = [s for s in services if parse_service_role_instance(s)[0] in {"server", "client"}]
            if not role_services:
                print_error("No editable server/client instances found.")
                input("\nPress Enter to continue...")
                continue
            editable_lines = []
            for index, service in enumerate(role_services, start=1):
                role, instance = parse_service_role_instance(service)
                editable_lines.append(f"{index}. {service}.service ({role_display(role)}:{instance})")
            print_menu("Editable Instances", editable_lines, color=Colors.CYAN, min_width=56)
            raw = input(f"Select instance [1-{len(role_services)}]: ").strip()
            if not raw.isdigit() or not (1 <= int(raw) <= len(role_services)):
                print_error("Invalid choice.")
                input("\nPress Enter to continue...")
                continue
            target = role_services[int(raw) - 1]
            edit_service_instance(target)
            input("\nPress Enter to continue...")
        elif choice == "0":
            return
        else:
            print_error("Invalid choice.")


def uninstall_everything():
    check_root()
    for service in installed_services():
        run_command(f"systemctl stop {shlex.quote(service)}")
        run_command(f"systemctl disable {shlex.quote(service)}")
        path = service_file_path(service)
        if os.path.exists(path):
            os.remove(path)

    # Cleanup known legacy names if they still exist.
    for service in [SERVER_SERVICE_NAME, CLIENT_SERVICE_NAME, LEGACY_SERVICE_NAME]:
        path = service_file_path(service)
        if os.path.exists(path):
            os.remove(path)

    run_command("systemctl daemon-reload")
    print_success("🗑️  Uninstalled services and configs (binary kept).")


def install_server_flow(
    server_location_label="Iran",
    tunnel_label="Reverse Tunnel",
    tunnel_mode="reverse",
    collect_mappings=True,
    mapping_mode=None,
    bind_side_label="This node",
    target_side_label="Remote node",
):
    print_header(f"🖥️ Server Configuration ({server_location_label})")
    print_menu(
        "Setup Context",
        [
            f"Tunnel Type: {tunnel_label}",
            f"This Node Role: server ({server_location_label})",
        ],
        color=Colors.CYAN,
        min_width=52,
    )
    instance = prompt_instance_name("server")
    cfg = menu_protocol("server")
    cfg["tunnel_mode"] = tunnel_mode
    cfg["license"] = prompt_license_id()
    cfg["profile"] = select_config_profile()
    deployment_mode = select_deployment_mode()
    tuning = configure_tuning("server", deployment_mode)
    obfuscation_cfg = select_obfuscation_profile()
    if collect_mappings:
        cfg["mappings"] = prompt_server_mappings(
            fixed_mode=mapping_mode,
            bind_side_label=bind_side_label,
            target_side_label=target_side_label,
        )
    else:
        cfg["mappings"] = []
    config_file = build_config_filename("server", instance)
    config_path = generate_config(cfg, tuning, obfuscation_cfg, config_file)
    create_service("server", instance)
    maybe_apply_linux_network_tuning()

    print_header("🎉 Server Installation Complete")
    print(f"Instance: {Colors.BOLD}{instance}{Colors.ENDC}")
    print(f"Tunnel:   {Colors.BOLD}{tunnel_label}{Colors.ENDC}")
    print(f"Location: {Colors.BOLD}{server_location_label}{Colors.ENDC}")
    print(f"Config:   {Colors.BOLD}{config_path}{Colors.ENDC}")
    print(f"Address:  {Colors.BOLD}:{cfg['port']}{Colors.ENDC}")
    psk_text = cfg["psk"] if cfg["psk"] else "(disabled)"
    print(f"PSK:      {Colors.BOLD}{psk_text}{Colors.ENDC}")
    print(f"Protocol: {Colors.BOLD}{cfg['type']}{Colors.ENDC}")
    print(f"Path MTU: {Colors.BOLD}{cfg.get('network_mtu', 0)}{Colors.ENDC}")
    print(f"Profile:  {Colors.BOLD}{cfg['profile']}{Colors.ENDC}")
    print(f"Deploy:   {Colors.BOLD}{deployment_mode}{Colors.ENDC}")
    if cfg["type"] == "reality":
        print(f"ShortID:  {Colors.BOLD}{cfg['short_id']}{Colors.ENDC}")
        print(f"Private:  {Colors.BOLD}{cfg['private_key']}{Colors.ENDC}")
        if cfg.get("public_key"):
            print(f"Public:   {Colors.BOLD}{cfg['public_key']}{Colors.ENDC}")


def install_client_flow(
    client_location_label="Kharej",
    tunnel_label="Reverse Tunnel",
    tunnel_mode="reverse",
    collect_mappings=False,
    mapping_mode=None,
    bind_side_label="This node",
    target_side_label="Remote node",
):
    print_header(f"💻 Client Configuration ({client_location_label})")
    print_menu(
        "Setup Context",
        [
            f"Tunnel Type: {tunnel_label}",
            f"This Node Role: client ({client_location_label})",
        ],
        color=Colors.CYAN,
        min_width=52,
    )
    instance = prompt_instance_name("client")
    server_addr, server_port = prompt_client_destination("127.0.0.1", 443)
    cfg = menu_protocol(
        "client",
        server_addr=server_addr,
        defaults={"server_addr": server_addr, "port": server_port},
    )
    cfg["tunnel_mode"] = tunnel_mode
    cfg["license"] = ""
    cfg["profile"] = select_config_profile()
    deployment_mode = select_deployment_mode()
    tuning = configure_tuning("client", deployment_mode)
    obfuscation_cfg = select_obfuscation_profile()
    cfg["server_addr"] = server_addr
    if collect_mappings:
        cfg["mappings"] = prompt_server_mappings(
            fixed_mode=mapping_mode,
            bind_side_label=bind_side_label,
            target_side_label=target_side_label,
        )
    else:
        cfg["mappings"] = []
    config_file = build_config_filename("client", instance)
    config_path = generate_client_config(cfg, tuning, obfuscation_cfg, config_file)
    create_service("client", instance)
    maybe_apply_linux_network_tuning()

    print_header("✅ Client Installation Complete")
    print(f"Instance:   {Colors.BOLD}{instance}{Colors.ENDC}")
    print(f"Tunnel:     {Colors.BOLD}{tunnel_label}{Colors.ENDC}")
    print(f"Location:   {Colors.BOLD}{client_location_label}{Colors.ENDC}")
    print(f"Config:     {Colors.BOLD}{config_path}{Colors.ENDC}")
    print(f"Run command: {Colors.BOLD}nodelay client -c {config_path}{Colors.ENDC}")
    print(f"Profile:    {Colors.BOLD}{cfg['profile']}{Colors.ENDC}")
    print(f"Pool Size:  {Colors.BOLD}{cfg.get('pool_size', 3)}{Colors.ENDC}")
    print(f"Path MTU:   {Colors.BOLD}{cfg.get('network_mtu', 0)}{Colors.ENDC}")
    print(f"Deploy:     {Colors.BOLD}{deployment_mode}{Colors.ENDC}")
    if cfg["type"] == "reality":
        print(f"ShortID:    {Colors.BOLD}{cfg['short_id']}{Colors.ENDC}")
        print(f"PublicKey:  {Colors.BOLD}{cfg['public_key']}{Colors.ENDC}")
        if cfg.get("generated_private_key"):
            print(f"PrivateKey: {Colors.BOLD}{cfg['generated_private_key']}{Colors.ENDC}")
            print_info("Use this private key on the server side.")


def install_tunnel_flow(tunnel_type):
    tunnel_profiles = {
        "direct": {
            "label": "Direct Tunnel",
            "client_location": "Iran",
            "server_location": "Kharej",
            "bind_logical_side": "client",
            "mapping_mode": "direct",
        },
        "reverse": {
            "label": "Reverse Tunnel",
            "client_location": "Kharej",
            "server_location": "Iran",
            "bind_logical_side": "server",
            "mapping_mode": "reverse",
        },
    }
    profile = tunnel_profiles.get(tunnel_type)
    if not profile:
        print_error(f"Unknown tunnel type: {tunnel_type}")
        return

    print_header(f"🧭 {profile['label']} Setup")
    print_menu(
        "Select Node Role",
        [
            f"1. This node = Server ({profile['server_location']})",
            f"2. This node = Client ({profile['client_location']})",
            "0. Cancel",
        ],
        color=Colors.CYAN,
        min_width=56,
    )

    while True:
        node_choice = input("Select role for this machine [1/2/0]: ").strip()
        if node_choice == "0":
            print_info("Tunnel setup cancelled.")
            return
        if node_choice not in {"1", "2"}:
            print_error("Invalid choice.")
            continue

        logical_role = "server" if node_choice == "1" else "client"
        location = (
            profile["server_location"]
            if logical_role == "server"
            else profile["client_location"]
        )
        bind_side_label = (
            f"Client side ({profile['client_location']})"
            if profile["bind_logical_side"] == "client"
            else f"Server side ({profile['server_location']})"
        )
        target_side_label = (
            f"Server side ({profile['server_location']})"
            if profile["bind_logical_side"] == "client"
            else f"Client side ({profile['client_location']})"
        )

        if logical_role == "server":
            collect_mappings = profile["bind_logical_side"] == "server"
            install_server_flow(
                server_location_label=location,
                tunnel_label=f"{profile['label']} ({bind_side_label} -> {target_side_label})",
                tunnel_mode=tunnel_type,
                collect_mappings=collect_mappings,
                mapping_mode=profile["mapping_mode"],
                bind_side_label=bind_side_label,
                target_side_label=target_side_label,
            )
            return

        collect_mappings = profile["bind_logical_side"] == "client"
        install_client_flow(
            client_location_label=location,
            tunnel_label=f"{profile['label']} ({bind_side_label} -> {target_side_label})",
            tunnel_mode=tunnel_type,
            collect_mappings=collect_mappings,
            mapping_mode=profile["mapping_mode"],
            bind_side_label=bind_side_label,
            target_side_label=target_side_label,
        )
        return


def main_menu():
    while True:
        print_banner()
        print_menu(
            "Main Menu",
            [
                f"{Colors.GREEN}[1]{Colors.ENDC} 🟢 Direct Tunnel Setup (IR -> KH)",
                f"{Colors.GREEN}[2]{Colors.ENDC} 🔁 Reverse Tunnel Setup (KH -> IR)",
                f"{Colors.CYAN}[3]{Colors.ENDC} 🔄 Update Binary",
                f"{Colors.CYAN}[4]{Colors.ENDC} 🗑️  Uninstall",
                f"{Colors.CYAN}[5]{Colors.ENDC} 📊 Monitor / Logs / Service Control",
                f"{Colors.CYAN}[6]{Colors.ENDC} 🧩 Multi Tunnel Management",
                f"{Colors.WARNING}[0]{Colors.ENDC} 🚪 Exit",
            ],
            color=Colors.CYAN,
            min_width=58,
        )

        choice = input(f"\n{Colors.BOLD}Select option: {Colors.ENDC}").strip()

        if choice == "1":
            check_root()
            if ensure_binary():
                install_tunnel_flow("direct")
                input("\nPress Enter to continue...")

        elif choice == "2":
            check_root()
            if ensure_binary():
                install_tunnel_flow("reverse")
                input("\nPress Enter to continue...")

        elif choice == "3":
            check_root()
            if download_binary():
                restart_installed_services()
                print_success("✅ Updated successfully.")
                input("\nPress Enter to continue...")

        elif choice == "4":
            uninstall_everything()
            input("\nPress Enter to continue...")

        elif choice == "5":
            check_root()
            service_control_menu()

        elif choice == "6":
            check_root()
            multi_tunnel_menu()

        elif choice == "0":
            sys.exit(0)
        else:
            print_error("Invalid choice.")


if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
