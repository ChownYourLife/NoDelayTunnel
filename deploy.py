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
import urllib.parse
import urllib.request
import uuid
import builtins

# Configuration
REPO_OWNER = "ChownYourLife"
REPO_NAME = "NoDelayTunnel"
BINARY_NAME = "nodelay"
INSTALL_DIR = "/usr/local/bin"
MANAGER_ALIAS_NAME = "nodelay-manager"
MANAGER_ALIAS_PATH = os.path.join(INSTALL_DIR, MANAGER_ALIAS_NAME)
MANAGER_UPDATE_RAW_MAIN = "https://raw.githubusercontent.com/ChownYourLife/NoDelayTunnel/refs/heads/main/deploy.py"
MANAGER_UPDATE_TIMEOUT = 20
CONFIG_DIR = "/etc/nodelay"
SERVER_SERVICE_NAME = "nodelay-server"
CLIENT_SERVICE_NAME = "nodelay-client"
LEGACY_SERVICE_NAME = "nodelay"
SYSTEMD_DIR = "/etc/systemd/system"
NODELAY_SYSCTL_D_PATH = "/etc/sysctl.d/99-nodelay.conf"
SYSCTL_CONF_PATH = "/etc/sysctl.conf"
SYSCTL_CONF_BEGIN = "# BEGIN NoDelay Tunnel managed settings"
SYSCTL_CONF_END = "# END NoDelay Tunnel managed settings"

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

DEFAULT_IRAN_PORT = 443
DEFAULT_KHAREJ_PORT = 443
TUNING_SECTIONS = ["smux", "tcp", "udp", "kcp", "quic", "reconnect"]
IPERF_TEST_DEFAULT_PORT = 9777
IPERF_TEST_DEFAULT_DURATION = 8
IPERF_TEST_DEFAULT_STREAMS = 8
IPERF_MULTI_PORT_TARGET_COUNT = 100
IPERF_MULTI_PORT_TOP_COUNT = 5
IPERF_MULTI_PORT_REQUIRED = [443, 80, 9999, 2053, 2095, 2086]
# iperf3 controls TCP segment size via MSS; set to 1300 for tunnel-path testing.
IPERF_TEST_MSS = 1300
IPERF_GOOD_MBPS = 150.0
IPERF_EXCELLENT_MBPS = 200.0
IPERF_POOR_MBPS = 100.0
PORT_HOPPING_MAX_PORTS = 256
MSS_CLAMP_DEFAULT = 0
SYSTEMD_RUNTIME_ENV = {
    "GOMEMLIMIT": "1GiB",
    "NODELAY_MEM_HOUSEKEEPER": "1",
    "NODELAY_MEM_HOUSEKEEPER_INTERVAL": "300s",
    "NODELAY_MEM_HOUSEKEEPER_MIN_HEAP": "512MiB",
}
DEFAULT_SERVICE_RESTART_MINUTES = 0
DEFAULT_SERVICE_RESTART_SECONDS = 3
DEFAULT_SERVICE_RUNTIME_MAX_MINUTES = 0

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


def normalize_service_restart_minutes(value, default=0):
    try:
        minutes = int(value)
    except (TypeError, ValueError):
        minutes = int(default)
    if minutes < 0:
        minutes = int(default)
    return minutes


def parse_service_restart_minutes(service_name, fallback=0):
    fallback_minutes = normalize_service_restart_minutes(fallback, 0)
    service_path = service_file_path(service_name)
    content = ""

    if os.path.exists(service_path):
        with open(service_path, "r") as f:
            content = f.read()
    else:
        quoted = shlex.quote(f"{service_name}.service")
        rc, stdout, _ = run_command_output(f"systemctl cat {quoted}")
        if rc == 0:
            content = stdout

    if not content:
        return fallback_minutes

    restart_match = re.search(r"(?im)^Restart\s*=\s*([^\n#;]+)", content)
    if restart_match:
        restart_mode = restart_match.group(1).strip().lower()
        if restart_mode in {"no", "off", "false", "never"}:
            return 0

    sec_match = re.search(r"(?im)^RestartSec\s*=\s*([^\n#;]+)", content)
    if not sec_match:
        return fallback_minutes

    token = sec_match.group(1).strip().lower()
    min_match = re.fullmatch(r"(\d+)\s*(?:m|min|minute|minutes)", token)
    if min_match:
        return int(min_match.group(1))

    sec_value_match = re.fullmatch(r"(\d+)\s*(?:s|sec|second|seconds)?", token)
    if sec_value_match:
        seconds = int(sec_value_match.group(1))
        return 0 if seconds <= 0 else max(1, (seconds + 59) // 60)

    return fallback_minutes


def prompt_service_restart_minutes(default_minutes=0):
    _ = normalize_service_restart_minutes(default_minutes, 0)
    return DEFAULT_SERVICE_RESTART_MINUTES


def normalize_service_runtime_max_minutes(value, default=0):
    try:
        minutes = int(value)
    except (TypeError, ValueError):
        minutes = int(default)
    if minutes < 0:
        minutes = int(default)
    return minutes


def _parse_time_value_to_seconds(raw):
    token = str(raw or "").strip().lower()
    if token in {"", "infinity", "infinite", "inf", "0", "0s"}:
        return 0

    m = re.fullmatch(r"(\d+)\s*(?:s|sec|second|seconds)?", token)
    if m:
        return int(m.group(1))

    m = re.fullmatch(r"(\d+)\s*(?:m|min|minute|minutes)", token)
    if m:
        return int(m.group(1)) * 60

    m = re.fullmatch(r"(\d+)\s*(?:h|hr|hour|hours)", token)
    if m:
        return int(m.group(1)) * 3600

    m = re.fullmatch(r"(\d+)\s*(?:d|day|days)", token)
    if m:
        return int(m.group(1)) * 86400

    return None


def parse_service_runtime_max_minutes(service_name, fallback=0):
    fallback_minutes = normalize_service_runtime_max_minutes(fallback, 0)
    service_path = service_file_path(service_name)
    content = ""

    if os.path.exists(service_path):
        with open(service_path, "r") as f:
            content = f.read()
    else:
        quoted = shlex.quote(f"{service_name}.service")
        rc, stdout, _ = run_command_output(f"systemctl cat {quoted}")
        if rc == 0:
            content = stdout

    if not content:
        return fallback_minutes

    match = re.search(r"(?im)^RuntimeMaxSec\s*=\s*([^\n#;]+)", content)
    if not match:
        return fallback_minutes

    seconds = _parse_time_value_to_seconds(match.group(1))
    if seconds is None:
        return fallback_minutes
    if seconds <= 0:
        return 0
    return max(1, (seconds + 59) // 60)


def prompt_service_runtime_max_minutes(default_minutes=0):
    default_minutes = normalize_service_runtime_max_minutes(default_minutes, 0)
    while True:
        raw = input_default("Runtime max in minutes (0 = disabled)", str(default_minutes)).strip()
        try:
            value = int(raw)
        except ValueError:
            print_error("Please enter an integer >= 0.")
            continue
        if value < 0:
            print_error("Please enter an integer >= 0.")
            continue
        return value


def check_root():
    if os.geteuid() != 0:
        print_error("This script must be run as root.")
        sys.exit(1)



def install_manager_alias():
    check_root()

    source_script = os.path.realpath(__file__)
    if not os.path.exists(source_script):
        print_error(f"Source script not found: {source_script}")
        return False

    if os.path.isdir(MANAGER_ALIAS_PATH):
        print_error(f"Cannot install alias because path is a directory: {MANAGER_ALIAS_PATH}")
        return False

    wrapper = (
        "#!/usr/bin/env bash\n"
        f"exec python3 {shlex.quote(source_script)} \"$@\"\n"
    )

    try:
        with open(MANAGER_ALIAS_PATH, "w") as handle:
            handle.write(wrapper)
        os.chmod(MANAGER_ALIAS_PATH, 0o755)
    except OSError as exc:
        print_error(f"Failed to install alias at {MANAGER_ALIAS_PATH}: {exc}")
        return False

    print_success(f"Installed command alias: {MANAGER_ALIAS_NAME}")
    print_info(f"Path: {MANAGER_ALIAS_PATH}")
    print_info(f"Run: {MANAGER_ALIAS_NAME}")
    return True


def update_manager_script():
    check_root()

    source_script = os.path.realpath(__file__)
    if not os.path.exists(source_script):
        print_error(f"Source script not found: {source_script}")
        return False

    print_header("⬆️ Updating nodelay-manager Script")

    fetched_text = ""
    fetched_from = MANAGER_UPDATE_RAW_MAIN

    try:
        req = urllib.request.Request(
            MANAGER_UPDATE_RAW_MAIN,
            headers={"User-Agent": "nodelay-manager-updater"},
        )
        with urllib.request.urlopen(req, timeout=MANAGER_UPDATE_TIMEOUT) as resp:
            body = resp.read().decode("utf-8")
        if "def main_menu(" not in body or "NoDelay" not in body:
            raise ValueError("downloaded file does not look like deploy.py")
        fetched_text = body
    except Exception as exc:
        print_error("Failed to download latest deploy.py")
        print_error(f"{MANAGER_UPDATE_RAW_MAIN}: {exc}")
        return False

    try:
        with open(source_script, "r", encoding="utf-8") as handle:
            current_text = handle.read()
    except OSError as exc:
        print_error(f"Failed to read current script: {exc}")
        return False
    normalized_new = fetched_text.replace("\r\n", "\n")
    if not normalized_new.endswith("\n"):
        normalized_new += "\n"

    if current_text == normalized_new:
        print_info("nodelay-manager is already up to date.")
        print_info(f"Source: {fetched_from}")
        install_manager_alias()
        return True

    backup_path = f"{source_script}.bak.{int(time.time())}"
    tmp_path = ""
    try:
        shutil.copy2(source_script, backup_path)
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=os.path.dirname(source_script) or ".",
            delete=False,
        ) as tmp:
            tmp.write(normalized_new)
            tmp_path = tmp.name
        os.chmod(tmp_path, 0o755)
        os.replace(tmp_path, source_script)
    except Exception as exc:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass
        print_error(f"Failed to replace script: {exc}")
        print_info(f"Backup kept at: {backup_path}")
        return False

    print_success("Updated nodelay-manager script successfully.")
    print_info(f"Downloaded from: {fetched_from}")
    print_info(f"Backup: {backup_path}")

    install_manager_alias()
    return True
def set_sysctl_conf_managed_block(setting_lines):
    existing_lines = []
    if os.path.exists(SYSCTL_CONF_PATH):
        try:
            with open(SYSCTL_CONF_PATH, "r") as handle:
                existing_lines = handle.read().splitlines()
        except OSError as exc:
            print_error(f"Could not read {SYSCTL_CONF_PATH}: {exc}")
            return False

    cleaned = []
    in_block = False
    for line in existing_lines:
        stripped = line.strip()
        if stripped == SYSCTL_CONF_BEGIN:
            in_block = True
            continue
        if stripped == SYSCTL_CONF_END:
            in_block = False
            continue
        if not in_block:
            cleaned.append(line)

    while cleaned and cleaned[-1].strip() == "":
        cleaned.pop()

    if setting_lines:
        cleaned.append("")
        cleaned.append(SYSCTL_CONF_BEGIN)
        cleaned.extend(setting_lines)
        cleaned.append(SYSCTL_CONF_END)

    try:
        with open(SYSCTL_CONF_PATH, "w") as handle:
            handle.write("\n".join(cleaned) + "\n")
        return True
    except OSError as exc:
        print_error(f"Could not write {SYSCTL_CONF_PATH}: {exc}")
        return False


def apply_mss_clamp_rules(mss=MSS_CLAMP_DEFAULT):
    tools = [tool for tool in ("iptables", "ip6tables") if shutil.which(tool)]
    if not tools:
        print_info("Skipping MSS clamp: iptables/ip6tables not found.")
        return False

    rule = "-p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"
    any_ok = False
    for tool in tools:
        for chain in ("OUTPUT", "FORWARD"):
            exists = run_command(f"{tool} -t mangle -C {chain} {rule}", check=False)
            if exists:
                any_ok = True
                continue
            added = run_command(f"{tool} -t mangle -A {chain} {rule}", check=False)
            any_ok = any_ok or added
    if any_ok:
        print_success("Applied MSS clamp rule (TCP SYN clamp-to-pmtu).")
    else:
        print_info("MSS clamp rules were not applied (check firewall backend/permissions).")
    return any_ok


def remove_mss_clamp_rules(mss=MSS_CLAMP_DEFAULT):
    tools = [tool for tool in ("iptables", "ip6tables") if shutil.which(tool)]
    if not tools:
        return False

    rule = "-p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"
    removed_any = False
    for tool in tools:
        for chain in ("OUTPUT", "FORWARD"):
            while run_command(f"{tool} -t mangle -D {chain} {rule}", check=False):
                removed_any = True
    return removed_any


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
                ("net.ipv4.tcp_base_mss", "1024"),
                ("net.ipv4.tcp_keepalive_time", "120"),
                ("net.ipv4.tcp_keepalive_intvl", "10"),
                ("net.ipv4.tcp_keepalive_probes", "3"),
                ("net.ipv4.tcp_fin_timeout", "20"),
                ("net.ipv6.conf.all.disable_ipv6", "1"),
                ("net.ipv6.conf.default.disable_ipv6", "1"),
                ("net.ipv6.conf.lo.disable_ipv6", "1"),
            ],
            "congestion_control": "bbr",
            "qdisc": "fq_codel",
        },
        "aggressive": {
            "title": "🚀 Linux Network Tuning (Aggressive)",
            "sysctl": [
                # Higher throughput bias; keep it upload-safe for real-world speed tests.
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
                # Keep fastopen conservative to avoid middlebox/path quirks.
                ("net.ipv4.tcp_fastopen", "1"),
                ("net.ipv4.tcp_mtu_probing", "1"),
                ("net.ipv4.tcp_base_mss", "1024"),
                ("net.ipv4.tcp_keepalive_time", "120"),
                ("net.ipv4.tcp_keepalive_intvl", "10"),
                ("net.ipv4.tcp_keepalive_probes", "3"),
                ("net.ipv4.tcp_fin_timeout", "20"),
                ("net.ipv6.conf.all.disable_ipv6", "1"),
                ("net.ipv6.conf.default.disable_ipv6", "1"),
                ("net.ipv6.conf.lo.disable_ipv6", "1"),
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
    mss_ok = apply_mss_clamp_rules(MSS_CLAMP_DEFAULT)

    managed_lines = [f"{k}={v}" for k, v in sysctl_settings]
    managed_lines.append(f"net.ipv4.tcp_congestion_control={selected['congestion_control']}")
    managed_lines.append(f"net.core.default_qdisc={selected['qdisc']}")

    conf_lines = ["# NoDelay Tunnel Linux network tuning"]
    conf_lines.extend(managed_lines)
    try:
        with open(NODELAY_SYSCTL_D_PATH, "w") as handle:
            handle.write("\n".join(conf_lines) + "\n")
        print_success(f"Persisted sysctl settings to {NODELAY_SYSCTL_D_PATH}")
    except OSError as exc:
        print_error(f"Could not write {NODELAY_SYSCTL_D_PATH}: {exc}")

    if set_sysctl_conf_managed_block(managed_lines):
        print_success(f"Persisted sysctl settings to {SYSCTL_CONF_PATH}")
    else:
        print_error(f"Failed to persist sysctl settings to {SYSCTL_CONF_PATH}")

    run_command("sysctl --system", check=False)
    run_command("sysctl -p", check=False)

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
    if not mss_ok:
        print_info("MSS clamp is not active; fragmented tunnel paths may reduce upload throughput.")
    return True


def restore_linux_network_defaults():
    if not sys.platform.startswith("linux"):
        print_info("Skipping network defaults restore: only supported on Linux.")
        return False

    print_header("♻️ Restore Linux Network Defaults")
    if os.path.exists(NODELAY_SYSCTL_D_PATH):
        try:
            os.remove(NODELAY_SYSCTL_D_PATH)
            print_success(f"Removed tuning file: {NODELAY_SYSCTL_D_PATH}")
        except OSError as exc:
            print_error(f"Could not remove {NODELAY_SYSCTL_D_PATH}: {exc}")
            return False
    else:
        print_info("No persisted NoDelay tuning file found.")

    if set_sysctl_conf_managed_block([]):
        print_success(f"Removed managed NoDelay block from {SYSCTL_CONF_PATH}")
    else:
        print_error(f"Could not update {SYSCTL_CONF_PATH}")

    run_command("sysctl --system", check=False)
    run_command("sysctl -p", check=False)
    run_command("sysctl -w net.ipv4.tcp_congestion_control=cubic", check=False)
    _, iface, _ = run_command_output("ip -o link show up | awk -F': ' '$2 != \"lo\" {print $2; exit}'")
    iface = iface.strip() or "eth0"
    run_command(f"tc qdisc del dev {shlex.quote(iface)} root", check=False)
    _ = remove_mss_clamp_rules(MSS_CLAMP_DEFAULT)
    print_success("Restored Linux network defaults (best effort).")
    return True


def maybe_apply_linux_network_tuning():
    print_menu(
        "⚙️ Linux Optimization",
        [
            "1. Balanced (Recommended)",
            "2. Aggressive (Experimental)",
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


def ensure_iperf3_installed():
    if shutil.which("iperf3"):
        return True

    print_info("iperf3 is not installed. Attempting automatic installation...")
    installers = []
    if shutil.which("apt-get"):
        installers = [
            "apt-get update",
            "DEBIAN_FRONTEND=noninteractive apt-get install -y iperf3",
        ]
    elif shutil.which("dnf"):
        installers = ["dnf install -y iperf3"]
    elif shutil.which("yum"):
        installers = ["yum install -y iperf3"]
    elif shutil.which("apk"):
        installers = ["apk add --no-cache iperf3"]
    elif shutil.which("pacman"):
        installers = ["pacman -Sy --noconfirm iperf3"]
    elif shutil.which("zypper"):
        installers = ["zypper --non-interactive install iperf3"]

    if not installers:
        print_error("Could not detect package manager. Please install iperf3 manually.")
        return False

    for cmd in installers:
        if not run_command_stream(cmd):
            print_error(f"Installation command failed: {cmd}")
            return False
    if not shutil.which("iperf3"):
        print_error("iperf3 installation finished but binary was not found in PATH.")
        return False
    print_success("iperf3 installed successfully.")
    return True


def run_iperf3_json(command_args):
    try:
        result = subprocess.run(command_args, check=False, text=True, capture_output=True)
    except Exception as exc:
        return None, f"failed to run iperf3: {exc}"

    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()
    if result.returncode != 0:
        return None, stderr or stdout or "iperf3 exited with non-zero status"

    try:
        payload = json.loads(stdout)
    except Exception:
        snippet = stdout[:220] + ("..." if len(stdout) > 220 else "")
        return None, f"failed to parse iperf3 json output: {snippet}"

    if isinstance(payload, dict) and payload.get("error"):
        return None, str(payload.get("error"))
    return payload, ""


def parse_port_list_csv(raw):
    seen = set()
    ports = []
    invalid = []
    for token in str(raw or "").split(","):
        part = token.strip()
        if not part:
            continue
        if not part.isdigit():
            invalid.append(part)
            continue
        port = int(part)
        if port < 1 or port > 65535:
            invalid.append(part)
            continue
        if port in seen:
            continue
        seen.add(port)
        ports.append(port)
    return ports, invalid


def extract_iperf_summary(payload):
    end = payload.get("end", {}) if isinstance(payload, dict) else {}
    sent_bps = float(end.get("sum_sent", {}).get("bits_per_second", 0.0) or 0.0)
    recv_bps = float(end.get("sum_received", {}).get("bits_per_second", 0.0) or 0.0)
    retr = int(end.get("sum_sent", {}).get("retransmits", 0) or 0)
    effective_bps = recv_bps if recv_bps > 0 else sent_bps
    return {
        "sent_mbps": sent_bps / 1_000_000.0,
        "recv_mbps": recv_bps / 1_000_000.0,
        "effective_mbps": effective_bps / 1_000_000.0,
        "retransmits": retr,
    }


def evaluate_connectivity_quality(uplink_mbps, downlink_mbps):
    floor = min(uplink_mbps, downlink_mbps)
    if floor >= IPERF_EXCELLENT_MBPS:
        return (
            "excellent",
            "Direct connectivity quality is excellent. Servers can be tunneled.",
        )
    if floor >= IPERF_GOOD_MBPS:
        return (
            "good",
            "Direct connectivity quality is good. Servers can be tunneled.",
        )
    if floor < IPERF_POOR_MBPS:
        return (
            "poor",
            "Direct connectivity is weak (<100 Mbps). Swap Iran/Kharej servers and test again.",
        )
    return (
        "moderate",
        "Direct connectivity is moderate. Tunnel can work, but quality may vary by route and load.",
    )


def run_direct_connectivity_measurement(target_host, port, duration, streams):
    base_cmd = [
        "iperf3",
        "-c",
        target_host,
        "-p",
        str(port),
        "-t",
        str(duration),
        "-P",
        str(streams),
        "-M",
        str(IPERF_TEST_MSS),
        "-J",
    ]

    down_payload, down_err = run_iperf3_json(base_cmd + ["-R"])
    if down_payload is None:
        return None, f"Downlink test failed: {down_err}"

    up_payload, up_err = run_iperf3_json(base_cmd)
    if up_payload is None:
        return None, f"Uplink test failed: {up_err}"

    down = extract_iperf_summary(down_payload)
    up = extract_iperf_summary(up_payload)
    down_mbps = down["effective_mbps"]
    up_mbps = up["effective_mbps"]
    quality, _ = evaluate_connectivity_quality(up_mbps, down_mbps)

    return {
        "port": int(port),
        "downlink_mbps": down_mbps,
        "uplink_mbps": up_mbps,
        "score_mbps": min(up_mbps, down_mbps),
        "quality": quality,
        "retransmits_up": up["retransmits"],
        "retransmits_down": down["retransmits"],
    }, ""


def run_direct_connectivity_benchmark(target_host, port, duration, streams):
    if not ensure_iperf3_installed():
        return None

    print_header("🌐 Direct Connectivity Benchmark (iperf3)")
    print_info(
        f"Target={target_host}:{port} | Duration={duration}s | Streams={streams} | MSS={IPERF_TEST_MSS} | Mode=direct (no tunnel)"
    )

    print_info("Running downlink + uplink test...")
    result, err = run_direct_connectivity_measurement(target_host, int(port), int(duration), int(streams))
    if result is None:
        print_error(err)
        print_info(
            "Ensure remote iperf3 server is running: `iperf3 -s -p "
            f"{port}`"
        )
        return None

    down_mbps = result["downlink_mbps"]
    up_mbps = result["uplink_mbps"]

    quality, verdict = evaluate_connectivity_quality(up_mbps, down_mbps)
    quality_label = {
        "excellent": f"{Colors.GREEN}excellent{Colors.ENDC}",
        "good": f"{Colors.GREEN}good{Colors.ENDC}",
        "moderate": f"{Colors.WARNING}moderate{Colors.ENDC}",
        "poor": f"{Colors.FAIL}poor{Colors.ENDC}",
    }.get(quality, quality)

    print_header("📈 Direct Connectivity Result")
    print(f"Downlink (remote -> local): {Colors.BOLD}{down_mbps:.2f} Mbps{Colors.ENDC}")
    print(f"Uplink   (local -> remote): {Colors.BOLD}{up_mbps:.2f} Mbps{Colors.ENDC}")
    print(
        f"Retransmits (uplink/downlink sender): "
        f"{Colors.BOLD}{result['retransmits_up']}/{result['retransmits_down']}{Colors.ENDC}"
    )
    print(f"Quality: {quality_label}")
    print_info(verdict)
    return {
        "port": int(port),
        "downlink_mbps": down_mbps,
        "uplink_mbps": up_mbps,
        "quality": quality,
    }


def build_multi_port_candidate_list(target_count):
    target = max(int(target_count), len(IPERF_MULTI_PORT_REQUIRED))
    ports = []
    seen = set()
    for port in IPERF_MULTI_PORT_REQUIRED:
        if 1 <= int(port) <= 65535 and port not in seen:
            seen.add(port)
            ports.append(int(port))
    while len(ports) < target:
        port = random.randint(1024, 65535)
        if port in seen:
            continue
        seen.add(port)
        ports.append(port)
    return ports


def start_iperf3_server_on_port(port):
    proc = subprocess.Popen(
        ["iperf3", "-s", "-p", str(int(port))],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(0.08)
    if proc.poll() is None:
        return proc
    return None


def stop_iperf3_servers(server_procs):
    for _, proc in server_procs:
        if proc is None:
            continue
        if proc.poll() is not None:
            continue
        try:
            proc.terminate()
        except Exception:
            pass
    for _, proc in server_procs:
        if proc is None:
            continue
        if proc.poll() is not None:
            continue
        try:
            proc.wait(timeout=2.0)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


def run_multi_port_server_mode():
    if not ensure_iperf3_installed():
        return

    target_count = IPERF_MULTI_PORT_TARGET_COUNT
    initial_candidates = build_multi_port_candidate_list(target_count)
    started = []
    failed_count = 0
    attempted = set()
    required_failed = []

    def try_start(port):
        nonlocal failed_count
        p = int(port)
        if p in attempted:
            return False
        attempted.add(p)
        proc = start_iperf3_server_on_port(p)
        if proc is None:
            failed_count += 1
            return False
        started.append((p, proc))
        return True

    for p in initial_candidates:
        if len(started) >= target_count:
            break
        ok = try_start(p)
        if (p in IPERF_MULTI_PORT_REQUIRED) and not ok:
            required_failed.append(p)

    refill_guard = 0
    while len(started) < target_count and refill_guard < 10000:
        refill_guard += 1
        p = random.randint(1024, 65535)
        try_start(p)

    started_ports = [port for port, _ in started]
    if not started_ports:
        print_error("Failed to start any iperf3 server port.")
        return

    print_success(
        f"Started iperf3 server listeners on {len(started_ports)} ports "
        f"(failed attempts={failed_count})."
    )
    if required_failed:
        print_error(
            "Could not bind required ports: " + ",".join(str(p) for p in required_failed)
        )
    csv_ports = ",".join(str(p) for p in started_ports)
    print_header("📋 Port List For Client")
    print(csv_ports)
    print_info("Copy the exact comma-separated list to the client benchmark mode.")
    print_info("Press Ctrl+C to stop all started iperf3 servers.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        stop_iperf3_servers(started)
        print_info("Stopped all started iperf3 server listeners.")


def run_multi_port_client_benchmark(target_host, ports, duration, streams):
    if not ensure_iperf3_installed():
        return None
    if not ports:
        print_error("Port list is empty.")
        return None

    total = len(ports)
    print_header("🌐 Multi-Port Direct Connectivity Benchmark")
    print_info(
        f"Target={target_host} | Ports={total} | Duration={duration}s | "
        f"Streams={streams} | MSS={IPERF_TEST_MSS}"
    )

    results = []
    failed = []
    for index, port in enumerate(ports, start=1):
        print_info(f"[{index}/{total}] Testing {target_host}:{port} ...")
        result, err = run_direct_connectivity_measurement(
            target_host,
            int(port),
            int(duration),
            int(streams),
        )
        if result is None:
            failed.append((int(port), err))
            print_error(f"[{index}/{total}] port={int(port)} failed: {err}")
            continue

        results.append(result)
        print_success(
            f"[{index}/{total}] port={result['port']} "
            f"score={result['score_mbps']:.2f} Mbps "
            f"down={result['downlink_mbps']:.2f} Mbps "
            f"up={result['uplink_mbps']:.2f} Mbps "
            f"retrans(up/down)={result['retransmits_up']}/{result['retransmits_down']} "
            f"quality={result['quality']}"
        )

    if not results:
        print_error("All port tests failed.")
        if failed:
            print_info(f"First error: {failed[0][0]} -> {failed[0][1]}")
        return None

    ranked = sorted(
        results,
        key=lambda x: (x.get("score_mbps", 0.0), x.get("downlink_mbps", 0.0), x.get("uplink_mbps", 0.0)),
        reverse=True,
    )
    top_count = min(IPERF_MULTI_PORT_TOP_COUNT, len(ranked))

    print_header(f"🏆 Top {top_count} Ports")
    for idx, row in enumerate(ranked[:top_count], start=1):
        print(
            f"{idx}. port={row['port']} "
            f"score={row['score_mbps']:.2f} Mbps "
            f"down={row['downlink_mbps']:.2f} Mbps "
            f"up={row['uplink_mbps']:.2f} Mbps "
            f"quality={row['quality']}"
        )

    print_info(f"Successful tests: {len(results)}/{total}")
    if failed:
        print_info(f"Failed tests: {len(failed)} (showing up to 10 ports)")
        print_info(",".join(str(p) for p, _ in failed[:10]))

    return ranked


def direct_connectivity_test_menu(default_host=""):
    while True:
        print_menu(
            "🌐 Direct Connectivity Test (iperf3)",
            [
                "1. Start iperf3 server mode on this node",
                "2. Run client benchmark to remote node",
                "0. Back",
            ],
            color=Colors.CYAN,
            min_width=56,
        )
        choice = input("Select option: ").strip()
        if choice == "0":
            return
        if choice == "1":
            if not ensure_iperf3_installed():
                input("\nPress Enter to continue...")
                continue
            print_menu(
                "🖥️ iperf3 Server Mode",
                [
                    "1. Single-port server",
                    f"2. Multi-port server ({IPERF_MULTI_PORT_TARGET_COUNT} ports, includes common ports)",
                    "0. Back",
                ],
                color=Colors.CYAN,
                min_width=64,
            )
            server_mode = input("Select mode: ").strip()
            if server_mode == "0":
                continue
            if server_mode == "1":
                port = prompt_int("Listen Port", IPERF_TEST_DEFAULT_PORT)
                while port < 1 or port > 65535:
                    print_error("Port must be between 1 and 65535.")
                    port = prompt_int("Listen Port", IPERF_TEST_DEFAULT_PORT)
                print_info(
                    f"Starting iperf3 server on :{port} (Ctrl+C to stop)..."
                )
                try:
                    run_command_stream(f"iperf3 -s -p {int(port)}")
                except KeyboardInterrupt:
                    pass
            elif server_mode == "2":
                run_multi_port_server_mode()
            else:
                print_error("Invalid mode.")
            input("\nPress Enter to continue...")
            continue
        if choice == "2":
            host_seed = default_host or "1.2.3.4"
            target_host = input_default("Remote server host/IP", host_seed).strip()
            while not target_host:
                print_error("Remote host is required.")
                target_host = input_default("Remote server host/IP", host_seed).strip()

            print_menu(
                "🧪 Client Benchmark Mode",
                [
                    "1. Single-port benchmark",
                    f"2. Multi-port benchmark (rank top {IPERF_MULTI_PORT_TOP_COUNT})",
                    "0. Back",
                ],
                color=Colors.CYAN,
                min_width=60,
            )
            client_mode = input("Select mode: ").strip()
            if client_mode == "0":
                continue

            duration = prompt_int("Test duration per port (seconds)", IPERF_TEST_DEFAULT_DURATION)
            streams = prompt_int("Parallel streams", IPERF_TEST_DEFAULT_STREAMS)
            if streams < 1:
                streams = 1

            if client_mode == "1":
                port = prompt_int("Remote iperf3 port", IPERF_TEST_DEFAULT_PORT)
                while port < 1 or port > 65535:
                    print_error("Port must be between 1 and 65535.")
                    port = prompt_int("Remote iperf3 port", IPERF_TEST_DEFAULT_PORT)
                run_direct_connectivity_benchmark(target_host, int(port), int(duration), int(streams))
            elif client_mode == "2":
                csv_default = ",".join(str(p) for p in IPERF_MULTI_PORT_REQUIRED)
                csv_raw = input_default("Remote iperf3 ports (comma separated)", csv_default).strip()
                ports, invalid = parse_port_list_csv(csv_raw)
                if invalid:
                    print_error(f"Ignoring invalid entries: {', '.join(invalid)}")
                if not ports:
                    print_error("No valid ports provided.")
                    input("\nPress Enter to continue...")
                    continue
                run_multi_port_client_benchmark(target_host, ports, int(duration), int(streams))
            else:
                print_error("Invalid mode.")
            input("\nPress Enter to continue...")
            continue
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


def ensure_axel_installed():
    if shutil.which("axel"):
        return True

    print_info("axel not found; installing axel for accelerated download...")
    install_cmds = [
        "apt-get update -y && apt-get install -y axel",
        "apt-get install -y axel",
        "dnf install -y axel",
        "yum install -y axel",
        "apk add --no-cache axel",
        "pacman -Sy --noconfirm axel",
    ]
    for cmd in install_cmds:
        if command_succeeds(cmd) and shutil.which("axel"):
            print_success("axel installed successfully.")
            return True

    print_error("Failed to install axel automatically.")
    return False


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

    if not ensure_axel_installed():
        return False

    print_info(f"Downloading with axel: {download_url}")
    temp_path = "/tmp/nodelay_dl"
    try:
        if os.path.exists(temp_path):
            os.remove(temp_path)
    except OSError:
        pass

    axel_cmd = f"axel -a -n 16 -o {shlex.quote(temp_path)} {shlex.quote(download_url)}"
    if not command_succeeds(axel_cmd):
        print_error("❌ Download failed with axel.")
        return False

    try:
        if not os.path.exists(temp_path) or os.path.getsize(temp_path) <= 0:
            print_error("❌ Download failed: downloaded file is empty or missing.")
            return False
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
    # Core requires at least 8 bytes (16 hex chars).
    if len(value) < 16:
        return False
    return len(value) % 2 == 0


def generate_self_signed_cert(common_name="www.example.com", cert_name=""):
    cert_dir = os.path.join(CONFIG_DIR, "certs")
    if not os.path.exists(cert_dir):
        os.makedirs(cert_dir)
    base = cert_base_name(cert_name or common_name or "selfsigned")
    key_path = os.path.join(cert_dir, f"selfsigned-{base}.key")
    cert_path = os.path.join(cert_dir, f"selfsigned-{base}.crt")

    for path in (cert_path, key_path):
        if os.path.exists(path):
            try:
                os.remove(path)
                print_info(f"Replacing existing certificate file: {path}")
            except OSError as exc:
                print_error(f"Could not replace existing file {path}: {exc}")

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


def remove_cert_files_if_exist(cert_path, key_path):
    for path in (cert_path, key_path):
        if not path:
            continue
        if not os.path.exists(path):
            continue
        try:
            os.remove(path)
            print_info(f"Replacing existing certificate file: {path}")
        except OSError as exc:
            print_error(f"Could not replace existing file {path}: {exc}")


def ensure_certbot_installed():
    certbot_bin = shutil.which("certbot")
    if certbot_bin:
        return certbot_bin

    print_info("certbot is not installed. Attempting automatic installation...")
    installers = []
    if shutil.which("apt-get"):
        installers = [
            "apt-get update",
            "DEBIAN_FRONTEND=noninteractive apt-get install -y certbot",
        ]
    elif shutil.which("dnf"):
        installers = ["dnf install -y certbot"]
    elif shutil.which("yum"):
        installers = ["yum install -y certbot"]
    elif shutil.which("apk"):
        installers = ["apk add --no-cache certbot"]
    elif shutil.which("pacman"):
        installers = ["pacman -Sy --noconfirm certbot"]
    elif shutil.which("zypper"):
        installers = ["zypper --non-interactive install certbot"]
    elif shutil.which("snap"):
        installers = [
            "snap install core",
            "snap refresh core",
            "snap install --classic certbot",
            "ln -sf /snap/bin/certbot /usr/bin/certbot",
        ]
    else:
        print_error("Could not detect package manager. Please install certbot manually.")
        return ""

    for cmd in installers:
        if not run_command_stream(cmd):
            print_error(f"Installation command failed: {cmd}")
            return ""

    certbot_bin = shutil.which("certbot")
    if not certbot_bin:
        print_error("certbot installation finished but binary was not found in PATH.")
        return ""
    print_success("certbot installed successfully.")
    return certbot_bin


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


def prompt_certbot_ca_server(default_server="letsencrypt"):
    ca_options = [
        ("1", "Let's Encrypt", "letsencrypt", ""),
        ("2", "ZeroSSL", "zerossl", "https://acme.zerossl.com/v2/DV90"),
        ("3", "Buypass", "buypass", "https://api.buypass.com/acme/directory"),
        ("4", "SSL.com (RSA)", "sslcom_rsa", "https://acme.ssl.com/sslcom-dv-rsa"),
        ("5", "Google Trust Services", "google", "https://dv.acme-v02.api.pki.goog/directory"),
        ("6", "Custom ACME server", "custom", ""),
    ]
    print_menu(
        "Certificate CA Provider",
        [
            f"{key}. {name}" if provider != "custom" else f"{key}. {name}"
            for key, name, provider, _ in ca_options
        ],
        color=Colors.CYAN,
        min_width=62,
    )

    default_choice = "1"
    for key, _, provider, _ in ca_options:
        if provider == default_server:
            default_choice = key
            break

    while True:
        choice = input_default("Select CA [1-6]", default_choice).strip()
        selected = next((item for item in ca_options if item[0] == choice), None)
        if not selected:
            print_error("Invalid choice. Select 1..6.")
            continue
        provider = selected[2]
        server_url = selected[3]
        if provider != "custom":
            return provider, server_url
        custom = input_required("Custom ACME directory URL")
        return "custom", custom


def certbot_lineage_name(value):
    raw = cert_base_name(value).replace("_", "-").strip("-")
    return raw or "trusted-cert"


def generate_trusted_cert_certbot():
    print_menu(
        "Trusted Certificate (ACME)",
        [
            "1. Domain certificate (HTTP-01 on port 80)",
            "2. IP certificate (TLS-ALPN-01 on port 443)",
        ],
        color=Colors.CYAN,
        min_width=74,
    )

    while True:
        mode = input_default("Select mode [1/2]", "1").strip()
        if mode in {"1", "2"}:
            break
        print_error("Invalid choice. Select 1 or 2.")

    ca_provider, ca_server_url = prompt_certbot_ca_server("letsencrypt")
    if mode == "1":
        while True:
            identifier = normalize_domain_name(
                input_default("Domain for certificate (must resolve to this server)", "example.com")
            )
            if is_valid_domain_name(identifier):
                break
            print_error("Invalid domain format.")
        challenge_mode = "http-01"
    else:
        while True:
            identifier = normalize_ip_identifier(
                input_default("Public IP for certificate", "")
            )
            if identifier:
                break
            print_error("Invalid IP address.")
        challenge_mode = "tls-alpn-01"

    email = input_required("ACME account email")
    certbot = ensure_certbot_installed()
    if not certbot:
        return "", ""

    cert_dir = os.path.join(CONFIG_DIR, "certs")
    if not os.path.exists(cert_dir):
        os.makedirs(cert_dir)

    cert_name = input_default(
        "Certificate file name prefix (trusted-<name>.*)",
        cert_base_name(identifier),
    ).strip()
    base = cert_base_name(cert_name or identifier)
    lineage_name = certbot_lineage_name(base)
    cert_path = os.path.join(cert_dir, f"trusted-{base}.crt")
    key_path = os.path.join(cert_dir, f"trusted-{base}.key")
    remove_cert_files_if_exist(cert_path, key_path)

    stop_services = input_default(
        "Temporarily stop nodelay services for certbot challenge? (Y/n)",
        "y",
    ).strip().lower()
    stopped = []
    if stop_services in {"", "y", "yes"}:
        stopped = stop_active_tunnel_services()

    try:
        issue_args = [
            certbot,
            "certonly",
            "--non-interactive",
            "--agree-tos",
            "--email",
            email,
            "--cert-name",
            lineage_name,
            "--standalone",
            "--preferred-challenges",
            challenge_mode,
            "-d",
            identifier,
        ]
        if ca_server_url:
            issue_args.extend(["--server", ca_server_url])

        print_info(
            f"Issuing trusted certificate for {identifier} using certbot ({ca_provider})..."
        )
        if not run_args_stream(issue_args):
            print_error("Certificate issuance failed. Ensure challenge ports are reachable from the internet.")
            return "", ""

        live_dir = os.path.join("/etc/letsencrypt/live", lineage_name)
        fullchain_src = os.path.join(live_dir, "fullchain.pem")
        privkey_src = os.path.join(live_dir, "privkey.pem")
        if not (os.path.exists(fullchain_src) and os.path.exists(privkey_src)):
            print_error(f"certbot issued certificate but expected files were not found in {live_dir}")
            return "", ""
        try:
            shutil.copy2(fullchain_src, cert_path)
            shutil.copy2(privkey_src, key_path)
        except OSError as exc:
            print_error(f"Failed to copy certbot certificate files: {exc}")
            return "", ""

        print_success(f"Trusted certificate generated: {cert_path}")
        print_success(f"Private key generated      : {key_path}")
        return cert_path, key_path
    finally:
        if stopped:
            start_tunnel_services(stopped)


def ask_cert_options(default_cert="", default_key="", allow_keep=False):
    back_signal = "__BACK_TO_TRANSPORT_MENU__"
    has_default_pair = bool(default_cert and default_key)
    default_choice = "0" if (allow_keep and has_default_pair) else "1"
    choice_prompt = "Select option [0/1/2/3]" if (allow_keep and has_default_pair) else "Select option [1/2/3]"

    while True:
        options = []
        if allow_keep and has_default_pair:
            options.append("0. Keep current certificate files")
        options.extend(
            [
                "1. Use existing certificate path",
                "2. Generate self-signed certificate (Auto)",
                "3. Generate trusted certificate (Certbot ACME)",
            ]
        )
        print_menu(
            "Certificate Options",
            options,
            color=Colors.CYAN,
            min_width=54,
        )

        choice = input_default(choice_prompt, default_choice).strip()
        if choice == "0" and allow_keep and has_default_pair:
            return default_cert, default_key

        if choice in {"2", "3"}:
            if choice == "3":
                cert, key = generate_trusted_cert_certbot()
            else:
                domain = input_default("Common Name (CN) for certificate", "www.bing.com").strip()
                cert_name = input_default(
                    "Certificate file name prefix (selfsigned-<name>.*)",
                    cert_base_name(domain),
                ).strip()
                cert, key = generate_self_signed_cert(domain, cert_name)

            if cert and key:
                return cert, key

            continue_setup = input_default(
                "Certificate generation failed. Continue setup? (Y/n)",
                "y",
            ).strip().lower()
            if continue_setup not in {"y", "yes"}:
                return back_signal, back_signal
            continue

        cert = input_default("Certificate Path", default_cert or "").strip()
        while not cert:
            print_error("Certificate path is required.")
            cert = input_default("Certificate Path", default_cert or "").strip()
        key = input_default("Private Key Path", default_key or "").strip()
        while not key:
            print_error("Private key path is required.")
            key = input_default("Private Key Path", default_key or "").strip()
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


def prompt_short_id(default_value="", role="server"):
    seed = str(default_value or random_hex(16)).strip().lower()
    role_name = str(role or "").strip().lower()
    prompt_label = "Server Short ID (hex, min 16 chars)" if role_name == "client" else "Short ID (hex, min 16 chars)"
    while True:
        short_id = input_default(prompt_label, seed).lower()
        if is_valid_short_id(short_id):
            return short_id
        print_error("Invalid Short ID. Use even-length hex with at least 16 characters.")


def prompt_server_names(default_values=None):
    if isinstance(default_values, list):
        seed = ",".join([str(item).strip() for item in default_values if str(item).strip()])
    else:
        seed = str(default_values or "").strip()
    if not seed:
        seed = "www.zoomg.ir,zoomg.ir"
    while True:
        names = parse_csv(
            input_default(
                "Server Names (comma separated)", seed
            )
        )
        if names:
            return names
        print_error("At least one server name is required.")


def prompt_reality_private_key(default_key=""):
    seed = str(default_key or "").strip().lower()
    while True:
        if seed:
            key = input(
                "Private Key (x25519, 64 hex chars) [enter=keep current, type 'auto' to generate]: "
            ).strip().lower()
            if not key:
                key = seed
            elif key == "auto":
                key = ""
        else:
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


def prompt_reality_public_key(default_key=""):
    seed = str(default_key or "").strip().lower()
    while True:
        if seed:
            key = input(
                "Server Public Key (x25519, 64 hex chars) [enter=keep current, type 'auto' to generate pair]: "
            ).strip().lower()
            if not key:
                key = seed
            elif key == "auto":
                key = ""
        else:
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


TRANSPORT_TYPE_OPTIONS = [
    ("1", "tcp", "🌐 TCP"),
    ("2", "tls", "🔒 TLS"),
    ("3", "ws", "🕸️ WebSocket (WS)"),
    ("4", "wss", "🛡️ WebSocket Secure (WSS)"),
    ("5", "kcp", "⚡ KCP"),
    ("6", "quic", "🚄 QUIC"),
    ("7", "httpsmimicry", "🎭 HTTPS Mimicry"),
    ("8", "httpmimicry", "📄 HTTP Mimicry"),
    ("9", "reality", "🌌 REALITY"),
]
TRANSPORT_TYPE_INDEX_TO_NAME = {idx: name for idx, name, _ in TRANSPORT_TYPE_OPTIONS}
TRANSPORT_TYPE_NAME_TO_INDEX = {name: idx for idx, name, _ in TRANSPORT_TYPE_OPTIONS}
MUX_TYPE_OPTIONS = [
    ("1", "smux", "SMUX (recommended)"),
    ("2", "yamux", "Yamux"),
    ("3", "h2mux", "H2MUX (native HTTP/2 streams)"),
]
MUX_TYPE_INDEX_TO_NAME = {idx: name for idx, name, _ in MUX_TYPE_OPTIONS}
MUX_TYPE_NAME_TO_INDEX = {name: idx for idx, name, _ in MUX_TYPE_OPTIONS}


def normalize_endpoint_type(value, default="tcp"):
    raw = str(value or "").strip().lower()
    if raw in TRANSPORT_TYPE_NAME_TO_INDEX:
        return raw
    return default


def endpoint_supports_path(transport_type):
    return normalize_endpoint_type(transport_type) in {"ws", "wss", "httpmimicry", "httpsmimicry"}


def endpoint_uses_tls(transport_type):
    return normalize_endpoint_type(transport_type) in {"tls", "wss", "quic", "httpsmimicry"}


def empty_tls_config():
    return {
        "cert_file": "",
        "key_file": "",
        "ca_file": "",
        "server_name": "",
        "insecure_skip_verify": False,
        "require_client_cert": False,
    }


def default_path_for_transport(transport_type):
    transport_type = normalize_endpoint_type(transport_type)
    if transport_type in {"ws", "wss"}:
        return "/ws"
    if transport_type in {"httpmimicry", "httpsmimicry"}:
        return "/api/v1/upload"
    return "/tunnel"


def normalize_connection_strategy(value, default="parallel"):
    raw = str(value or "").strip().lower()
    if raw in {"parallel", "priority"}:
        return raw
    return default


def normalize_mux_type(value, default="smux"):
    raw = str(value or "").strip().lower()
    if raw in MUX_TYPE_NAME_TO_INDEX:
        return raw
    return default


def prompt_mux_type(default="smux"):
    normalized_default = normalize_mux_type(default, "smux")
    default_choice = MUX_TYPE_NAME_TO_INDEX.get(normalized_default, "1")
    print_menu(
        "🧵 Multiplexer",
        [f"{Colors.GREEN}[{idx}]{Colors.ENDC} {label}" for idx, _, label in MUX_TYPE_OPTIONS],
        color=Colors.CYAN,
        min_width=56,
    )
    while True:
        choice = input_default("MUX [1-3]", default_choice).strip()
        if choice in MUX_TYPE_INDEX_TO_NAME:
            return MUX_TYPE_INDEX_TO_NAME[choice]
        print_error("Invalid choice. Pick 1, 2, or 3.")


def prompt_connection_strategy(default="parallel"):
    normalized_default = normalize_connection_strategy(default, "parallel")
    default_choice = "2" if normalized_default == "priority" else "1"
    print_menu(
        "🔀 Connection Strategy",
        [
            f"{Colors.GREEN}[1]{Colors.ENDC} parallel (spread workers, plus failover)",
            f"{Colors.GREEN}[2]{Colors.ENDC} priority (ordered failover)",
        ],
        color=Colors.CYAN,
        min_width=56,
    )
    while True:
        choice = input_default("Strategy [1-2]", default_choice).strip()
        if choice == "1":
            return "parallel"
        if choice == "2":
            return "priority"
        print_error("Invalid choice. Pick 1 or 2.")


def prompt_endpoint_type(default="tcp", prompt_label="Transport Type"):
    normalized_default = normalize_endpoint_type(default, "tcp")
    default_choice = TRANSPORT_TYPE_NAME_TO_INDEX.get(normalized_default, "1")
    print_menu(
        "📡 Transport Endpoint",
        [f"{Colors.GREEN}[{idx}]{Colors.ENDC} {label}" for idx, _, label in TRANSPORT_TYPE_OPTIONS],
        color=Colors.CYAN,
        min_width=46,
    )
    while True:
        choice = input_default(f"{prompt_label} [1-9]", default_choice).strip()
        if choice in TRANSPORT_TYPE_INDEX_TO_NAME:
            return TRANSPORT_TYPE_INDEX_TO_NAME[choice]
        print_error("Invalid choice. Pick a number between 1 and 9.")


def normalize_server_names_list(value):
    if isinstance(value, list):
        raw_items = value
    elif isinstance(value, str):
        raw_items = parse_csv(value)
    else:
        raw_items = []
    out = []
    seen = set()
    for item in raw_items:
        name = str(item).strip()
        if not name:
            continue
        if name in seen:
            continue
        seen.add(name)
        out.append(name)
    return out


def normalize_port_hopping_mode(value, default="spread"):
    raw = str(value or "").strip().lower()
    if raw in {"", "spread"}:
        return "spread"
    return default


def normalize_port_hopping_ports(value):
    if isinstance(value, str):
        ports, _ = parse_port_list_csv(value)
        return ports
    if not isinstance(value, list):
        return []
    seen = set()
    out = []
    for item in value:
        try:
            port = int(str(item).strip())
        except (TypeError, ValueError):
            continue
        if port < 1 or port > 65535:
            continue
        if port in seen:
            continue
        seen.add(port)
        out.append(port)
    return out


def normalize_port_hopping_cfg(value, fallback=None):
    raw = value if isinstance(value, dict) else {}
    base = fallback if isinstance(fallback, dict) else {}
    mode = normalize_port_hopping_mode(raw.get("mode", base.get("mode", "spread")))
    enabled_default = bool(base.get("enabled", False))
    enabled = parse_bool(raw.get("enabled", enabled_default), enabled_default)
    start_port = 0
    end_port = 0
    count = 0
    try:
        start_port = int(raw.get("start_port", base.get("start_port", 0)) or 0)
    except (TypeError, ValueError):
        start_port = 0
    try:
        end_port = int(raw.get("end_port", base.get("end_port", 0)) or 0)
    except (TypeError, ValueError):
        end_port = 0
    try:
        count = int(raw.get("count", base.get("count", 0)) or 0)
    except (TypeError, ValueError):
        count = 0
    if count < 0:
        count = 0
    ports = normalize_port_hopping_ports(raw.get("ports", base.get("ports", [])))
    return {
        "enabled": enabled,
        "start_port": start_port,
        "end_port": end_port,
        "ports": ports,
        "mode": mode,
        "count": count,
    }


def has_port_hopping_cfg(cfg):
    if not isinstance(cfg, dict):
        return False
    if bool(cfg.get("enabled", False)):
        return True
    if int(cfg.get("start_port", 0) or 0) != 0:
        return True
    if int(cfg.get("end_port", 0) or 0) != 0:
        return True
    if int(cfg.get("count", 0) or 0) > 0:
        return True
    return len(normalize_port_hopping_ports(cfg.get("ports", []))) > 0


def resolved_port_hopping_ports(port_hopping_cfg, base_port):
    cfg = normalize_port_hopping_cfg(port_hopping_cfg, {})
    if not cfg["enabled"]:
        return []
    if base_port < 1 or base_port > 65535:
        return []
    seen = set()
    out = []

    def append_port(port):
        if port < 1 or port > 65535:
            return
        if port in seen:
            return
        seen.add(port)
        out.append(port)

    append_port(base_port)
    for port in cfg["ports"]:
        append_port(port)

    start_port = cfg["start_port"]
    end_port = cfg["end_port"]
    if start_port or end_port:
        if (
            start_port < 1
            or start_port > 65535
            or end_port < 1
            or end_port > 65535
            or start_port > end_port
        ):
            return []
        for port in range(start_port, end_port + 1):
            append_port(port)

    if cfg["count"] > 0 and len(out) > cfg["count"]:
        out = out[: cfg["count"]]
    return out


def prompt_port_hopping_for_endpoint(base_port, default_cfg=None):
    cfg = normalize_port_hopping_cfg(default_cfg, {})
    default_enabled = "y" if cfg["enabled"] else "n"
    enable = parse_bool(
        input_default("Enable Port Hopping for this endpoint? (y/N)", default_enabled),
        cfg["enabled"],
    )
    if not enable:
        return {
            "enabled": False,
            "start_port": 0,
            "end_port": 0,
            "ports": [],
            "mode": "spread",
            "count": 0,
        }

    while True:
        use_range_default = "y" if (cfg["start_port"] > 0 or cfg["end_port"] > 0) else "n"
        use_range = parse_bool(
            input_default("Use port range for hopping? (y/N)", use_range_default),
            cfg["start_port"] > 0 or cfg["end_port"] > 0,
        )
        start_port = 0
        end_port = 0
        if use_range:
            start_port = prompt_int(
                "Port Hopping range start_port",
                cfg["start_port"] if cfg["start_port"] > 0 else base_port,
            )
            end_port = prompt_int(
                "Port Hopping range end_port",
                cfg["end_port"] if cfg["end_port"] > 0 else start_port,
            )
            if (
                start_port < 1
                or start_port > 65535
                or end_port < 1
                or end_port > 65535
                or start_port > end_port
            ):
                print_error("Invalid range. start_port/end_port must be 1..65535 and start <= end.")
                continue

        ports_default = ",".join(str(p) for p in cfg["ports"])
        ports_csv = input_default("Additional individual hop ports CSV (optional)", ports_default).strip()
        ports, invalid = parse_port_list_csv(ports_csv)
        if invalid:
            print_error(f"Ignored invalid ports: {', '.join(invalid)}")

        candidate_cfg = normalize_port_hopping_cfg(
            {
                "enabled": True,
                "start_port": start_port,
                "end_port": end_port,
                "ports": ports,
                "mode": "spread",
                "count": cfg["count"],
            }
        )
        resolved = resolved_port_hopping_ports(candidate_cfg, base_port)
        if not resolved:
            print_error("No valid hop ports resolved for this endpoint.")
            continue
        if len(resolved) > PORT_HOPPING_MAX_PORTS:
            print_error(
                f"Resolved {len(resolved)} ports; max allowed per endpoint is {PORT_HOPPING_MAX_PORTS}. Narrow range/list."
            )
            continue
        print_info(f"Port hopping prepared with {len(resolved)} resolved ports (mode=spread).")
        return candidate_cfg


def normalize_endpoint_reality_config(
    value,
    role,
    fallback=None,
    default_dest_when_empty=False,
):
    raw = value if isinstance(value, dict) else {}
    base = fallback if isinstance(fallback, dict) else {}
    dest = str(raw.get("dest", base.get("dest", ""))).strip()
    if default_dest_when_empty and not dest:
        dest = ""
    server_names = normalize_server_names_list(
        raw.get("server_names", base.get("server_names", []))
    )
    short_id = str(raw.get("short_id", base.get("short_id", ""))).strip().lower()
    private_key = str(raw.get("private_key", base.get("private_key", ""))).strip().lower()
    public_key = str(raw.get("public_key", base.get("public_key", ""))).strip().lower()
    if role == "server":
        public_key = ""
    else:
        private_key = ""
    return {
        "dest": dest,
        "server_names": server_names,
        "short_id": short_id,
        "private_key": private_key,
        "public_key": public_key,
    }


def normalize_transport_endpoint(
    endpoint,
    role,
    fallback_type="tcp",
    fallback_address="",
    fallback_path="/tunnel",
    fallback_reality=None,
    fallback_port_hopping=None,
):
    ep = endpoint if isinstance(endpoint, dict) else {}
    ep_type = normalize_endpoint_type(ep.get("type", fallback_type), normalize_endpoint_type(fallback_type))
    address = str(ep.get("address", fallback_address) or fallback_address).strip()
    if not address:
        address = ":8443" if role == "server" else "127.0.0.1:8443"
    path = normalize_path(ep.get("path", fallback_path), fallback_path)
    url = str(ep.get("url", "") or "").strip()
    tls = ep.get("tls", {}) if isinstance(ep.get("tls"), dict) else {}
    tls_cfg = {
        "cert_file": str(tls.get("cert_file", "")).strip(),
        "key_file": str(tls.get("key_file", "")).strip(),
        "ca_file": str(tls.get("ca_file", "")).strip(),
        "server_name": str(tls.get("server_name", "")).strip(),
        "insecure_skip_verify": bool(tls.get("insecure_skip_verify", False)),
        "require_client_cert": bool(tls.get("require_client_cert", False)),
    }
    if not endpoint_uses_tls(ep_type):
        tls_cfg = empty_tls_config()
    if role == "server":
        tls_cfg["server_name"] = ""
        tls_cfg["insecure_skip_verify"] = False
    else:
        tls_cfg["require_client_cert"] = False
    if ep_type == "reality":
        reality_cfg = normalize_endpoint_reality_config(
            ep.get("reality", {}),
            role=role,
            fallback=fallback_reality,
            default_dest_when_empty=True,
        )
    else:
        reality_cfg = {}
    port_hopping_cfg = normalize_port_hopping_cfg(
        ep.get("port_hopping", {}),
        fallback_port_hopping,
    )
    return {
        "type": ep_type,
        "address": address,
        "url": url,
        "path": path,
        "tls": tls_cfg,
        "reality": reality_cfg,
        "port_hopping": port_hopping_cfg,
    }


def derive_client_address_from_endpoint(endpoint, fallback="127.0.0.1:8443"):
    ep = endpoint if isinstance(endpoint, dict) else {}
    address = str(ep.get("address", "")).strip()
    if address:
        return address
    raw_url = str(ep.get("url", "")).strip()
    if not raw_url:
        return fallback
    try:
        parsed = urllib.parse.urlparse(raw_url)
    except Exception:
        return fallback
    host = (parsed.hostname or "").strip()
    if not host:
        return fallback
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "wss" else 80
    return f"{host}:{port}"


def prompt_additional_transport_endpoints(role, protocol_config, existing=None):
    back_signal = "__BACK_TO_TRANSPORT_MENU__"
    defaults = protocol_config if isinstance(protocol_config, dict) else {}
    endpoints = deep_copy(existing) if isinstance(existing, list) else []
    default_reality_cfg = normalize_endpoint_reality_config(
        {
            "dest": defaults.get("dest", ""),
            "server_names": defaults.get("server_names", []),
            "short_id": defaults.get("short_id", ""),
            "private_key": defaults.get("private_key", ""),
            "public_key": defaults.get("public_key", ""),
        },
        role=role,
        default_dest_when_empty=True,
    )

    if endpoints:
        keep = input_default("Keep existing additional endpoints? (Y/n)", "y").strip().lower()
        if keep in {"y", "yes"}:
            return endpoints
        endpoints = []

    if role == "client":
        print_info("Default topology is single-link: 1 Kharej client -> 1 Iran server endpoint.")
        print_info("Add extra upstream endpoints only for special failover/load scenarios.")
    else:
        print_info("Default topology is a single server listen endpoint.")
        print_info("Add extra listen endpoints only for special failover/load scenarios.")

    prompt = "Add additional upstream endpoints? (y/N)" if role == "client" else "Add additional listen endpoints? (y/N)"
    add_more = input_default(prompt, "n").strip().lower()
    if add_more not in {"y", "yes"}:
        return endpoints

    result = []
    index = 1
    while True:
        print(f"\n{Colors.CYAN}Additional endpoint #{index}{Colors.ENDC}")
        ep_type = prompt_endpoint_type(default=defaults.get("type", "tcp"))

        try:
            port_default = int(defaults.get("port", 443))
        except (TypeError, ValueError):
            port_default = 443
        if not (1 <= port_default <= 65535):
            port_default = 443

        if role == "server":
            host_default = str(defaults.get("listen_host", "")).strip()
            host = input_default("Listen Host/IP (blank = all interfaces)", host_default).strip()
            port = prompt_int("Listen Port", port_default)
            while port < 1 or port > 65535:
                print_error("Port must be between 1 and 65535.")
                port = prompt_int("Listen Port", port_default)
            address = f"{host}:{port}" if host else f":{port}"
        else:
            host = input_default(
                "Destination Host (IP/Domain)",
                defaults.get("server_addr", "127.0.0.1"),
            ).strip()
            while not host:
                print_error("Destination host is required.")
                host = input_default(
                    "Destination Host (IP/Domain)",
                    defaults.get("server_addr", "127.0.0.1"),
                ).strip()
            port = prompt_int("Destination Port", port_default)
            while port < 1 or port > 65535:
                print_error("Port must be between 1 and 65535.")
                port = prompt_int("Destination Port", port_default)
            address = f"{host}:{port}"

        path_default = default_path_for_transport(ep_type)
        seed_path = normalize_path(defaults.get("path", path_default), path_default)
        if endpoint_supports_path(ep_type):
            path_label = "Mimic Path" if ep_type in {"httpmimicry", "httpsmimicry"} else "Path"
            path = normalize_path(input_default(path_label, seed_path), path_default)
        else:
            path = seed_path
        if ep_type in {"httpmimicry", "httpsmimicry"}:
            defaults["mimicry_transport_mode"] = prompt_mimicry_transport_mode(
                defaults.get("mimicry_transport_mode", "websocket"),
                allow_http3=(ep_type == "httpsmimicry"),
            )
        default_port_hopping_cfg = normalize_port_hopping_cfg(
            defaults.get("port_hopping", {}),
            {},
        )
        base_port_for_hop = parse_port_from_address(address, port_default)
        port_hopping_cfg = prompt_port_hopping_for_endpoint(
            base_port_for_hop,
            default_cfg=default_port_hopping_cfg,
        )

        tls_cfg = empty_tls_config()
        if endpoint_uses_tls(ep_type):
            if role == "server":
                cert_default = str(defaults.get("cert", "")).strip()
                key_default = str(defaults.get("key", "")).strip()
                tls_cfg["cert_file"], tls_cfg["key_file"] = ask_cert_options(
                    default_cert=cert_default,
                    default_key=key_default,
                    allow_keep=bool(cert_default and key_default),
                )
                if tls_cfg["cert_file"] == back_signal and tls_cfg["key_file"] == back_signal:
                    return back_signal
                tls_cfg["ca_file"] = input_default(
                    "TLS client CA file (optional)",
                    "",
                ).strip()
                require_client_cert_default = False
                tls_cfg["require_client_cert"] = parse_bool(
                    input_default(
                        "Require client certificate (true/false)",
                        "true" if require_client_cert_default else "false",
                    ),
                    default=require_client_cert_default,
                )
                if tls_cfg["require_client_cert"]:
                    while not tls_cfg["ca_file"]:
                        print_error("Client CA file is required when client certificate auth is enabled.")
                        tls_cfg["ca_file"] = input_default(
                            "TLS client CA file",
                            "",
                        ).strip()
            else:
                default_sni = str(defaults.get("sni", "") or host).strip()
                tls_cfg["server_name"] = input_default("SNI for this endpoint", default_sni).strip()
                skip_verify_default = bool(defaults.get("insecure_skip_verify", False))
                tls_cfg["insecure_skip_verify"] = parse_bool(
                    input_default(
                        "Insecure Skip Verify (true/false)",
                        "true" if skip_verify_default else "false",
                    ),
                    default=skip_verify_default,
                )
                tls_cfg["ca_file"] = input_default("TLS CA file (optional)", "").strip()
                while True:
                    tls_cfg["cert_file"] = input_default(
                        "Client cert_file for this endpoint (optional)",
                        "",
                    ).strip()
                    tls_cfg["key_file"] = input_default(
                        "Client key_file for this endpoint (optional)",
                        "",
                    ).strip()
                    if bool(tls_cfg["cert_file"]) == bool(tls_cfg["key_file"]):
                        break
                    print_error("Client cert_file and key_file must both be set, or both left empty.")

        reality_cfg = {}
        if ep_type == "reality":
            reality_cfg = normalize_endpoint_reality_config(
                {},
                role=role,
                fallback=default_reality_cfg,
                default_dest_when_empty=True,
            )
            reality_cfg["server_names"] = prompt_server_names(
                default_values=default_reality_cfg.get("server_names", [])
            )
            reality_cfg["short_id"] = prompt_short_id(
                default_reality_cfg.get("short_id", ""),
                role=role,
            )
            reality_cfg["dest"] = input_default(
                "Dest (real target site:port)",
                default_reality_cfg.get("dest", "") or "",
            ).strip()
            if role == "server":
                (
                    reality_cfg["private_key"],
                    derived_public_key,
                    _,
                ) = prompt_reality_private_key(default_reality_cfg.get("private_key", ""))
                if derived_public_key:
                    print_info(f"Derived/Public key for this endpoint: {derived_public_key}")
            else:
                (
                    reality_cfg["public_key"],
                    generated_private_key,
                    _,
                ) = prompt_reality_public_key(default_reality_cfg.get("public_key", ""))
                if generated_private_key:
                    print_info(
                        f"Generated private key for this endpoint (use on server): {generated_private_key}"
                    )

        endpoint = normalize_transport_endpoint(
            {
                "type": ep_type,
                "address": address,
                "url": "",
                "path": path,
                "port_hopping": port_hopping_cfg,
                "tls": tls_cfg,
                "reality": reality_cfg,
            },
            role=role,
            fallback_type=ep_type,
            fallback_address=address,
            fallback_path=path,
            fallback_reality=default_reality_cfg,
            fallback_port_hopping=default_port_hopping_cfg,
        )
        if role == "client" and ep_type in {"ws", "wss"}:
            endpoint["url"] = resolve_ws_url({"type": ep_type}, endpoint["address"], endpoint["path"])

        result.append(endpoint)

        more = input_default("Add another additional endpoint? (y/N)", "n").strip().lower()
        if more not in {"y", "yes"}:
            break
        index += 1

    return result


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


DNS_MODE_OPTIONS = [
    ("system", "System Resolver"),
    ("doh_dot_strict", "DoH + DoT Strict (Recommended)"),
    ("doh_strict", "DoH Strict"),
    ("dot_strict", "DoT Strict"),
]


def normalize_dns_mode(value, default="system"):
    raw = str(value or "").strip().lower()
    allowed = {item[0] for item in DNS_MODE_OPTIONS}
    if raw in allowed:
        return raw
    return default


def normalize_dns_list(values, default_list):
    if isinstance(values, str):
        values = [item.strip() for item in values.split(",") if item.strip()]
    elif isinstance(values, list):
        values = [str(item).strip() for item in values if str(item).strip()]
    else:
        values = []
    if not values:
        values = list(default_list)
    seen = set()
    cleaned = []
    for item in values:
        if item in seen:
            continue
        seen.add(item)
        cleaned.append(item)
    return cleaned


def normalize_dns_config(cfg, default=None):
    if not isinstance(default, dict):
        default = {}
    if not isinstance(cfg, dict):
        cfg = {}
    out = {
        "mode": normalize_dns_mode(cfg.get("mode", default.get("mode", "system")), "system"),
        "doh_endpoints": normalize_dns_list(
            cfg.get("doh_endpoints", default.get("doh_endpoints", [])),
            ["https://1.1.1.1/dns-query", "https://dns.google/dns-query"],
        ),
        "dot_servers": normalize_dns_list(
            cfg.get("dot_servers", default.get("dot_servers", [])),
            ["1.1.1.1:853", "8.8.8.8:853"],
        ),
        "query_timeout": str(cfg.get("query_timeout", default.get("query_timeout", "3s")) or "3s").strip() or "3s",
        "cache_ttl": str(cfg.get("cache_ttl", default.get("cache_ttl", "2m")) or "2m").strip() or "2m",
        "max_inflight": 256,
    }
    try:
        out["max_inflight"] = int(cfg.get("max_inflight", default.get("max_inflight", 256)) or 256)
    except (TypeError, ValueError):
        out["max_inflight"] = 256
    if out["max_inflight"] <= 0:
        out["max_inflight"] = 256
    return out


def prompt_csv_list(prompt, default_values):
    default_csv = ", ".join(default_values)
    raw = input_default(prompt, default_csv).strip()
    if not raw:
        return list(default_values)
    return [item.strip() for item in raw.split(",") if item.strip()]


def prompt_dns_settings(defaults=None):
    current = normalize_dns_config(defaults or {}, {})
    current_mode = current["mode"]
    default_index = 1
    for idx, (mode_key, _) in enumerate(DNS_MODE_OPTIONS, start=1):
        if mode_key == current_mode:
            default_index = idx
            break

    lines = []
    for idx, (mode_key, label) in enumerate(DNS_MODE_OPTIONS, start=1):
        suffix = " (current)" if mode_key == current_mode else ""
        lines.append(f"{idx}. {label}{suffix}")
    print_menu("🌐 Secure DNS Mode", lines, color=Colors.CYAN, min_width=56)

    while True:
        choice = input_default(f"DNS mode [1-{len(DNS_MODE_OPTIONS)}]", default_index).strip()
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(DNS_MODE_OPTIONS):
                current["mode"] = DNS_MODE_OPTIONS[idx - 1][0]
                break
        print_error("Invalid choice.")

    if current["mode"] in {"doh_dot_strict", "doh_strict"}:
        current["doh_endpoints"] = normalize_dns_list(
            prompt_csv_list("DoH endpoints (comma-separated)", current["doh_endpoints"]),
            current["doh_endpoints"],
        )
    if current["mode"] in {"doh_dot_strict", "dot_strict"}:
        current["dot_servers"] = normalize_dns_list(
            prompt_csv_list("DoT servers (comma-separated)", current["dot_servers"]),
            current["dot_servers"],
        )

    current["query_timeout"] = input_default("DNS query timeout", current["query_timeout"]).strip() or current["query_timeout"]
    current["cache_ttl"] = input_default("DNS cache TTL", current["cache_ttl"]).strip() or current["cache_ttl"]
    current["max_inflight"] = max(1, prompt_int("DNS max inflight queries", current["max_inflight"]))
    return current

def normalize_mimicry_transport_mode(value, default="websocket"):
    raw = str(value or "").strip().lower()
    if raw in {"", "websocket", "ws", "wss"}:
        return "websocket"
    if raw in {"http2", "h2"}:
        return "http2"
    if raw in {"http3", "h3"}:
        return "http3"
    return default


def prompt_mimicry_transport_mode(default="websocket", allow_http3=False):
    normalized_default = normalize_mimicry_transport_mode(default, "websocket")
    if allow_http3 and normalized_default == "http3":
        default_choice = "3"
    elif normalized_default == "http2":
        default_choice = "2"
    else:
        default_choice = "1"
    menu_lines = [
        f"{Colors.GREEN}[1]{Colors.ENDC} WebSocket ({Colors.BOLD}ws/wss{Colors.ENDC})",
        f"{Colors.GREEN}[2]{Colors.ENDC} HTTP/2 stream tunnel",
    ]
    if allow_http3:
        menu_lines.append(f"{Colors.GREEN}[3]{Colors.ENDC} HTTP/3 (QUIC) stream tunnel")
    max_choice = 3 if allow_http3 else 2
    print_menu(
        "🎛️ Mimicry Transport Mode",
        menu_lines,
        color=Colors.CYAN,
        min_width=44,
    )
    while True:
        choice = input_default(f"Mode [1-{max_choice}]", default_choice).strip()
        if choice == "1":
            return "websocket"
        if choice == "2":
            return "http2"
        if allow_http3 and choice == "3":
            return "http3"
        print_error(f"Invalid choice. Pick 1..{max_choice}.")


def prompt_client_destination(default_host="1.2.3.4", default_port=DEFAULT_KHAREJ_PORT):
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


def menu_protocol(role, server_addr="", defaults=None, prompt_port=True, deployment_mode="default"):
    back_signal = "__BACK_TO_TRANSPORT_MENU__"
    options = [(idx, label) for idx, _, label in TRANSPORT_TYPE_OPTIONS]
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

    advanced_mode = str(deployment_mode).strip().lower() == "advanced"
    config = {
        "port": str(DEFAULT_IRAN_PORT),
        "path": "/tunnel",
        "network_mtu": 0,
        "network_dns": normalize_dns_config({"mode": "system"}, {"mode": "system"}),
        "utls_strict_profile_match": True,
        "mux_type": "smux",
        "mimicry_preset_region": "mixed",
        "mimicry_profiles": {},
        "mimicry_transport_mode": "websocket",
        "mimicry_auth_secret": "",
        "mimicry_auth_window_seconds": 60,
        "mimicry_basic_auth_user": "ndclient",
        "mimicry_basic_auth_pass": "ndclient",
        "pool_size": 3,
        "connection_strategy": "parallel",
        "additional_endpoints": [],
        "port_hopping": {
            "enabled": False,
            "start_port": 0,
            "end_port": 0,
            "ports": [],
            "mode": "spread",
            "count": 0,
        },
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
        "listen_host": "",
    }

    if isinstance(defaults, dict):
        for k, v in defaults.items():
            config[k] = v

    if not str(config.get("psk", "")).strip():
        if role == "server":
            config["psk"] = generate_uuid()
        else:
            config["psk"] = "replace-with-server-psk"

    def prompt_or_keep_port(default_port):
        default_value = config.get("port", default_port)
        if role == "client" and not prompt_port:
            return str(default_value)
        return input_default("Port", default_value)

    if role != "server":
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
        config["connection_strategy"] = prompt_connection_strategy(
            config.get("connection_strategy", "parallel")
        )

    if choice == "1":
        config["type"] = "tcp"
        config["port"] = prompt_or_keep_port(8080)

    elif choice == "2":
        config["type"] = "tls"
        config["port"] = prompt_or_keep_port(443)
        if role == "server":
            keep_current = input_default("Keep current certificate files? (Y/n)", "y").strip().lower()
            if keep_current in {"y", "yes"} and config.get("cert") and config.get("key"):
                pass
            else:
                cert, key = ask_cert_options()
                if cert == back_signal and key == back_signal:
                    print_info("Returning to protocol selection menu...")
                    return menu_protocol(
                        role,
                        server_addr=server_addr,
                        defaults=config,
                        prompt_port=prompt_port,
                        deployment_mode=deployment_mode,
                    )
                config["cert"], config["key"] = cert, key
        else:
            config["sni"], config["insecure_skip_verify"] = prompt_client_tls_settings(
                server_addr or config.get("server_addr", ""),
                default_sni=config.get("sni", ""),
                default_skip_verify=bool(config.get("insecure_skip_verify", True)),
            )

    elif choice == "3":
        config["type"] = "ws"
        config["port"] = prompt_or_keep_port(80)
        config["path"] = normalize_path(input_default("Path", config.get("path", "/ws")), "/ws")

    elif choice == "4":
        config["type"] = "wss"
        config["port"] = prompt_or_keep_port(443)
        config["path"] = normalize_path(input_default("Path", config.get("path", "/ws")), "/ws")
        if role == "server":
            keep_current = input_default("Keep current certificate files? (Y/n)", "y").strip().lower()
            if keep_current in {"y", "yes"} and config.get("cert") and config.get("key"):
                pass
            else:
                cert, key = ask_cert_options()
                if cert == back_signal and key == back_signal:
                    print_info("Returning to protocol selection menu...")
                    return menu_protocol(
                        role,
                        server_addr=server_addr,
                        defaults=config,
                        prompt_port=prompt_port,
                        deployment_mode=deployment_mode,
                    )
                config["cert"], config["key"] = cert, key
        else:
            config["sni"], config["insecure_skip_verify"] = prompt_client_tls_settings(
                server_addr or config.get("server_addr", ""),
                default_sni=config.get("sni", ""),
                default_skip_verify=bool(config.get("insecure_skip_verify", True)),
            )

    elif choice == "5":
        config["type"] = "kcp"
        config["port"] = prompt_or_keep_port(4000)

    elif choice == "6":
        config["type"] = "quic"
        config["port"] = prompt_or_keep_port(443)
        if role == "server":
            keep_current = input_default("Keep current certificate files? (Y/n)", "y").strip().lower()
            if keep_current in {"y", "yes"} and config.get("cert") and config.get("key"):
                pass
            else:
                cert, key = ask_cert_options()
                if cert == back_signal and key == back_signal:
                    print_info("Returning to protocol selection menu...")
                    return menu_protocol(
                        role,
                        server_addr=server_addr,
                        defaults=config,
                        prompt_port=prompt_port,
                        deployment_mode=deployment_mode,
                    )
                config["cert"], config["key"] = cert, key
        else:
            config["sni"], config["insecure_skip_verify"] = prompt_client_tls_settings(
                server_addr or config.get("server_addr", ""),
                default_sni=config.get("sni", ""),
                default_skip_verify=bool(config.get("insecure_skip_verify", True)),
            )

    elif choice == "7":
        config["type"] = "httpsmimicry"
        config["port"] = prompt_or_keep_port(443)
        config["path"] = normalize_path(
            input_default("Mimic Path", config.get("path", "/api/v1/upload")), "/api/v1/upload"
        )
        config["mimicry_preset_region"] = "mixed"
        config["mimicry_transport_mode"] = prompt_mimicry_transport_mode(
            config.get("mimicry_transport_mode", "websocket"),
            allow_http3=True,
        )
        enable_probe_guard = input_default(
            "Enable Mimicry Anti-Probe Auth Headers? (y/N)",
            "y" if str(config.get("mimicry_auth_secret", "")).strip() else "n",
        ).strip().lower()
        if enable_probe_guard in {"y", "yes"}:
            config["mimicry_auth_secret"] = input_default(
                "Mimicry Auth Secret (must match on both sides)",
                str(config.get("mimicry_auth_secret", "")).strip() or generate_uuid(),
            ).strip()
            while not config["mimicry_auth_secret"]:
                print_error("Mimicry Auth Secret cannot be empty when enabled.")
                config["mimicry_auth_secret"] = input_default(
                    "Mimicry Auth Secret (must match on both sides)",
                    generate_uuid(),
                ).strip()
            config["mimicry_auth_window_seconds"] = max(
                10,
                prompt_int(
                    "Mimicry Auth Time Window (seconds)",
                    int(config.get("mimicry_auth_window_seconds", 60) or 60),
                ),
            )
        else:
            config["mimicry_auth_secret"] = ""
            config["mimicry_auth_window_seconds"] = 60

        if advanced_mode:
            config["mimicry_basic_auth_user"] = input_default(
                "Mimicry Basic Auth Username",
                str(config.get("mimicry_basic_auth_user", "")).strip() or "ndclient",
            ).strip()
            while not config["mimicry_basic_auth_user"]:
                print_error("Mimicry Basic Auth username cannot be empty.")
                config["mimicry_basic_auth_user"] = input_default(
                    "Mimicry Basic Auth Username",
                    "ndclient",
                ).strip()

            config["mimicry_basic_auth_pass"] = input_default(
                "Mimicry Basic Auth Password",
                str(config.get("mimicry_basic_auth_pass", "")).strip() or "ndclient",
            ).strip()
            while not config["mimicry_basic_auth_pass"]:
                print_error("Mimicry Basic Auth password cannot be empty.")
                config["mimicry_basic_auth_pass"] = input_default(
                    "Mimicry Basic Auth Password",
                    "ndclient",
                ).strip()
        else:
            config["mimicry_basic_auth_user"] = str(config.get("mimicry_basic_auth_user", "")).strip() or "ndclient"
            config["mimicry_basic_auth_pass"] = str(config.get("mimicry_basic_auth_pass", "")).strip() or "ndclient"
        if role == "server":
            keep_current = input_default("Keep current certificate files? (Y/n)", "y").strip().lower()
            if keep_current in {"y", "yes"} and config.get("cert") and config.get("key"):
                pass
            else:
                cert, key = ask_cert_options()
                if cert == back_signal and key == back_signal:
                    print_info("Returning to protocol selection menu...")
                    return menu_protocol(
                        role,
                        server_addr=server_addr,
                        defaults=config,
                        prompt_port=prompt_port,
                        deployment_mode=deployment_mode,
                    )
                config["cert"], config["key"] = cert, key
        else:
            config["sni"], config["insecure_skip_verify"] = prompt_client_tls_settings(
                server_addr or config.get("server_addr", ""),
                default_sni=config.get("sni", ""),
                default_skip_verify=bool(config.get("insecure_skip_verify", True)),
            )

    elif choice == "8":
        config["type"] = "httpmimicry"
        config["port"] = prompt_or_keep_port(80)
        config["path"] = normalize_path(
            input_default("Mimic Path", config.get("path", "/api/v1/upload")), "/api/v1/upload"
        )
        config["mimicry_preset_region"] = "mixed"
        config["mimicry_transport_mode"] = prompt_mimicry_transport_mode(
            config.get("mimicry_transport_mode", "websocket"),
            allow_http3=False,
        )
        enable_probe_guard = input_default(
            "Enable Mimicry Anti-Probe Auth Headers? (y/N)",
            "y" if str(config.get("mimicry_auth_secret", "")).strip() else "n",
        ).strip().lower()
        if enable_probe_guard in {"y", "yes"}:
            config["mimicry_auth_secret"] = input_default(
                "Mimicry Auth Secret (must match on both sides)",
                str(config.get("mimicry_auth_secret", "")).strip() or generate_uuid(),
            ).strip()
            while not config["mimicry_auth_secret"]:
                print_error("Mimicry Auth Secret cannot be empty when enabled.")
                config["mimicry_auth_secret"] = input_default(
                    "Mimicry Auth Secret (must match on both sides)",
                    generate_uuid(),
                ).strip()
            config["mimicry_auth_window_seconds"] = max(
                10,
                prompt_int(
                    "Mimicry Auth Time Window (seconds)",
                    int(config.get("mimicry_auth_window_seconds", 60) or 60),
                ),
            )
        else:
            config["mimicry_auth_secret"] = ""
            config["mimicry_auth_window_seconds"] = 60

        if advanced_mode:
            config["mimicry_basic_auth_user"] = input_default(
                "Mimicry Basic Auth Username",
                str(config.get("mimicry_basic_auth_user", "")).strip() or "ndclient",
            ).strip()
            while not config["mimicry_basic_auth_user"]:
                print_error("Mimicry Basic Auth username cannot be empty.")
                config["mimicry_basic_auth_user"] = input_default(
                    "Mimicry Basic Auth Username",
                    "ndclient",
                ).strip()

            config["mimicry_basic_auth_pass"] = input_default(
                "Mimicry Basic Auth Password",
                str(config.get("mimicry_basic_auth_pass", "")).strip() or "ndclient",
            ).strip()
            while not config["mimicry_basic_auth_pass"]:
                print_error("Mimicry Basic Auth password cannot be empty.")
                config["mimicry_basic_auth_pass"] = input_default(
                    "Mimicry Basic Auth Password",
                    "ndclient",
                ).strip()
        else:
            config["mimicry_basic_auth_user"] = str(config.get("mimicry_basic_auth_user", "")).strip() or "ndclient"
            config["mimicry_basic_auth_pass"] = str(config.get("mimicry_basic_auth_pass", "")).strip() or "ndclient"
        config["sni"] = ""
        config["insecure_skip_verify"] = False

    elif choice == "9":
        config["type"] = "reality"
        config["port"] = prompt_or_keep_port(443)
        config["server_names"] = prompt_server_names(config.get("server_names", []))
        config["short_id"] = prompt_short_id(config.get("short_id", ""), role=role)
        config["dest"] = input_default(
            "Dest (camouflage upstream for probes, optional host:port)",
            config.get("dest", "") or "",
        ).strip()
        if role == "server":
            (
                config["private_key"],
                config["public_key"],
                config["reality_key_generated"],
            ) = prompt_reality_private_key(config.get("private_key", ""))
        else:
            (
                config["public_key"],
                config["generated_private_key"],
                config["reality_key_generated"],
            ) = prompt_reality_public_key(config.get("public_key", ""))

    current_psk = str(config.get("psk", "")).strip()
    disable_default = "y" if not current_psk else "n"
    disable_encryption = input_default(
        "Disable Encryption (PSK)? (Y/n)",
        disable_default,
    ).strip().lower()
    if disable_encryption in {"", "y", "yes"}:
        config["psk"] = ""
    else:
        if role == "server":
            config["psk"] = input_default(
                "PSK (shared secret)",
                current_psk or generate_uuid(),
            ).strip()
            while not config["psk"]:
                print_error("PSK cannot be empty when encryption is enabled.")
                config["psk"] = input_default(
                    "PSK (shared secret)",
                    generate_uuid(),
                ).strip()
        else:
            while True:
                config["psk"] = input_default(
                    "PSK (must match server)",
                    current_psk,
                ).strip()
                if config["psk"]:
                    break
                print_error("PSK cannot be empty when encryption is enabled.")

    try:
        primary_port = int(config.get("port", DEFAULT_IRAN_PORT))
    except (TypeError, ValueError):
        primary_port = DEFAULT_IRAN_PORT
    config["port_hopping"] = prompt_port_hopping_for_endpoint(
        primary_port,
        default_cfg=config.get("port_hopping", {}),
    )

    config["mux_type"] = prompt_mux_type(config.get("mux_type", "smux"))
    config["additional_endpoints"] = prompt_additional_transport_endpoints(
        role,
        config,
        existing=config.get("additional_endpoints", []),
    )
    if config["additional_endpoints"] == back_signal:
        print_info("Returning to protocol selection menu...")
        return menu_protocol(
            role,
            server_addr=server_addr,
            defaults=config,
            prompt_port=prompt_port,
            deployment_mode=deployment_mode,
        )
    config["network_mtu"] = prompt_network_mtu(config.get("network_mtu", 0))
    if advanced_mode:
        config["network_dns"] = prompt_dns_settings(config.get("network_dns", {}))
    else:
        config["network_dns"] = normalize_dns_config(
            config.get("network_dns", {}),
            {"mode": "system"},
        )
    config["utls_strict_profile_match"] = parse_bool(
        input_default("Force uTLS/HTTP profile coherence? (Y/n)", "y" if config.get("utls_strict_profile_match", True) else "n"),
        True,
    )

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
    service_name = build_service_name(role, instance)
    service_restart_minutes = parse_service_restart_minutes(
        service_name, fallback=DEFAULT_SERVICE_RESTART_MINUTES
    )
    service_runtime_max_minutes = parse_service_runtime_max_minutes(
        service_name, fallback=DEFAULT_SERVICE_RUNTIME_MAX_MINUTES
    )

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
    network_dns = normalize_dns_config(network_cfg.get("dns", {}), {})
    utls_cfg = parsed.get("utls", {}) if isinstance(parsed.get("utls"), dict) else {}
    utls_strict_profile_match = bool(utls_cfg.get("strict_profile_match", True))
    http_mimicry_cfg = (
        parsed.get("http_mimicry", {}) if isinstance(parsed.get("http_mimicry"), dict) else {}
    )
    mux_cfg = parsed.get("mux", {}) if isinstance(parsed.get("mux"), dict) else {}
    mux_type = normalize_mux_type(mux_cfg.get("type", "smux"), "smux")
    mimicry_preset_region = normalize_mimicry_preset_region(
        http_mimicry_cfg.get("preset_region", "mixed"),
        "mixed",
    )
    mimicry_profiles = deep_copy(http_mimicry_cfg.get("profiles", {})) if isinstance(http_mimicry_cfg.get("profiles"), dict) else {}
    mimicry_transport_mode = normalize_mimicry_transport_mode(
        http_mimicry_cfg.get("transport_mode", "websocket"),
        "websocket",
    )
    mimicry_auth_secret = str(http_mimicry_cfg.get("auth_secret", "")).strip()
    mimicry_basic_auth_user = str(http_mimicry_cfg.get("basic_auth_user", "")).strip()
    mimicry_basic_auth_pass = str(http_mimicry_cfg.get("basic_auth_pass", "")).strip()
    try:
        mimicry_auth_window_seconds = int(http_mimicry_cfg.get("auth_window_seconds", 60) or 60)
    except (TypeError, ValueError):
        mimicry_auth_window_seconds = 60
    if mimicry_auth_window_seconds <= 0:
        mimicry_auth_window_seconds = 60

    if role == "server":
        server_cfg = parsed.get("server", {}) if isinstance(parsed.get("server"), dict) else {}
        legacy_port_hopping_cfg = normalize_port_hopping_cfg(
            server_cfg.get("port_hopping", {}),
            {},
        )
        listen = server_cfg.get("listen", {}) if isinstance(server_cfg.get("listen"), dict) else {}
        listens = server_cfg.get("listens", [])
        if not isinstance(listens, list):
            listens = []
        reality_global = (
            parsed.get("reality", {}) if isinstance(parsed.get("reality"), dict) else {}
        )
        primary_fallback = normalize_transport_endpoint(
            listen,
            role="server",
            fallback_type="tcp",
            fallback_address=":8443",
            fallback_path="/tunnel",
            fallback_reality=reality_global,
        )
        normalized_listens = []
        for ep in listens:
            if not isinstance(ep, dict):
                continue
            normalized_listens.append(
                normalize_transport_endpoint(
                    ep,
                    role="server",
                    fallback_type=primary_fallback["type"],
                    fallback_address=primary_fallback["address"],
                    fallback_path=primary_fallback["path"],
                    fallback_reality=reality_global,
                )
            )
        if not normalized_listens:
            normalized_listens = [primary_fallback]
        if (
            normalized_listens
            and has_port_hopping_cfg(legacy_port_hopping_cfg)
            and not has_port_hopping_cfg(normalized_listens[0].get("port_hopping", {}))
        ):
            normalized_listens[0]["port_hopping"] = normalize_port_hopping_cfg(
                legacy_port_hopping_cfg,
                {},
            )
        primary_listen = normalized_listens[0]
        tls_cfg = primary_listen.get("tls", {})
        primary_port_hopping = normalize_port_hopping_cfg(
            primary_listen.get("port_hopping", {}),
            legacy_port_hopping_cfg,
        )
        primary_reality = normalize_endpoint_reality_config(
            primary_listen.get("reality", {}),
            role="server",
            fallback=reality_global,
            default_dest_when_empty=str(primary_listen.get("type", "tcp")).strip().lower() == "reality",
        )
        protocol_cfg = {
            "type": str(primary_listen.get("type", "tcp")),
            "tunnel_mode": tunnel_mode,
            "port": parse_port_from_address(primary_listen.get("address", ":8443"), 8443),
            "listen_host": parse_host_from_address(primary_listen.get("address", ":8443"), ""),
            "path": str(primary_listen.get("path", "/tunnel")),
            "port_hopping": primary_port_hopping,
            "network_mtu": network_mtu,
            "network_dns": deep_copy(network_dns),
            "utls_strict_profile_match": utls_strict_profile_match,
            "mux_type": mux_type,
            "mimicry_preset_region": mimicry_preset_region,
            "mimicry_profiles": deep_copy(mimicry_profiles),
            "mimicry_transport_mode": mimicry_transport_mode,
            "mimicry_auth_secret": mimicry_auth_secret,
            "mimicry_auth_window_seconds": mimicry_auth_window_seconds,
            "mimicry_basic_auth_user": mimicry_basic_auth_user,
            "mimicry_basic_auth_pass": mimicry_basic_auth_pass,
            "additional_endpoints": deep_copy(normalized_listens[1:]),
            "cert": str(tls_cfg.get("cert_file", "")),
            "key": str(tls_cfg.get("key_file", "")),
            "psk": psk,
            "dest": str(primary_reality.get("dest", "")),
            "server_names": primary_reality.get("server_names", []),
            "short_id": str(primary_reality.get("short_id", "")),
            "private_key": str(primary_reality.get("private_key", "")),
            "public_key": "",
            "generated_private_key": "",
            "reality_key_generated": False,
            "license": license_id,
            "service_restart_minutes": service_restart_minutes,
            "service_runtime_max_minutes": service_runtime_max_minutes,
            "profile": profile,
        }
        mappings = (
            server_cfg.get("mappings", [])
            if isinstance(server_cfg, dict)
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
        legacy_port_hopping_cfg = normalize_port_hopping_cfg(
            client.get("port_hopping", {}),
            {},
        )
        server_ep = client.get("server", {}) if isinstance(client.get("server"), dict) else {}
        servers = client.get("servers", [])
        if not isinstance(servers, list):
            servers = []
        reality_global = (
            parsed.get("reality", {}) if isinstance(parsed.get("reality"), dict) else {}
        )
        primary_fallback = normalize_transport_endpoint(
            server_ep,
            role="client",
            fallback_type="tcp",
            fallback_address="127.0.0.1:8443",
            fallback_path="/tunnel",
            fallback_reality=reality_global,
        )
        normalized_servers = []
        for ep in servers:
            if not isinstance(ep, dict):
                continue
            normalized_servers.append(
                normalize_transport_endpoint(
                    ep,
                    role="client",
                    fallback_type=primary_fallback["type"],
                    fallback_address=primary_fallback["address"],
                    fallback_path=primary_fallback["path"],
                    fallback_reality=reality_global,
                )
            )
        if not normalized_servers:
            normalized_servers = [primary_fallback]
        if (
            normalized_servers
            and has_port_hopping_cfg(legacy_port_hopping_cfg)
            and not has_port_hopping_cfg(normalized_servers[0].get("port_hopping", {}))
        ):
            normalized_servers[0]["port_hopping"] = normalize_port_hopping_cfg(
                legacy_port_hopping_cfg,
                {},
            )
        primary_server = normalized_servers[0]
        primary_addr = derive_client_address_from_endpoint(primary_server, "127.0.0.1:8443")
        tls_cfg = primary_server.get("tls", {})
        primary_port_hopping = normalize_port_hopping_cfg(
            primary_server.get("port_hopping", {}),
            legacy_port_hopping_cfg,
        )
        primary_reality = normalize_endpoint_reality_config(
            primary_server.get("reality", {}),
            role="client",
            fallback=reality_global,
            default_dest_when_empty=str(primary_server.get("type", "tcp")).strip().lower() == "reality",
        )
        try:
            pool_size = int(client.get("pool_size", 3) or 3)
        except (TypeError, ValueError):
            pool_size = 3
        if pool_size < 1:
            pool_size = 1
        protocol_cfg = {
            "type": str(primary_server.get("type", "tcp")),
            "tunnel_mode": tunnel_mode,
            "port": parse_port_from_address(primary_addr, 8443),
            "server_addr": parse_host_from_address(primary_addr, "127.0.0.1"),
            "pool_size": pool_size,
            "connection_strategy": normalize_connection_strategy(
                client.get("connection_strategy", "parallel"),
                "parallel",
            ),
            "path": str(primary_server.get("path", "/tunnel")),
            "port_hopping": primary_port_hopping,
            "network_mtu": network_mtu,
            "network_dns": deep_copy(network_dns),
            "utls_strict_profile_match": utls_strict_profile_match,
            "mux_type": mux_type,
            "mimicry_preset_region": mimicry_preset_region,
            "mimicry_profiles": deep_copy(mimicry_profiles),
            "mimicry_transport_mode": mimicry_transport_mode,
            "mimicry_auth_secret": mimicry_auth_secret,
            "mimicry_auth_window_seconds": mimicry_auth_window_seconds,
            "mimicry_basic_auth_user": mimicry_basic_auth_user,
            "mimicry_basic_auth_pass": mimicry_basic_auth_pass,
            "additional_endpoints": deep_copy(normalized_servers[1:]),
            "cert": "",
            "key": "",
            "psk": psk,
            "sni": str(tls_cfg.get("server_name", "")),
            "insecure_skip_verify": bool(tls_cfg.get("insecure_skip_verify", False)),
            "dest": str(primary_reality.get("dest", "")),
            "server_names": primary_reality.get("server_names", []),
            "short_id": str(primary_reality.get("short_id", "")),
            "private_key": "",
            "public_key": str(primary_reality.get("public_key", "")),
            "generated_private_key": "",
            "reality_key_generated": False,
            "license": license_id,
            "service_restart_minutes": service_restart_minutes,
            "service_runtime_max_minutes": service_runtime_max_minutes,
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

    explicit_tuning = any(
        section in parsed and isinstance(parsed.get(section), dict)
        for section in TUNING_SECTIONS
    )

    tuning = deep_copy(base_tuning(role))
    for section in TUNING_SECTIONS:
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
        "explicit_tuning": explicit_tuning,
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
        # Keep buffers moderate so backpressure kicks in before long one-way stalls.
        "max_receive_buffer": 4 * 1024 * 1024,
        "max_stream_buffer": 1024 * 1024,
    }
    return {
        "smux": smux_values,
        "tcp": {
            "no_delay": True,
            "keepalive": "15s",
            "read_buffer": 8388608,
            "write_buffer": 8388608,
            "conn_limit": 5000,
            "copy_buffer": 262144,
            "target_dial_pool": 2,
            "max_seg": 0,
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
    for section in TUNING_SECTIONS:
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


def resolve_http_mimicry_state(protocol_config, endpoints):
    # Enable mimicry if any configured endpoint uses mimicry transport.
    if not isinstance(endpoints, list):
        endpoints = []
    for ep in endpoints:
        if not isinstance(ep, dict):
            continue
        ep_type = normalize_endpoint_type(ep.get("type", "tcp"), "tcp")
        if ep_type in {"httpmimicry", "httpsmimicry"}:
            return True
    return False


def build_http_mimicry_profiles(preset_region="mixed"):
    preset_region = normalize_mimicry_preset_region(preset_region, "mixed")

    combined_profiles = {
        "zoomg_articles": {
            "path": "/",
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
                "Sec-Fetch-Site": "same-origin",
                "Cache-Control": "max-age=0",
            },
        },
        "linode_docs": {
            "path": "/docs/",
            "browser": "chrome",
            "fake_host": "www.linode.com",
            "cookie_enabled": True,
            "chunked_encoding": False,
            "custom_headers": {
                "Referer": "https://www.linode.com/docs/",
                "Sec-Fetch-Site": "same-origin",
                "Cache-Control": "max-age=0",
            },
        },
        "gnu_manuals": {
            "path": "/software/",
            "browser": "firefox",
            "fake_host": "www.gnu.org",
            "cookie_enabled": True,
            "chunked_encoding": False,
            "custom_headers": {
                "Referer": "https://www.gnu.org/software/",
                "Sec-Fetch-Site": "same-origin",
                "Cache-Control": "max-age=0",
            },
        },
    }

    iran_profile_names = {
        "zoomg_articles",
        "virgool_read",
        "hamyarwp_blog",
        "rasaneh3_feed",
        "mizbanfa_docs",
    }

    ordered_names = list(combined_profiles.keys())
    if preset_region == "iran":
        selected_names = [name for name in ordered_names if name in iran_profile_names]
    elif preset_region == "foreign":
        selected_names = [name for name in ordered_names if name not in iran_profile_names]
    else:
        selected_names = ordered_names

    if not selected_names:
        selected_names = ["zoomg_articles"]

    return {name: combined_profiles[name] for name in selected_names}


def normalize_http_mimicry_profiles_for_render(raw_profiles):
    if not isinstance(raw_profiles, dict):
        return {}
    out = {}
    for name, profile in raw_profiles.items():
        if not isinstance(profile, dict):
            continue
        key = str(name).strip()
        if not key:
            continue
        out[key] = {
            "path": normalize_path(profile.get("path", "/"), "/"),
            "browser": str(profile.get("browser", "chrome")).strip() or "chrome",
            "fake_host": str(profile.get("fake_host", "www.zoomg.ir")).strip() or "www.zoomg.ir",
            "cookie_enabled": bool(profile.get("cookie_enabled", True)),
            "chunked_encoding": bool(profile.get("chunked_encoding", False)),
            "custom_headers": profile.get("custom_headers", {}) if isinstance(profile.get("custom_headers", {}), dict) else {},
        }
    return out


def render_http_mimicry_lines(protocol_config, enabled=False):
    preset_region = normalize_mimicry_preset_region(protocol_config.get("mimicry_preset_region", "mixed"), "mixed")
    mimicry_transport_mode = normalize_mimicry_transport_mode(
        protocol_config.get("mimicry_transport_mode", "websocket"),
        "websocket",
    )
    mimicry_auth_secret = str(protocol_config.get("mimicry_auth_secret", "")).strip()
    mimicry_basic_auth_user = str(protocol_config.get("mimicry_basic_auth_user", "")).strip()
    mimicry_basic_auth_pass = str(protocol_config.get("mimicry_basic_auth_pass", "")).strip()
    try:
        mimicry_auth_window_seconds = int(protocol_config.get("mimicry_auth_window_seconds", 60) or 60)
    except (TypeError, ValueError):
        mimicry_auth_window_seconds = 60
    if mimicry_auth_window_seconds <= 0:
        mimicry_auth_window_seconds = 60

    profiles = normalize_http_mimicry_profiles_for_render(protocol_config.get("mimicry_profiles", {}))
    if not profiles:
        profiles = build_http_mimicry_profiles(preset_region)
    primary_profile = next(iter(profiles.values()))
    lines = [
        "http_mimicry:",
        f"  enabled: {yaml_scalar(enabled)}",
        f"  preset_region: {yaml_scalar(preset_region)}",
        f"  transport_mode: {yaml_scalar(mimicry_transport_mode)}",
        f"  auth_secret: {yaml_scalar(mimicry_auth_secret)}",
        f"  auth_window_seconds: {yaml_scalar(mimicry_auth_window_seconds)}",
        f"  basic_auth_user: {yaml_scalar(mimicry_basic_auth_user)}",
        f"  basic_auth_pass: {yaml_scalar(mimicry_basic_auth_pass)}",
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


def build_primary_endpoint_reality(role, protocol_config, endpoint_type=""):
    if normalize_endpoint_type(endpoint_type, "tcp") != "reality":
        return {}
    cfg = protocol_config if isinstance(protocol_config, dict) else {}
    return normalize_endpoint_reality_config(
        {
            "dest": cfg.get("dest", ""),
            "server_names": cfg.get("server_names", []),
            "short_id": cfg.get("short_id", ""),
            "private_key": cfg.get("private_key", ""),
            "public_key": cfg.get("public_key", ""),
        },
        role=role,
        default_dest_when_empty=True,
    )


def build_server_primary_endpoint(protocol_config):
    endpoint_type = normalize_endpoint_type(protocol_config.get("type", "tcp"), "tcp")
    path_default = default_path_for_transport(endpoint_type)
    path = normalize_path(protocol_config.get("path", path_default), path_default)
    listen_host = str(protocol_config.get("listen_host", "")).strip()
    if listen_host:
        address = f"{listen_host}:{protocol_config.get('port', 8443)}"
    else:
        address = f":{protocol_config.get('port', 8443)}"
    port_hopping_cfg = normalize_port_hopping_cfg(protocol_config.get("port_hopping", {}), {})
    return normalize_transport_endpoint(
        {
            "type": endpoint_type,
            "address": address,
            "url": "",
            "path": path,
            "port_hopping": port_hopping_cfg,
            "tls": {
                "cert_file": protocol_config.get("cert", ""),
                "key_file": protocol_config.get("key", ""),
                "ca_file": "",
                "server_name": "",
                "insecure_skip_verify": False,
                "require_client_cert": False,
            },
            "reality": build_primary_endpoint_reality("server", protocol_config, endpoint_type),
        },
        role="server",
        fallback_type=endpoint_type,
        fallback_address=address,
        fallback_path=path,
        fallback_reality=build_primary_endpoint_reality("server", protocol_config, endpoint_type),
        fallback_port_hopping=port_hopping_cfg,
    )


def build_client_primary_endpoint(protocol_config):
    endpoint_type = normalize_endpoint_type(protocol_config.get("type", "tcp"), "tcp")
    path_default = default_path_for_transport(endpoint_type)
    path = normalize_path(protocol_config.get("path", path_default), path_default)
    server_addr = str(protocol_config.get("server_addr", "127.0.0.1")).strip() or "127.0.0.1"
    address = f"{server_addr}:{protocol_config.get('port', 8443)}"
    url = ""
    if endpoint_type in {"ws", "wss"}:
        url = resolve_ws_url({"type": endpoint_type}, address, path)
    port_hopping_cfg = normalize_port_hopping_cfg(protocol_config.get("port_hopping", {}), {})
    return normalize_transport_endpoint(
        {
            "type": endpoint_type,
            "address": address,
            "url": url,
            "path": path,
            "port_hopping": port_hopping_cfg,
            "tls": {
                "cert_file": "",
                "key_file": "",
                "ca_file": "",
                "server_name": protocol_config.get("sni", ""),
                "insecure_skip_verify": bool(protocol_config.get("insecure_skip_verify", False)),
                "require_client_cert": False,
            },
            "reality": build_primary_endpoint_reality("client", protocol_config, endpoint_type),
        },
        role="client",
        fallback_type=endpoint_type,
        fallback_address=address,
        fallback_path=path,
        fallback_reality=build_primary_endpoint_reality("client", protocol_config, endpoint_type),
        fallback_port_hopping=port_hopping_cfg,
    )


def build_all_endpoints_for_render(role, protocol_config, primary_endpoint):
    out = [primary_endpoint]
    extra = protocol_config.get("additional_endpoints", [])
    if not isinstance(extra, list):
        return out
    for ep in extra:
        if not isinstance(ep, dict):
            continue
        normalized = normalize_transport_endpoint(
            ep,
            role=role,
            fallback_type=primary_endpoint["type"],
            fallback_address=primary_endpoint["address"],
            fallback_path=primary_endpoint["path"],
            fallback_reality=primary_endpoint.get("reality", {}),
        )
        if role == "client" and normalized["type"] in {"ws", "wss"} and not normalized["url"]:
            normalized["url"] = resolve_ws_url(
                {"type": normalized["type"]},
                normalized["address"],
                normalized["path"],
            )
        out.append(normalized)
    return out


def collect_render_endpoints(role, protocol_config):
    if role == "server":
        primary = build_server_primary_endpoint(protocol_config)
    else:
        primary = build_client_primary_endpoint(protocol_config)
    return build_all_endpoints_for_render(role, protocol_config, primary)


def format_endpoint_summary(endpoint):
    ep_type = str(endpoint.get("type", "tcp"))
    address = str(endpoint.get("address", ""))
    path = str(endpoint.get("path", "/tunnel"))
    url = str(endpoint.get("url", "")).strip()
    summary = f"{ep_type}://{address} path={path}"
    if url:
        summary += f" url={url}"
    return summary


def render_port_hopping_lines(indent, port_hopping_cfg):
    cfg = normalize_port_hopping_cfg(port_hopping_cfg, {})
    if not has_port_hopping_cfg(cfg):
        return []
    return [
        f"{indent}port_hopping:",
        f"{indent}  enabled: {yaml_scalar(bool(cfg.get('enabled', False)))}",
        f"{indent}  start_port: {yaml_scalar(int(cfg.get('start_port', 0) or 0))}",
        f"{indent}  end_port: {yaml_scalar(int(cfg.get('end_port', 0) or 0))}",
        f"{indent}  ports: {json.dumps(normalize_port_hopping_ports(cfg.get('ports', [])))}",
        f"{indent}  mode: {yaml_scalar(normalize_port_hopping_mode(cfg.get('mode', 'spread')))}",
        f"{indent}  count: {yaml_scalar(max(0, int(cfg.get('count', 0) or 0)))}",
    ]


def render_named_transport_endpoint_lines(
    indent,
    key_name,
    endpoint,
    include_require_client_cert=False,
):
    ep_type = normalize_endpoint_type(endpoint.get("type", "tcp"), "tcp")
    tls_cfg = endpoint.get("tls", {}) if isinstance(endpoint.get("tls"), dict) else {}
    reality_cfg = (
        endpoint.get("reality", {}) if isinstance(endpoint.get("reality"), dict) else {}
    )
    include_tls = endpoint_uses_tls(ep_type)
    include_reality = ep_type == "reality"
    lines = [
        f"{indent}{key_name}:",
        f"{indent}  type: {yaml_scalar(ep_type)}",
        f"{indent}  address: {yaml_scalar(endpoint.get('address', ''))}",
        f"{indent}  url: {yaml_scalar(endpoint.get('url', ''))}",
        f"{indent}  path: {yaml_scalar(endpoint.get('path', '/tunnel'))}",
    ]
    lines.extend(render_port_hopping_lines(f"{indent}  ", endpoint.get("port_hopping", {})))
    if include_tls:
        lines.extend(
            [
                f"{indent}  tls:",
                f"{indent}    cert_file: {yaml_scalar(tls_cfg.get('cert_file', ''))}",
                f"{indent}    key_file: {yaml_scalar(tls_cfg.get('key_file', ''))}",
                f"{indent}    ca_file: {yaml_scalar(tls_cfg.get('ca_file', ''))}",
                f"{indent}    server_name: {yaml_scalar(tls_cfg.get('server_name', ''))}",
                f"{indent}    insecure_skip_verify: {yaml_scalar(bool(tls_cfg.get('insecure_skip_verify', False)))}",
            ]
        )
    if include_tls and include_require_client_cert:
        lines.append(
            f"{indent}    require_client_cert: {yaml_scalar(bool(tls_cfg.get('require_client_cert', False)))}"
        )
    if include_reality:
        lines.extend(
            [
                f"{indent}  reality:",
                f"{indent}    dest: {yaml_scalar(reality_cfg.get('dest', ''))}",
                f"{indent}    server_names: {json.dumps(normalize_server_names_list(reality_cfg.get('server_names', [])))}",
                f"{indent}    short_id: {yaml_scalar(reality_cfg.get('short_id', ''))}",
                f"{indent}    private_key: {yaml_scalar(reality_cfg.get('private_key', ''))}",
                f"{indent}    public_key: {yaml_scalar(reality_cfg.get('public_key', ''))}",
            ]
        )
    return lines


def render_transport_endpoints_list_lines(
    indent,
    key_name,
    endpoints,
    include_require_client_cert=False,
):
    if not endpoints:
        return [f"{indent}{key_name}: []"]
    lines = [f"{indent}{key_name}:"]
    for endpoint in endpoints:
        ep_type = normalize_endpoint_type(endpoint.get("type", "tcp"), "tcp")
        tls_cfg = endpoint.get("tls", {}) if isinstance(endpoint.get("tls"), dict) else {}
        reality_cfg = (
            endpoint.get("reality", {}) if isinstance(endpoint.get("reality"), dict) else {}
        )
        include_tls = endpoint_uses_tls(ep_type)
        include_reality = ep_type == "reality"
        lines.extend(
            [
                f"{indent}  - type: {yaml_scalar(ep_type)}",
                f"{indent}    address: {yaml_scalar(endpoint.get('address', ''))}",
                f"{indent}    url: {yaml_scalar(endpoint.get('url', ''))}",
                f"{indent}    path: {yaml_scalar(endpoint.get('path', '/tunnel'))}",
            ]
        )
        lines.extend(render_port_hopping_lines(f"{indent}    ", endpoint.get("port_hopping", {})))
        if include_tls:
            lines.extend(
                [
                    f"{indent}    tls:",
                    f"{indent}      cert_file: {yaml_scalar(tls_cfg.get('cert_file', ''))}",
                    f"{indent}      key_file: {yaml_scalar(tls_cfg.get('key_file', ''))}",
                    f"{indent}      ca_file: {yaml_scalar(tls_cfg.get('ca_file', ''))}",
                    f"{indent}      server_name: {yaml_scalar(tls_cfg.get('server_name', ''))}",
                    f"{indent}      insecure_skip_verify: {yaml_scalar(bool(tls_cfg.get('insecure_skip_verify', False)))}",
                ]
            )
        if include_tls and include_require_client_cert:
            lines.append(
                f"{indent}      require_client_cert: {yaml_scalar(bool(tls_cfg.get('require_client_cert', False)))}"
            )
        if include_reality:
            lines.extend(
                [
                    f"{indent}    reality:",
                    f"{indent}      dest: {yaml_scalar(reality_cfg.get('dest', ''))}",
                    f"{indent}      server_names: {json.dumps(normalize_server_names_list(reality_cfg.get('server_names', [])))}",
                    f"{indent}      short_id: {yaml_scalar(reality_cfg.get('short_id', ''))}",
                    f"{indent}      private_key: {yaml_scalar(reality_cfg.get('private_key', ''))}",
                    f"{indent}      public_key: {yaml_scalar(reality_cfg.get('public_key', ''))}",
                ]
            )
    return lines


def build_server_config_text(protocol_config, tuning, obfuscation_cfg):
    if not os.path.exists(CONFIG_DIR):
        os.makedirs(CONFIG_DIR)

    primary_endpoint = build_server_primary_endpoint(protocol_config)
    all_listens = build_all_endpoints_for_render("server", protocol_config, primary_endpoint)
    mimicry_enabled = resolve_http_mimicry_state(protocol_config, all_listens)
    network_mtu = normalize_network_mtu(protocol_config.get("network_mtu", 0), 0)
    network_dns = normalize_dns_config(protocol_config.get("network_dns", {}), {})
    utls_strict_profile_match = bool(protocol_config.get("utls_strict_profile_match", True))
    reality_enabled = any(
        normalize_endpoint_type(ep.get("type", "tcp"), "tcp") == "reality"
        for ep in all_listens
        if isinstance(ep, dict)
    )
    reality_cfg_source = {}
    for ep in all_listens:
        if not isinstance(ep, dict):
            continue
        if normalize_endpoint_type(ep.get("type", "tcp"), "tcp") != "reality":
            continue
        if isinstance(ep.get("reality"), dict):
            reality_cfg_source = ep["reality"]
            break
    reality_cfg = normalize_endpoint_reality_config(
        reality_cfg_source,
        role="server",
        fallback={
            "dest": protocol_config.get("dest", ""),
            "server_names": protocol_config.get("server_names", []),
            "short_id": protocol_config.get("short_id", ""),
            "private_key": protocol_config.get("private_key", ""),
            "public_key": "",
        },
        default_dest_when_empty=reality_enabled,
    )
    reality_dest = reality_cfg.get("dest", "")
    reality_server_names = reality_cfg.get("server_names", [])
    reality_short_id = reality_cfg.get("short_id", "")
    reality_private_key = reality_cfg.get("private_key", "")
    mux_type = normalize_mux_type(protocol_config.get("mux_type", "smux"), "smux")
    lines = [
        "mode: server",
        f"tunnel_mode: {yaml_scalar(protocol_config.get('tunnel_mode', 'reverse'))}",
        f"profile: {yaml_scalar(protocol_config.get('profile', 'balanced'))}",
        "",
        "server:",
    ]
    lines.extend(
        render_transport_endpoints_list_lines(
            "  ",
            "listens",
            all_listens,
            include_require_client_cert=True,
        )
    )
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
            "mux:",
            f"  type: {yaml_scalar(mux_type)}",
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
            f"  target_dial_pool: {yaml_scalar(tuning['tcp']['target_dial_pool'])}",
            f"  max_seg: {yaml_scalar(tuning['tcp']['max_seg'])}",
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
            "  dns:",
            f"    mode: {yaml_scalar(network_dns['mode'])}",
            f"    doh_endpoints: {json.dumps(network_dns['doh_endpoints'])}",
            f"    dot_servers: {json.dumps(network_dns['dot_servers'])}",
            f"    query_timeout: {yaml_scalar(network_dns['query_timeout'])}",
            f"    cache_ttl: {yaml_scalar(network_dns['cache_ttl'])}",
            f"    max_inflight: {yaml_scalar(network_dns['max_inflight'])}",
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
    lines.extend(render_http_mimicry_lines(protocol_config, enabled=mimicry_enabled))
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
            f"  strict_profile_match: {yaml_scalar(utls_strict_profile_match)}",
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

    primary_endpoint = build_client_primary_endpoint(protocol_config)
    all_servers = build_all_endpoints_for_render("client", protocol_config, primary_endpoint)
    mimicry_enabled = resolve_http_mimicry_state(protocol_config, all_servers)
    network_mtu = normalize_network_mtu(protocol_config.get("network_mtu", 0), 0)
    network_dns = normalize_dns_config(protocol_config.get("network_dns", {}), {})
    utls_strict_profile_match = bool(protocol_config.get("utls_strict_profile_match", True))
    connection_strategy = normalize_connection_strategy(
        protocol_config.get("connection_strategy", "parallel"),
        "parallel",
    )
    reality_enabled = any(
        normalize_endpoint_type(ep.get("type", "tcp"), "tcp") == "reality"
        for ep in all_servers
        if isinstance(ep, dict)
    )
    reality_cfg_source = {}
    for ep in all_servers:
        if not isinstance(ep, dict):
            continue
        if normalize_endpoint_type(ep.get("type", "tcp"), "tcp") != "reality":
            continue
        if isinstance(ep.get("reality"), dict):
            reality_cfg_source = ep["reality"]
            break
    reality_cfg = normalize_endpoint_reality_config(
        reality_cfg_source,
        role="client",
        fallback={
            "dest": protocol_config.get("dest", ""),
            "server_names": protocol_config.get("server_names", []),
            "short_id": protocol_config.get("short_id", ""),
            "private_key": "",
            "public_key": protocol_config.get("public_key", ""),
        },
        default_dest_when_empty=reality_enabled,
    )
    reality_dest = reality_cfg.get("dest", "")
    reality_server_names = reality_cfg.get("server_names", [])
    reality_short_id = reality_cfg.get("short_id", "")
    reality_public_key = reality_cfg.get("public_key", "")
    mux_type = normalize_mux_type(protocol_config.get("mux_type", "smux"), "smux")
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
        f"  connection_strategy: {yaml_scalar(connection_strategy)}",
    ]
    lines.extend(render_transport_endpoints_list_lines("  ", "servers", all_servers))
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
        "mux:",
        f"  type: {yaml_scalar(mux_type)}",
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
        f"  target_dial_pool: {yaml_scalar(tuning['tcp']['target_dial_pool'])}",
        f"  max_seg: {yaml_scalar(tuning['tcp']['max_seg'])}",
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
            "  dns:",
            f"    mode: {yaml_scalar(network_dns['mode'])}",
            f"    doh_endpoints: {json.dumps(network_dns['doh_endpoints'])}",
            f"    dot_servers: {json.dumps(network_dns['dot_servers'])}",
            f"    query_timeout: {yaml_scalar(network_dns['query_timeout'])}",
            f"    cache_ttl: {yaml_scalar(network_dns['cache_ttl'])}",
            f"    max_inflight: {yaml_scalar(network_dns['max_inflight'])}",
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
    lines.extend(render_http_mimicry_lines(protocol_config, enabled=mimicry_enabled))
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
            f"  strict_profile_match: {yaml_scalar(utls_strict_profile_match)}",
            "",
            "reality:",
            f"  enabled: {yaml_scalar(reality_enabled)}",
            f"  dest: {yaml_scalar(reality_dest)}",
            f"  server_names: {json.dumps(reality_server_names)}",
            f"  short_id: {yaml_scalar(reality_short_id)}",
            '  private_key: ""',
            f"  public_key: {yaml_scalar(reality_public_key)}",
            "",
            f"license: {yaml_scalar(protocol_config.get('license', ''))}",
        ]
    )
    return "\n".join(lines) + "\n"


def strip_top_level_sections(config_text, section_names):
    if not section_names:
        return config_text

    lines = config_text.splitlines()
    out = []
    skip_section = None

    for line in lines:
        stripped = line.strip()
        is_top_level = bool(stripped) and not line.startswith((" ", "\t")) and ":" in stripped
        if is_top_level:
            key = stripped.split(":", 1)[0].strip()
            if skip_section and key not in section_names:
                skip_section = None
            if key in section_names:
                skip_section = key
                continue
        if skip_section:
            continue
        out.append(line)

    compact = []
    prev_blank = False
    for line in out:
        blank = line.strip() == ""
        if blank and prev_blank:
            continue
        compact.append(line)
        prev_blank = blank

    return "\n".join(compact).rstrip() + "\n"


def generate_config(protocol_config, tuning, obfuscation_cfg, config_filename, explicit_tuning=False):
    config_path = os.path.join(CONFIG_DIR, config_filename)
    final_content = build_server_config_text(protocol_config, tuning, obfuscation_cfg)
    if not explicit_tuning:
        final_content = strip_top_level_sections(final_content, set(TUNING_SECTIONS))
    with open(config_path, "w") as f:
        f.write(final_content)
    print_success(f"💾 Configuration generated at {config_path}")
    return config_path


def generate_client_config(protocol_config, tuning, obfuscation_cfg, config_filename, explicit_tuning=False):
    config_path = os.path.join(CONFIG_DIR, config_filename)
    final_content = build_client_config_text(protocol_config, tuning, obfuscation_cfg)
    if not explicit_tuning:
        final_content = strip_top_level_sections(final_content, set(TUNING_SECTIONS))
    with open(config_path, "w") as f:
        f.write(final_content)
    print_success(f"💾 Client Configuration generated at {config_path}")
    return config_path


def render_service_restart_lines(restart_minutes):
    _ = normalize_service_restart_minutes(
        restart_minutes, DEFAULT_SERVICE_RESTART_MINUTES
    )
    return f"Restart=always\nRestartSec={DEFAULT_SERVICE_RESTART_SECONDS}"


def render_service_runtime_max_lines(runtime_max_minutes):
    runtime_max_minutes = normalize_service_runtime_max_minutes(
        runtime_max_minutes, DEFAULT_SERVICE_RUNTIME_MAX_MINUTES
    )
    if runtime_max_minutes <= 0:
        return "RuntimeMaxSec=infinity"
    return f"RuntimeMaxSec={runtime_max_minutes * 60}"


def create_service(role, instance="default", restart_minutes=0, runtime_max_minutes=0):
    restart_minutes = normalize_service_restart_minutes(
        restart_minutes, DEFAULT_SERVICE_RESTART_MINUTES
    )
    runtime_max_minutes = normalize_service_runtime_max_minutes(
        runtime_max_minutes, DEFAULT_SERVICE_RUNTIME_MAX_MINUTES
    )
    restart_lines = render_service_restart_lines(restart_minutes)
    runtime_max_lines = render_service_runtime_max_lines(runtime_max_minutes)
    restart_label = f"always ({DEFAULT_SERVICE_RESTART_SECONDS}s)"
    runtime_max_label = (
        "disabled"
        if runtime_max_minutes == 0
        else f"{runtime_max_minutes} minute(s)"
    )
    profile = SERVICE_PROFILES[role]
    service_name = build_service_name(role, instance)
    service_path = service_file_path(service_name)
    config_path = os.path.join(CONFIG_DIR, build_config_filename(role, instance))
    exec_start = f"{os.path.join(INSTALL_DIR, BINARY_NAME)} {profile['mode']} -c {config_path}"
    description = profile["description"] if instance == "default" else f"{profile['description']} [{instance}]"
    env_lines = "\n".join(
        f'Environment="{key}={value}"'
        for key, value in SYSTEMD_RUNTIME_ENV.items()
    )
    content = f"""[Unit]
Description={description}
After=network.target

[Service]
Type=simple
User=root
{env_lines}
ExecStart={exec_start}
{restart_lines}
{runtime_max_lines}
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
    print_success(
        f"✅ Systemd service installed and started: {service_name}.service "
        f"(auto-restart: {restart_label}, runtime-max: {runtime_max_label})"
    )


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
    for section in TUNING_SECTIONS:
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
    explicit_tuning = bool(loaded.get("explicit_tuning", False))
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
            f"MUX:         {protocol_cfg.get('mux_type', 'smux')}",
            f"TunnelMode:  {protocol_cfg.get('tunnel_mode', 'reverse')}",
            f"Profile:     {protocol_cfg.get('profile', 'balanced')}",
            f"Obfuscation: {'enabled' if obfuscation_cfg.get('enabled') else 'disabled'}",
            (
                f"AutoRestart: always ({DEFAULT_SERVICE_RESTART_SECONDS}s)"
            ),
            (
                f"RuntimeMax: {normalize_service_runtime_max_minutes(protocol_cfg.get('service_runtime_max_minutes', 0), 0)} min (0=off)"
            ),
        ]
        if role == "server":
            menu_lines.append(f"Mappings:    {len(protocol_cfg.get('mappings', []))}")
            menu_lines.append(f"Extra EPs:   {len(protocol_cfg.get('additional_endpoints', []))}")
        else:
            menu_lines.append(
                f"Server:      {protocol_cfg.get('server_addr')}:{protocol_cfg.get('port')}"
            )
            menu_lines.append(
                f"Strategy:    {protocol_cfg.get('connection_strategy', 'parallel')}"
            )
            menu_lines.append(f"Extra EPs:   {len(protocol_cfg.get('additional_endpoints', []))}")
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
                    "7. Edit service runtime max",
                    "8. Save changes and restart service",
                    "0. Cancel",
                ]
            )
        elif client_direct_mode:
            menu_lines.extend(
                [
                    "4. Edit port mappings",
                    "5. Edit advanced tuning",
                    "6. Edit license ID",
                    "7. Edit service runtime max",
                    "8. Save changes and restart service",
                    "0. Cancel",
                ]
            )
        else:
            menu_lines.extend(
                [
                    "4. Edit advanced tuning",
                    "5. Edit license ID",
                    "6. Edit service runtime max",
                    "7. Save changes and restart service",
                    "0. Cancel",
                ]
            )
        print_menu(f"✏️ Edit Tunnel: {service_name}.service", menu_lines, color=Colors.CYAN, min_width=62)

        choice = input("Select option: ").strip()

        if choice == "1":
            if role == "client":
                current_port = protocol_cfg.get("port", DEFAULT_KHAREJ_PORT)
                try:
                    current_port = int(current_port)
                except (TypeError, ValueError):
                    current_port = DEFAULT_KHAREJ_PORT
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
                prompt_port=(role != "client"),
                deployment_mode="advanced" if explicit_tuning else "default",
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
            protocol_cfg["service_restart_minutes"] = normalize_service_restart_minutes(
                protocol_cfg.get("service_restart_minutes", loaded["protocol_config"].get("service_restart_minutes", 0)),
                loaded["protocol_config"].get("service_restart_minutes", 0),
            )
            protocol_cfg["service_runtime_max_minutes"] = normalize_service_runtime_max_minutes(
                protocol_cfg.get("service_runtime_max_minutes", loaded["protocol_config"].get("service_runtime_max_minutes", 0)),
                loaded["protocol_config"].get("service_runtime_max_minutes", 0),
            )
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
            explicit_tuning = True
        elif (choice == "6" and role == "server") or (choice == "6" and client_direct_mode) or (choice == "5" and role == "client" and not client_direct_mode):
            protocol_cfg["license"] = prompt_license_id()
        elif (choice == "7" and role == "server") or (choice == "7" and client_direct_mode) or (choice == "6" and role == "client" and not client_direct_mode):
            protocol_cfg["service_runtime_max_minutes"] = prompt_service_runtime_max_minutes(
                default_minutes=protocol_cfg.get("service_runtime_max_minutes", 0)
            )
        elif (choice == "8" and role == "server") or (choice == "8" and client_direct_mode) or (choice == "7" and role == "client" and not client_direct_mode):
            config_file = build_config_filename(role, instance)
            restart_minutes = protocol_cfg.get("service_restart_minutes", DEFAULT_SERVICE_RESTART_MINUTES)
            runtime_max_minutes = protocol_cfg.get(
                "service_runtime_max_minutes", DEFAULT_SERVICE_RUNTIME_MAX_MINUTES
            )
            if role == "server":
                generate_config(
                    protocol_cfg,
                    tuning,
                    obfuscation_cfg,
                    config_file,
                    explicit_tuning=explicit_tuning,
                )
            else:
                generate_client_config(
                    protocol_cfg,
                    tuning,
                    obfuscation_cfg,
                    config_file,
                    explicit_tuning=explicit_tuning,
                )
            create_service(
                role,
                instance,
                restart_minutes=restart_minutes,
                runtime_max_minutes=runtime_max_minutes,
            )
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
    deployment_mode = select_deployment_mode()
    cfg = menu_protocol(
        "server",
        defaults={"port": DEFAULT_IRAN_PORT},
        deployment_mode=deployment_mode,
    )
    cfg["tunnel_mode"] = tunnel_mode
    cfg["license"] = prompt_license_id()
    cfg["profile"] = select_config_profile()
    tuning = configure_tuning("server", deployment_mode)
    obfuscation_cfg = select_obfuscation_profile()
    cfg["service_restart_minutes"] = prompt_service_restart_minutes(
        default_minutes=DEFAULT_SERVICE_RESTART_MINUTES
    )
    cfg["service_runtime_max_minutes"] = prompt_service_runtime_max_minutes(
        default_minutes=DEFAULT_SERVICE_RUNTIME_MAX_MINUTES
    )
    if collect_mappings:
        cfg["mappings"] = prompt_server_mappings(
            fixed_mode=mapping_mode,
            bind_side_label=bind_side_label,
            target_side_label=target_side_label,
        )
    else:
        cfg["mappings"] = []
    config_file = build_config_filename("server", instance)
    config_path = generate_config(
        cfg,
        tuning,
        obfuscation_cfg,
        config_file,
        explicit_tuning=(deployment_mode == "advanced"),
    )
    create_service(
        "server",
        instance,
        restart_minutes=cfg.get("service_restart_minutes", 0),
        runtime_max_minutes=cfg.get("service_runtime_max_minutes", 0),
    )
    maybe_apply_linux_network_tuning()

    all_listens = collect_render_endpoints("server", cfg)

    print_header("🎉 Server Installation Complete")
    print(f"Instance: {Colors.BOLD}{instance}{Colors.ENDC}")
    print(f"Tunnel:   {Colors.BOLD}{tunnel_label}{Colors.ENDC}")
    print(f"Location: {Colors.BOLD}{server_location_label}{Colors.ENDC}")
    print(f"Config:   {Colors.BOLD}{config_path}{Colors.ENDC}")
    psk_text = cfg["psk"] if cfg["psk"] else "(disabled)"
    print(f"PSK:      {Colors.BOLD}{psk_text}{Colors.ENDC}")
    print(f"Listens:  {Colors.BOLD}{len(all_listens)} endpoint(s){Colors.ENDC}")
    for ep in all_listens:
        print(f"  - {format_endpoint_summary(ep)}")
    print(f"Path MTU: {Colors.BOLD}{cfg.get('network_mtu', 0)}{Colors.ENDC}")
    print(f"MUX:      {Colors.BOLD}{cfg.get('mux_type', 'smux')}{Colors.ENDC}")
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
    server_addr, server_port = prompt_client_destination("1.2.3.4", DEFAULT_KHAREJ_PORT)
    run_direct_test = input_default(
        "Run direct connectivity benchmark before tunnel setup? (Y/n)",
        "y",
    ).strip().lower()
    if run_direct_test in {"y", "yes"}:
        print_info(
            "Tip: Run this on remote server first to listen for test traffic: "
            f"`iperf3 -s -p {IPERF_TEST_DEFAULT_PORT}`"
        )
        direct_connectivity_test_menu(default_host=server_addr)
    deployment_mode = select_deployment_mode()
    cfg = menu_protocol(
        "client",
        server_addr=server_addr,
        defaults={"server_addr": server_addr, "port": server_port},
        prompt_port=False,
        deployment_mode=deployment_mode,
    )
    cfg["tunnel_mode"] = tunnel_mode
    cfg["license"] = ""
    cfg["profile"] = select_config_profile()
    tuning = configure_tuning("client", deployment_mode)
    obfuscation_cfg = select_obfuscation_profile()
    cfg["service_restart_minutes"] = prompt_service_restart_minutes(
        default_minutes=DEFAULT_SERVICE_RESTART_MINUTES
    )
    cfg["service_runtime_max_minutes"] = prompt_service_runtime_max_minutes(
        default_minutes=DEFAULT_SERVICE_RUNTIME_MAX_MINUTES
    )
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
    config_path = generate_client_config(
        cfg,
        tuning,
        obfuscation_cfg,
        config_file,
        explicit_tuning=(deployment_mode == "advanced"),
    )
    create_service(
        "client",
        instance,
        restart_minutes=cfg.get("service_restart_minutes", 0),
        runtime_max_minutes=cfg.get("service_runtime_max_minutes", 0),
    )
    maybe_apply_linux_network_tuning()

    all_servers = collect_render_endpoints("client", cfg)

    print_header("✅ Client Installation Complete")
    print(f"Instance:   {Colors.BOLD}{instance}{Colors.ENDC}")
    print(f"Tunnel:     {Colors.BOLD}{tunnel_label}{Colors.ENDC}")
    print(f"Location:   {Colors.BOLD}{client_location_label}{Colors.ENDC}")
    print(f"Config:     {Colors.BOLD}{config_path}{Colors.ENDC}")
    print(f"Run command: {Colors.BOLD}nodelay client -c {config_path}{Colors.ENDC}")
    print(f"Profile:    {Colors.BOLD}{cfg['profile']}{Colors.ENDC}")
    print(f"Pool Size:  {Colors.BOLD}{cfg.get('pool_size', 3)}{Colors.ENDC}")
    print(f"Strategy:   {Colors.BOLD}{cfg.get('connection_strategy', 'parallel')}{Colors.ENDC}")
    print(f"Upstreams:  {Colors.BOLD}{len(all_servers)} endpoint(s){Colors.ENDC}")
    for ep in all_servers:
        print(f"  - {format_endpoint_summary(ep)}")
    print(f"Path MTU:   {Colors.BOLD}{cfg.get('network_mtu', 0)}{Colors.ENDC}")
    print(f"MUX:        {Colors.BOLD}{cfg.get('mux_type', 'smux')}{Colors.ENDC}")
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
                f"{Colors.CYAN}[4]{Colors.ENDC} 📊 Monitor / Logs / Service Control",
                f"{Colors.CYAN}[5]{Colors.ENDC} 🧩 Multi Tunnel Management",
                f"{Colors.CYAN}[6]{Colors.ENDC} ⚙️ Linux Optimization",
                f"{Colors.CYAN}[7]{Colors.ENDC} 🌐 Direct Connectivity Test (iperf3)",
                f"{Colors.CYAN}[8]{Colors.ENDC} 🧷 Install nodelay-manager alias",
                f"{Colors.CYAN}[9]{Colors.ENDC} ⬆️ Update nodelay-manager script",
                f"{Colors.CYAN}[10]{Colors.ENDC} 🗑️  Uninstall",
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
            check_root()
            service_control_menu()

        elif choice == "5":
            check_root()
            multi_tunnel_menu()

        elif choice == "6":
            check_root()
            maybe_apply_linux_network_tuning()
            input("\nPress Enter to continue...")

        elif choice == "7":
            check_root()
            direct_connectivity_test_menu()

        elif choice == "8":
            install_manager_alias()
            input("\nPress Enter to continue...")

        elif choice == "9":
            update_manager_script()
            input("\nPress Enter to continue...")

        elif choice == "10":
            uninstall_everything()
            input("\nPress Enter to continue...")

        elif choice == "0":
            sys.exit(0)
        else:
            print_error("Invalid choice.")



def handle_cli_args():
    if len(sys.argv) <= 1:
        return False

    arg = str(sys.argv[1]).strip().lower()
    if arg in {"--install-manager", "install-manager"}:
        install_manager_alias()
        return True

    if arg in {"--update-manager", "update-manager"}:
        update_manager_script()
        return True

    if arg in {"-h", "--help", "help"}:
        print("Usage:")
        print(f"  {os.path.basename(__file__)} --install-manager")
        print(f"      Install command alias at {MANAGER_ALIAS_PATH}")
        print(f"  {os.path.basename(__file__)} --update-manager")
        print("      Fetch and replace this script with the latest deploy.py")
        print(f"  {os.path.basename(__file__)}")
        print("      Launch interactive manager menu")
        return True

    return False
if __name__ == "__main__":
    try:
        if not handle_cli_args():
            main_menu()
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
