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
import urllib.request
import uuid

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


def print_header(text):
    print(f"\n{Colors.HEADER}{Colors.BOLD}=== {text} ==={Colors.ENDC}")


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

    print(f"\n{Colors.CYAN}{action_label.title()} target:{Colors.ENDC}")
    for index, service in enumerate(services, start=1):
        print(f"{index}. {service}.service")
    if allow_all and len(services) > 1:
        print(f"{len(services) + 1}. all")

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


def apply_linux_network_tuning():
    if not sys.platform.startswith("linux"):
        print_info("Skipping network tuning: only supported on Linux.")
        return False

    print_header("🚀 Linux Network Tuning")
    sysctl_settings = [
        ("net.core.rmem_max", "8388608"),
        ("net.core.wmem_max", "8388608"),
        ("net.core.rmem_default", "131072"),
        ("net.core.wmem_default", "131072"),
        ("net.ipv4.tcp_rmem", "4096 65536 8388608"),
        ("net.ipv4.tcp_wmem", "4096 65536 8388608"),
        ("net.ipv4.tcp_window_scaling", "1"),
        ("net.ipv4.tcp_timestamps", "1"),
        ("net.ipv4.tcp_sack", "1"),
        ("net.ipv4.tcp_retries2", "6"),
        ("net.ipv4.tcp_syn_retries", "2"),
        ("net.core.netdev_max_backlog", "1000"),
        ("net.core.somaxconn", "512"),
        ("net.ipv4.tcp_fastopen", "3"),
        ("net.ipv4.tcp_low_latency", "1"),
        ("net.ipv4.tcp_slow_start_after_idle", "0"),
        ("net.ipv4.tcp_no_metrics_save", "1"),
        ("net.ipv4.tcp_autocorking", "0"),
        ("net.ipv4.tcp_mtu_probing", "1"),
        ("net.ipv4.tcp_base_mss", "1024"),
        ("net.ipv4.tcp_keepalive_time", "120"),
        ("net.ipv4.tcp_keepalive_intvl", "10"),
        ("net.ipv4.tcp_keepalive_probes", "3"),
        ("net.ipv4.tcp_fin_timeout", "15"),
    ]

    failed = []
    for key, value in sysctl_settings:
        cmd = f"sysctl -w {key}={shlex.quote(value)}"
        if not run_command(cmd, check=False):
            failed.append(key)

    bbr_ok = run_command("modprobe tcp_bbr", check=False)
    if bbr_ok:
        bbr_ok = run_command("sysctl -w net.ipv4.tcp_congestion_control=bbr", check=False)
    qdisc_ok = run_command("sysctl -w net.core.default_qdisc=fq_codel", check=False)

    _, iface, _ = run_command_output("ip -o link show up | awk -F': ' '$2 != \"lo\" {print $2; exit}'")
    iface = iface.strip() or "eth0"
    tc_ok = run_command(f"tc qdisc replace dev {shlex.quote(iface)} root fq_codel", check=False)

    conf_lines = ["# NoDelay Tunnel Linux network tuning"]
    conf_lines.extend([f"{k}={v}" for k, v in sysctl_settings])
    conf_lines.append("net.ipv4.tcp_congestion_control=bbr")
    conf_lines.append("net.core.default_qdisc=fq_codel")
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
        print_success(f"fq_codel configured on {iface}")
    else:
        print_info("fq_codel could not be fully applied; verify `tc` and interface state.")
    return True


def maybe_apply_linux_network_tuning():
    answer = input_default("Apply Linux network tuning (BBR/fq_codel)? (Y/n)", "y").strip().lower()
    if answer in {"n", "no"}:
        return
    apply_linux_network_tuning()


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
    print(f"{Colors.CYAN}{Colors.BOLD}")
    print("╔══════════════════════════════════════════════════════╗")
    print("║        ✨ NoDelay Tunnel Made By Hosi ✨             ║")
    print("║          📢 Channel: @LoungeOfH                      ║")
    print("╚══════════════════════════════════════════════════════╝")
    print(f"{Colors.ENDC}")


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


def ask_cert_options():
    print(f"\n{Colors.CYAN}Certificate Options:{Colors.ENDC}")
    print("1. Use existing certificate path")
    print("2. Generate self-signed certificate (Auto)")
    choice = input("Select option [1/2]: ").strip()
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


def prompt_server_mappings():
    print_header("🔀 Configure Tunnel Mappings")
    print_info(
        "At least one mapping is required. You only enter ports; bind/target IPs are auto-filled."
    )
    mappings = []
    index = 1

    while True:
        print(f"\n{Colors.CYAN}Mapping #{index}{Colors.ENDC}")
        name = input_default("Name", f"mapping-{index}")

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


def prompt_client_tls_settings(server_addr):
    sni = input_default("Server Name (SNI)", server_addr).strip()
    skip_verify_raw = input_default("Insecure Skip Verify (true/false)", "true")
    skip_verify = parse_bool(skip_verify_raw, default=True)
    return sni, skip_verify


def prompt_license_id():
    while True:
        value = input("License ID: ").strip()
        if value:
            return value
        print_error("License ID is required.")


def menu_protocol(role, server_addr=""):
    print_header("📜 Select Protocol")
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
    for key, name in options:
        print(f"{Colors.GREEN}[{key}]{Colors.ENDC} {name}")

    while True:
        choice = input(f"\n{Colors.BOLD}Enter choice [1-9]: {Colors.ENDC}").strip()
        if choice in {str(i) for i in range(1, 10)}:
            break
        print_error("Invalid choice. Pick a number between 1 and 9.")

    config = {
        "port": "443",
        "path": "/tunnel",
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

    if role == "server":
        config["psk"] = input_default(
            "PSK (shared secret, leave empty to disable)", generate_uuid()
        )
    else:
        while True:
            config["psk"] = input(
                "PSK (must match server, leave empty if disabled on server): "
            ).strip()
            if config["psk"]:
                break
            confirm_empty = input_default(
                "Client PSK is empty. Continue only if server PSK is disabled (y/N)", "n"
            ).strip().lower()
            if confirm_empty in {"y", "yes"}:
                break

    if choice == "1":
        config["type"] = "tcp"
        config["port"] = input_default("Port", 8080)

    elif choice == "2":
        config["type"] = "tls"
        config["port"] = input_default("Port", 443)
        if role == "server":
            config["cert"], config["key"] = ask_cert_options()
        else:
            config["sni"], config["insecure_skip_verify"] = prompt_client_tls_settings(
                server_addr
            )

    elif choice == "3":
        config["type"] = "ws"
        config["port"] = input_default("Port", 80)
        config["path"] = normalize_path(input_default("Path", "/ws"), "/ws")

    elif choice == "4":
        config["type"] = "wss"
        config["port"] = input_default("Port", 443)
        config["path"] = normalize_path(input_default("Path", "/ws"), "/ws")
        if role == "server":
            config["cert"], config["key"] = ask_cert_options()
        else:
            config["sni"], config["insecure_skip_verify"] = prompt_client_tls_settings(
                server_addr
            )

    elif choice == "5":
        config["type"] = "kcp"
        config["port"] = input_default("Port", 4000)

    elif choice == "6":
        config["type"] = "quic"
        config["port"] = input_default("Port", 443)
        if role == "server":
            config["cert"], config["key"] = ask_cert_options()
        else:
            config["sni"], config["insecure_skip_verify"] = prompt_client_tls_settings(
                server_addr
            )

    elif choice == "7":
        config["type"] = "httpsmimicry"
        config["port"] = input_default("Port", 443)
        config["path"] = normalize_path(
            input_default("Mimic Path", "/api/v1/upload"), "/api/v1/upload"
        )
        if role == "server":
            config["cert"], config["key"] = ask_cert_options()
        else:
            config["sni"], config["insecure_skip_verify"] = prompt_client_tls_settings(
                server_addr
            )

    elif choice == "8":
        config["type"] = "httpmimicry"
        config["port"] = input_default("Port", 80)
        config["path"] = normalize_path(
            input_default("Mimic Path", "/api/v1/upload"), "/api/v1/upload"
        )
        config["sni"] = ""
        config["insecure_skip_verify"] = False

    elif choice == "9":
        config["type"] = "reality"
        config["port"] = input_default("Port", 443)
        config["server_names"] = prompt_server_names()
        config["short_id"] = prompt_short_id()
        if role == "server":
            config["dest"] = input_default(
                "Dest (real target site:port)", "www.microsoft.com:443"
            )
            (
                config["private_key"],
                config["public_key"],
                config["reality_key_generated"],
            ) = prompt_reality_private_key()
        else:
            (
                config["public_key"],
                config["generated_private_key"],
                config["reality_key_generated"],
            ) = prompt_reality_public_key()

    return config


PROFILE_PRESETS = ["performance", "latency", "balanced", "aggressive", "cpu-efficient", "gaming"]

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


def select_config_profile():
    print_header("🎛️ Config Profile Preset")
    for index, profile in enumerate(PROFILE_PRESETS, start=1):
        print(f"{index}. {profile}")
    while True:
        choice = input(f"Select profile [1-{len(PROFILE_PRESETS)}]: ").strip()
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(PROFILE_PRESETS):
                return PROFILE_PRESETS[idx - 1]
        print_error("Invalid choice.")


def select_deployment_mode():
    print_header("🚀 Deployment Mode")
    print("1. Default Optimized (recommended)")
    print("2. Advanced (customize smux/tcp/udp/kcp/quic/reconnect)")
    while True:
        choice = input("Select mode [1/2]: ").strip()
        if choice == "1":
            return "default"
        if choice == "2":
            return "advanced"
        print_error("Invalid choice.")


def select_obfuscation_profile():
    print_header("🕶️ Obfuscation Profile")
    for index, preset in enumerate(OBFUSCATION_PRESETS, start=1):
        if not preset["enabled"]:
            suffix = " (Recommended for speed)" if preset["key"] == "speed" else ""
            print(f"{index}. {preset['label']:<16} | enabled=false{suffix}")
            continue
        print(
            f"{index}. {preset['label']:<16} | enabled=true  "
            f"padding={preset['min_padding']}-{preset['max_padding']}  "
            f"delay={preset['min_delay_ms']}-{preset['max_delay_ms']}ms  "
            f"burst_chance={preset['burst_chance']}%"
        )
    while True:
        choice = input(f"Select profile [1-{len(OBFUSCATION_PRESETS)}]: ").strip()
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(OBFUSCATION_PRESETS):
                selected = OBFUSCATION_PRESETS[idx - 1]
                return {
                    "enabled": selected["enabled"],
                    "min_padding": selected["min_padding"],
                    "max_padding": selected["max_padding"],
                    "min_delay_ms": selected["min_delay_ms"],
                    "max_delay_ms": selected["max_delay_ms"],
                    "burst_chance": selected["burst_chance"],
                    # Legacy fields for backward compatibility with old binaries.
                    "max_timing_ms": selected["max_delay_ms"],
                    "min_chunk": 0,
                    "max_chunk": 0,
                    "burst_enabled": False,
                    "burst_interval": "5s",
                    "burst_count": 0,
                }
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


def build_http_mimicry_profiles(primary_path):
    primary_path = normalize_path(primary_path, "/api/v1/upload")
    return {
        "varzesh3_news": {
            "path": primary_path,
            "browser": "chrome",
            "fake_host": "www.varzesh3.com",
            "cookie_enabled": True,
            "chunked_encoding": False,
            "custom_headers": {
                "X-Requested-With": "XMLHttpRequest",
                "Referer": "https://www.varzesh3.com/",
                "Cache-Control": "max-age=0",
            },
        },
        "aparat_feed": {
            "path": "/",
            "browser": "chrome",
            "fake_host": "www.aparat.com",
            "cookie_enabled": True,
            "chunked_encoding": False,
            "custom_headers": {
                "Referer": "https://www.aparat.com/",
                "Sec-Fetch-Site": "same-origin",
                "Pragma": "no-cache",
            },
        },
        "digikala_search": {
            "path": "/search/",
            "browser": "firefox",
            "fake_host": "www.digikala.com",
            "cookie_enabled": True,
            "chunked_encoding": False,
            "custom_headers": {
                "Referer": "https://www.digikala.com/",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Connection": "keep-alive",
            },
        },
        "divar_city": {
            "path": "/s/tehran",
            "browser": "chrome",
            "fake_host": "divar.ir",
            "cookie_enabled": True,
            "chunked_encoding": False,
            "custom_headers": {
                "Referer": "https://divar.ir/",
                "Sec-Fetch-Site": "same-origin",
                "Cache-Control": "no-cache",
            },
        },
        "snapp_home": {
            "path": "/",
            "browser": "chrome",
            "fake_host": "snapp.ir",
            "cookie_enabled": True,
            "chunked_encoding": False,
            "custom_headers": {
                "Origin": "https://snapp.ir",
                "Referer": "https://snapp.ir/",
                "Sec-Fetch-Mode": "navigate",
            },
        },
        "torob_search": {
            "path": "/search/",
            "browser": "edge",
            "fake_host": "torob.com",
            "cookie_enabled": True,
            "chunked_encoding": False,
            "custom_headers": {
                "Referer": "https://torob.com/",
                "Sec-Fetch-Site": "same-origin",
                "Pragma": "no-cache",
            },
        },
    }


def render_http_mimicry_lines(protocol_config, http_path):
    enabled = protocol_config["type"] in {"httpmimicry", "httpsmimicry"}
    profiles = build_http_mimicry_profiles(http_path)
    lines = [
        "http_mimicry:",
        f"  enabled: {yaml_scalar(enabled)}",
        f"  path: {yaml_scalar(http_path)}",
        '  browser: "chrome"',
        '  fake_host: "www.varzesh3.com"',
        "  cookie_enabled: true",
        "  chunked_encoding: false",
        "  custom_headers:",
        '    X-Requested-With: "XMLHttpRequest"',
        '    Referer: "https://www.varzesh3.com/"',
        "  profiles:",
    ]
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
    reality_enabled = protocol_config["type"] == "reality"
    reality_dest = protocol_config.get("dest", "www.microsoft.com:443") if reality_enabled else "www.microsoft.com:443"
    reality_server_names = protocol_config.get("server_names", []) if reality_enabled else []
    reality_short_id = protocol_config.get("short_id", "") if reality_enabled else ""
    reality_private_key = protocol_config.get("private_key", "") if reality_enabled else ""
    lines = [
        "mode: server",
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
        "  mappings:",
    ]
    lines.extend(render_mappings_lines(protocol_config.get("mappings", [])))
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
    lines = [
        "mode: client",
        f"profile: {yaml_scalar(protocol_config.get('profile', 'balanced'))}",
        "",
        "client:",
        "  pool_size: 3",
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
        print_header("📊 Tunnel Monitor & Service Control")
        print("1. Show tunnel/service status")
        print("2. Show recent logs")
        print("3. Follow live logs")
        print("4. Start service")
        print("5. Stop service")
        print("6. Restart service")
        print("0. Back")

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


def multi_tunnel_menu():
    while True:
        print_header("🧩 Multi Tunnel Management")
        services = installed_services()
        print(f"Installed tunnel services: {len(services)}")
        print("1. List tunnel instances")
        print("2. Remove one instance")
        print("0. Back")
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
            print(f"\n{Colors.CYAN}Removable instances:{Colors.ENDC}")
            for index, service in enumerate(role_services, start=1):
                role, instance = parse_service_role_instance(service)
                print(f"{index}. {service}.service ({role_display(role)}:{instance})")
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


def install_server_flow():
    print_info("Role mapping: server = Iran Server (inside Iran)")
    instance = prompt_instance_name("server")
    cfg = menu_protocol("server")
    cfg["license"] = prompt_license_id()
    cfg["profile"] = select_config_profile()
    deployment_mode = select_deployment_mode()
    tuning = configure_tuning("server", deployment_mode)
    obfuscation_cfg = select_obfuscation_profile()
    cfg["mappings"] = prompt_server_mappings()
    config_file = build_config_filename("server", instance)
    config_path = generate_config(cfg, tuning, obfuscation_cfg, config_file)
    create_service("server", instance)
    maybe_apply_linux_network_tuning()

    print_header("🎉 Server Installation Complete")
    print(f"Instance: {Colors.BOLD}{instance}{Colors.ENDC}")
    print(f"Config:   {Colors.BOLD}{config_path}{Colors.ENDC}")
    print(f"Address:  {Colors.BOLD}:{cfg['port']}{Colors.ENDC}")
    psk_text = cfg["psk"] if cfg["psk"] else "(disabled)"
    print(f"PSK:      {Colors.BOLD}{psk_text}{Colors.ENDC}")
    print(f"Protocol: {Colors.BOLD}{cfg['type']}{Colors.ENDC}")
    print(f"Profile:  {Colors.BOLD}{cfg['profile']}{Colors.ENDC}")
    print(f"Deploy:   {Colors.BOLD}{deployment_mode}{Colors.ENDC}")
    if cfg["type"] == "reality":
        print(f"ShortID:  {Colors.BOLD}{cfg['short_id']}{Colors.ENDC}")
        print(f"Private:  {Colors.BOLD}{cfg['private_key']}{Colors.ENDC}")
        if cfg.get("public_key"):
            print(f"Public:   {Colors.BOLD}{cfg['public_key']}{Colors.ENDC}")


def install_client_flow():
    print_header("💻 Client Configuration (Kharej Server)")
    print_info("Role mapping: client = Kharej Server (outside Iran)")
    instance = prompt_instance_name("client")
    server_addr = input_required("Server Address (IP/Domain)")
    cfg = menu_protocol("client", server_addr=server_addr)
    cfg["license"] = prompt_license_id()
    cfg["profile"] = select_config_profile()
    deployment_mode = select_deployment_mode()
    tuning = configure_tuning("client", deployment_mode)
    obfuscation_cfg = select_obfuscation_profile()
    cfg["server_addr"] = server_addr
    config_file = build_config_filename("client", instance)
    config_path = generate_client_config(cfg, tuning, obfuscation_cfg, config_file)
    create_service("client", instance)
    maybe_apply_linux_network_tuning()

    print_header("✅ Client Installation Complete")
    print(f"Instance:   {Colors.BOLD}{instance}{Colors.ENDC}")
    print(f"Config:     {Colors.BOLD}{config_path}{Colors.ENDC}")
    print(f"Run command: {Colors.BOLD}nodelay client -c {config_path}{Colors.ENDC}")
    print(f"Profile:    {Colors.BOLD}{cfg['profile']}{Colors.ENDC}")
    print(f"Deploy:     {Colors.BOLD}{deployment_mode}{Colors.ENDC}")
    if cfg["type"] == "reality":
        print(f"ShortID:    {Colors.BOLD}{cfg['short_id']}{Colors.ENDC}")
        print(f"PublicKey:  {Colors.BOLD}{cfg['public_key']}{Colors.ENDC}")
        if cfg.get("generated_private_key"):
            print(f"PrivateKey: {Colors.BOLD}{cfg['generated_private_key']}{Colors.ENDC}")
            print_info("Use this private key on the server side.")


def main_menu():
    while True:
        print_banner()
        print(f"{Colors.GREEN}[1]{Colors.ENDC} 📥 Install Server (Iran)")
        print(f"{Colors.GREEN}[2]{Colors.ENDC} 💻 Install Client (Kharej)")
        print(f"{Colors.CYAN}[3]{Colors.ENDC} 🔄 Update Binary")
        print(f"{Colors.CYAN}[4]{Colors.ENDC} 🗑️  Uninstall")
        print(f"{Colors.CYAN}[5]{Colors.ENDC} 📊 Monitor / Logs / Service Control")
        print(f"{Colors.CYAN}[6]{Colors.ENDC} 🧩 Multi Tunnel Management")
        print(f"{Colors.WARNING}[0]{Colors.ENDC} 🚪 Exit")

        choice = input(f"\n{Colors.BOLD}Select option: {Colors.ENDC}").strip()

        if choice == "1":
            check_root()
            if ensure_binary():
                install_server_flow()
                input("\nPress Enter to continue...")

        elif choice == "2":
            check_root()
            if ensure_binary():
                install_client_flow()
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
