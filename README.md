# ⚡ NoDelay Tunnel

<div align="center">

**High-performance reverse/direct tunneling with multi-transport routing, profile-based tuning, and DPI-evasion options.**

🔴**لطفا در نظر داشته باشید برای استفاده از این تانل نیاز به خرید لایسنس از ربات تلگرام نودیلی دارید**🔴

**[![Telegram](https://img.shields.io/badge/telegram-NoDelayTunnel-blue?logo=telegram)](https://t.me/NoDelayTunnel)**

[English Overview](#-english-overview) • [Deploy](#-deploy) • [Config Samples](#-config-samples) • [Benchmarks](#-benchmarks) • [راهنمای فارسی](#-راهنمای-فارسی)

</div>

<div align="center">

[![Project](https://img.shields.io/badge/Project-NoDelay%20Tunnel-0A7EA4.svg)](https://github.com/ChownYourLife/NoDelayTunnel)
[![Deploy Script](https://img.shields.io/badge/Deploy-deploy.py-2EA043.svg)](https://raw.githubusercontent.com/ChownYourLife/NoDelayTunnel/main/deploy.py)
[![Platform](https://img.shields.io/badge/Platform-Linux-333333.svg)](https://github.com/ChownYourLife/NoDelayTunnel)

</div>

---

## 📚 Table of Contents

- [English Overview](#-english-overview)
- [Core Features](#-core-features)
- [Deployment](#-deploy)
- [Config Samples](#-config-samples)
- [Benchmarks](#-benchmarks)
- [Security Notes](#-security-notes)
- [راهنمای فارسی](#-راهنمای-فارسی)

---

## 🌍 Overview

**NoDelay Tunnel** is built for operators who need a fast and stable tunnel layer between two hosts, with support for both reverse and direct forwarding models.

It focuses on three practical goals:

- **Connection quality**: low handshake overhead, stable multiplexed sessions, and automatic recovery.
- **Operational flexibility**: multiple transports and runtime profiles for different network conditions.
- **Resistance in restrictive networks**: optional mimicry and obfuscation layers when plain transport is not enough.

NoDelay can be used as a lightweight forwarding core in front of services such as HTTPS gateways, game relays, VPN endpoints, API services, and private control planes.

## ✨ Core Features

### 1. Tunnel modes

- **Reverse mode**: client creates upstream sessions, server exposes mapped ports.
- **Direct mode**: server accepts incoming traffic and forwards it directly to the target.

### 2. Transport options

- `tcp`, `tls`, `ws`, `wss`, `kcp`, `quic`
- `httpmimicry`, `httpsmimicry`
- `reality`

### 3. Multiplexing and session handling

- SMUX-based stream multiplexing over each session.
- Connection pool support for parallel paths and better service continuity.
- Multi-endpoint support on both sides: `server.listens` and `client.servers`.
- Supports both deployment patterns:
  multiple clients to one server (`multi-client`) and one client to multiple servers (`multi-server`).
- You can run multiple transport types in one config by mixing endpoint entries
  (for example `tcp` + `ws` + `reality`) under `server.listens` / `client.servers`.
- There is no hard-coded endpoint count limit in core; practical limits come from
  OS resources (ports, file descriptors, CPU/RAM, bandwidth).
- Client-side endpoint selection strategy via `client.connection_strategy`:
  `parallel` (spread workers across endpoints) or `priority` (ordered failover).
- Health checks and reconnect backoff with jitter.
- In `reverse` mode with multiple listens/clients, mappings are served by a shared
  session pool (round-robin over active sessions), not pinned to a specific listen/client.

### Multi-Tunnel Load Spreading (Important)

You can run multiple tunnels simultaneously between the same two servers and distribute traffic across different transports.

- Define multiple endpoints in `server.listens` and `client.servers` (for example `reality` + `httpsmimicry` + `tcp`).
- Set `client.connection_strategy: parallel` to actively spread sessions/workers across available endpoints.
- Use `priority` only if you want strict ordered failover instead of active spreading.
- This is a core capability of NoDelay and one of the main ways to improve resilience under route instability or transport-specific throttling.

### 4. Security stack

- Token-based authentication (optional).
- PSK-based encrypted control/data layer.
- ACL support for allow-list behavior.
- TLS/uTLS/REALITY capabilities depending on selected transport.

### 5. Anti-DPI and traffic shaping options

- Optional traffic obfuscation (padding, timing, chunking, burst).
- HTTP/HTTPS mimicry to make flows look browser-like.
- uTLS fingerprint selection.
- Fragment controls for specific traffic patterns.

### 6. Ready-made profiles

- `balanced`
- `performance`
- `aggressive`
- `latency`
- `cpu-efficient`
- `gaming`

Profile defaults are applied first, then user custom values override profile fields.

## 🚀 Deploy

Repository:

- https://github.com/ChownYourLife/NoDelayTunnel

Deploy script:

- https://raw.githubusercontent.com/ChownYourLife/NoDelayTunnel/main/deploy.py

Quick start:

```bash
curl -fsSL https://raw.githubusercontent.com/ChownYourLife/NoDelayTunnel/main/deploy.py -o deploy.py
sudo python3 deploy.py
```

### Benchmark first (recommended before tunnel setup)

Before creating server/client tunnel configs, run a direct connectivity benchmark between the two VPS nodes.

- In `deploy.py`, use `🌐 Direct Connectivity Test (iperf3)` (or accept the benchmark prompt in client setup).
- Run tests in both directions (uplink/downlink), then decide:
  - `>=150-200 Mbps`: link quality is good for tunneling.
  - `<100 Mbps`: swap Iran/Kharej roles and test again before deployment.
- If direct link quality is poor, tunnel tuning alone usually will not fully fix throughput.

### What `deploy.py` handles

- Installs or updates the `nodelay` binary.
- Creates server/client config files under `/etc/nodelay/`.
- Builds and manages systemd services.
- Exposes common service controls (start/stop/restart/status/logs).
- Can apply optional Linux network tuning (for example BBR/fq_codel/sysctl presets).
- Supports configuring additional transport endpoints and client connection strategy from the interactive menu.

### Config generation modes (latest)

- `Default` deploy mode writes a lean config and relies on runtime defaults + selected `profile`.
- In `Default` mode, tuning sections are omitted from the file: `smux`, `tcp`, `udp`, `kcp`, `quic`, `reconnect`.
- `Advanced` deploy mode writes those tuning sections explicitly and lets you customize every field.
- In multi-tunnel edit mode, if you choose **Edit advanced tuning**, the instance is saved with explicit tuning blocks.

## 🧪 Config Samples

These samples are full explicit examples (equivalent to `Advanced` deploy output).

### Sample 0: Multi-endpoint + connection strategy

Server (multiple listen endpoints):

```yaml
mode: server
profile: performance

server:
  listens:
    - type: tcp
      address: ":9999"
      path: /tunnel
    - type: ws
      address: ":8080"
      path: /ws
  mappings:
    - name: web-443
      mode: reverse
      protocol: tcp
      bind: 0.0.0.0:443
      target: 127.0.0.1:443
```

Client (multiple upstream endpoints + strategy):

```yaml
mode: client
profile: performance

client:
  pool_size: 4
  connection_strategy: parallel # parallel | priority
  servers:
    - type: tcp
      address: 203.0.113.10:9999
      path: /tunnel
    - type: ws
      address: 203.0.113.11:8080
      path: /ws
```

Notes:

- If `listens`/`servers` are omitted, runtime falls back to a single default endpoint for each side.
- `parallel` spreads workers across endpoints; `priority` prefers the first endpoint and falls back in order.

### Sample 0.1: Multi-client (many foreign clients -> one Iran server)

Iran server:

```yaml
mode: server
profile: balanced

server:
  listens:
    - type: tcp
      address: ":9999"
      path: /tunnel
  mappings:
    - name: web-443
      mode: reverse
      protocol: tcp
      bind: 0.0.0.0:443
      target: 127.0.0.1:443
```

Foreign client #1:

```yaml
mode: client
profile: balanced

client:
  pool_size: 3
  connection_strategy: priority
  servers:
    - type: tcp
      address: ir-server.example.com:9999
      path: /tunnel
```

Foreign client #2 (same Iran server, separate instance):

```yaml
mode: client
profile: performance

client:
  pool_size: 2
  connection_strategy: priority
  servers:
    - type: tcp
      address: ir-server.example.com:9999
      path: /tunnel
```

### Sample 0.2: Multi-server (one foreign client -> multiple Iran servers)

Foreign client:

```yaml
mode: client
profile: performance

client:
  pool_size: 6
  connection_strategy: parallel # use priority for strict failover order
  servers:
    - type: tls
      address: ir-server-1.example.com:443
      path: /tunnel
      tls:
        server_name: ir-server-1.example.com
        insecure_skip_verify: false
    - type: tls
      address: ir-server-2.example.com:443
      path: /tunnel
      tls:
        server_name: ir-server-2.example.com
        insecure_skip_verify: false
```

Iran server #1/#2 (same structure, different host/IP):

```yaml
mode: server
profile: performance

server:
  listens:
    - type: tls
      address: ":443"
      path: /tunnel
      tls:
        cert_file: /etc/nodelay/certs/fullchain.pem
        key_file: /etc/nodelay/certs/privkey.pem
  mappings:
    - name: web-443
      mode: reverse
      protocol: tcp
      bind: 0.0.0.0:443
      target: 127.0.0.1:443
```

### Sample 1: Reverse + REALITY

Full Server Config (Advanced/Explicit):

```yaml
mode: server
profile: latency

server:
  listen:
    type: reality
    address: ":1999"
    path: /tunnel
    tls:
      cert_file: ""
      key_file: ""
      ca_file: ""
      require_client_cert: false
  mappings:
    - name: web-443
      mode: reverse
      protocol: tcp
      bind: 0.0.0.0:443
      target: 127.0.0.1:443

smux:
  version: 2
  keepalive_enabled: true
  keepalive_every: 5s
  keepalive_timeout: 15s
  max_frame_size: 32768
  max_receive_buffer: 16777216
  max_stream_buffer: 16777216

tcp:
  no_delay: true
  keepalive: 15s
  read_buffer: 8388608
  write_buffer: 8388608
  conn_limit: 5000
  copy_buffer: 65536
  auto_tune: true

udp:
  read_buffer: 8388608
  write_buffer: 8388608
  max_datagram_size: 65507
  session_idle_timeout: 2m

kcp:
  data_shards: 10
  parity_shards: 3
  no_delay: 1
  interval: 20
  resend: 2
  no_congestion: 1
  mtu: 1200
  send_window: 512
  recv_window: 512

quic:
  alpn: nodelay-quic-v1
  handshake_timeout: 10s
  max_idle_timeout: 60s
  keepalive_period: 15s

security:
  token: ""
  psk: "YOUR_SHARED_PSK"
  auth_timeout: 10s
  acl:
    enabled: false
    allow: ["*"]

health:
  enabled: true
  interval: 15s

reconnect:
  min_delay: 500ms
  max_delay: 15s
  factor: 1.8
  jitter: true

obfuscation:
  enabled: true
  max_padding: 12
  max_timing_ms: 8
  min_chunk: 32
  max_chunk: 512
  burst_enabled: false
  burst_interval: 5s
  burst_count: 0

http_mimicry:
  enabled: false
  path: /search
  browser: chrome
  fake_host: www.google.com
  cookie_enabled: true
  chunked_encoding: false
  custom_headers:
    X-Requested-With: XMLHttpRequest
    Referer: https://www.google.com/

frag:
  enabled: false
  split_pos: 0
  fake_ttl: 0
  reverse_order: false

utls:
  enabled: false
  fingerprint: chrome

reality:
  enabled: true
  dest: "www.microsoft.com:443"
  server_names: ["www.microsoft.com", "microsoft.com"]
  short_id: "052bb7e1"
  private_key: "SERVER_PRIVATE_KEY_HEX"
  public_key: ""
```

Full Client Config (Advanced/Explicit):

```yaml
mode: client
profile: latency

client:
  pool_size: 3
  server:
    type: reality
    address: your-server.example.com:1999
    path: /tunnel

smux:
  version: 2
  keepalive_enabled: true
  keepalive_every: 5s
  keepalive_timeout: 15s
  max_frame_size: 32768
  max_receive_buffer: 16777216
  max_stream_buffer: 16777216

tcp:
  no_delay: true
  keepalive: 15s
  read_buffer: 8388608
  write_buffer: 8388608
  conn_limit: 5000
  copy_buffer: 65536
  auto_tune: true

udp:
  read_buffer: 8388608
  write_buffer: 8388608
  max_datagram_size: 65507
  session_idle_timeout: 2m

kcp:
  data_shards: 10
  parity_shards: 3
  no_delay: 1
  interval: 20
  resend: 2
  no_congestion: 1
  mtu: 1200
  send_window: 512
  recv_window: 512

quic:
  alpn: nodelay-quic-v1
  handshake_timeout: 10s
  max_idle_timeout: 60s
  keepalive_period: 15s

security:
  token: ""
  psk: "YOUR_SHARED_PSK"
  auth_timeout: 10s
  acl:
    enabled: false
    allow: ["*"]

health:
  enabled: true
  interval: 15s

reconnect:
  min_delay: 500ms
  max_delay: 15s
  factor: 1.8
  jitter: true

obfuscation:
  enabled: true
  max_padding: 12
  max_timing_ms: 8
  min_chunk: 32
  max_chunk: 512
  burst_enabled: false
  burst_interval: 5s
  burst_count: 0

http_mimicry:
  enabled: false
  path: /search
  browser: chrome
  fake_host: www.google.com
  cookie_enabled: true
  chunked_encoding: false
  custom_headers:
    X-Requested-With: XMLHttpRequest
    Referer: https://www.google.com/

frag:
  enabled: false
  split_pos: 0
  fake_ttl: 0
  reverse_order: false

utls:
  enabled: true
  fingerprint: chrome

reality:
  enabled: true
  dest: "www.microsoft.com:443"
  server_names: ["www.microsoft.com", "microsoft.com"]
  short_id: "052bb7e1"
  private_key: ""
  public_key: "SERVER_PUBLIC_KEY_HEX"
```

### Sample 2: Reverse + HTTPS Mimicry

Full Server Config (Advanced/Explicit):

```yaml
mode: server
profile: balanced

server:
  listen:
    type: httpsmimicry
    address: ":443"
    path: /search
    tls:
      cert_file: /etc/nodelay/certs/fullchain.pem
      key_file: /etc/nodelay/certs/privkey.pem
      ca_file: ""
      require_client_cert: false
  mappings:
    - name: tls-8443
      mode: reverse
      protocol: tcp
      bind: 0.0.0.0:8443
      target: 127.0.0.1:8443

smux:
  version: 2
  keepalive_enabled: true
  keepalive_every: 5s
  keepalive_timeout: 15s
  max_frame_size: 32768
  max_receive_buffer: 16777216
  max_stream_buffer: 16777216

tcp:
  no_delay: true
  keepalive: 15s
  read_buffer: 8388608
  write_buffer: 8388608
  conn_limit: 5000
  copy_buffer: 65536
  auto_tune: true

security:
  token: ""
  psk: "YOUR_SHARED_PSK"
  auth_timeout: 10s

health:
  enabled: true
  interval: 15s

reconnect:
  min_delay: 500ms
  max_delay: 15s
  factor: 1.8
  jitter: true

obfuscation:
  enabled: false
  max_padding: 8
  max_timing_ms: 5
  min_chunk: 64
  max_chunk: 1024
  burst_enabled: false
  burst_interval: 5s
  burst_count: 0

http_mimicry:
  enabled: true
  path: /search
  browser: chrome
  fake_host: www.google.com
  cookie_enabled: true
  chunked_encoding: false
  custom_headers:
    X-Requested-With: XMLHttpRequest
    Referer: https://www.google.com/

frag:
  enabled: false
  split_pos: 0
  fake_ttl: 0
  reverse_order: false

utls:
  enabled: false
  fingerprint: chrome

reality:
  enabled: false
  dest: "www.microsoft.com:443"
  server_names: []
  short_id: ""
  private_key: ""
  public_key: ""
```

Full Client Config (Advanced/Explicit):

```yaml
mode: client
profile: balanced

client:
  pool_size: 3
  server:
    type: httpsmimicry
    address: your-server.example.com:443
    path: /search
    tls:
      server_name: your-server.example.com
      insecure_skip_verify: false

smux:
  version: 2
  keepalive_enabled: true
  keepalive_every: 5s
  keepalive_timeout: 15s
  max_frame_size: 32768
  max_receive_buffer: 16777216
  max_stream_buffer: 16777216

tcp:
  no_delay: true
  keepalive: 15s
  read_buffer: 8388608
  write_buffer: 8388608
  conn_limit: 5000
  copy_buffer: 65536
  auto_tune: true

security:
  token: ""
  psk: "YOUR_SHARED_PSK"
  auth_timeout: 10s

reconnect:
  min_delay: 500ms
  max_delay: 15s
  factor: 1.8
  jitter: true

obfuscation:
  enabled: false
  max_padding: 8
  max_timing_ms: 5
  min_chunk: 64
  max_chunk: 1024
  burst_enabled: false
  burst_interval: 5s
  burst_count: 0

http_mimicry:
  enabled: true
  path: /search
  browser: chrome
  fake_host: www.google.com
  cookie_enabled: true
  chunked_encoding: false

utls:
  enabled: true
  fingerprint: chrome

reality:
  enabled: false
  dest: "www.microsoft.com:443"
  server_names: []
  short_id: ""
  private_key: ""
  public_key: ""
```

### Sample 3: Reverse + KCP for mixed TCP/UDP mapping

Full Server Config (Advanced/Explicit):

```yaml
mode: server
profile: performance

server:
  listen:
    type: kcp
    address: ":4000"
  mappings:
    - name: wg-udp
      mode: reverse
      protocol: udp
      bind: 0.0.0.0:51820
      target: 127.0.0.1:51820
    - name: app-tcp
      mode: reverse
      protocol: tcp
      bind: 0.0.0.0:9443
      target: 127.0.0.1:9443

smux:
  version: 2
  keepalive_enabled: true
  keepalive_every: 5s
  keepalive_timeout: 15s
  max_frame_size: 32768
  max_receive_buffer: 16777216
  max_stream_buffer: 16777216

tcp:
  no_delay: true
  keepalive: 15s
  read_buffer: 8388608
  write_buffer: 8388608
  conn_limit: 5000
  copy_buffer: 65536
  auto_tune: true

udp:
  read_buffer: 8388608
  write_buffer: 8388608
  max_datagram_size: 65507
  session_idle_timeout: 2m

kcp:
  data_shards: 10
  parity_shards: 3
  no_delay: 1
  interval: 20
  resend: 2
  no_congestion: 1
  mtu: 1200
  send_window: 512
  recv_window: 512

security:
  token: ""
  psk: "YOUR_SHARED_PSK"
  auth_timeout: 10s

obfuscation:
  enabled: false
  max_padding: 8
  max_timing_ms: 0
  min_chunk: 64
  max_chunk: 1024
  burst_enabled: false
  burst_interval: 5s
  burst_count: 0
```

Full Client Config (Advanced/Explicit):

```yaml
mode: client
profile: performance

client:
  pool_size: 4
  server:
    type: kcp
    address: your-server.example.com:4000

smux:
  version: 2
  keepalive_enabled: true
  keepalive_every: 5s
  keepalive_timeout: 15s
  max_frame_size: 32768
  max_receive_buffer: 16777216
  max_stream_buffer: 16777216

tcp:
  no_delay: true
  keepalive: 15s
  read_buffer: 8388608
  write_buffer: 8388608
  conn_limit: 5000
  copy_buffer: 65536
  auto_tune: true

udp:
  read_buffer: 8388608
  write_buffer: 8388608
  max_datagram_size: 65507
  session_idle_timeout: 2m

kcp:
  data_shards: 10
  parity_shards: 3
  no_delay: 1
  interval: 20
  resend: 2
  no_congestion: 1
  mtu: 1200
  send_window: 512
  recv_window: 512

security:
  token: ""
  psk: "YOUR_SHARED_PSK"
  auth_timeout: 10s

reconnect:
  min_delay: 500ms
  max_delay: 15s
  factor: 1.8
  jitter: true
```

### Sample 4: Direct mode

```yaml
mode: server
profile: performance

server:
  listen:
    type: tcp
    address: ":8443"
  mappings:
    - name: direct-http
      mode: direct
      protocol: tcp
      bind: 127.0.0.1:18080
      target: 1.1.1.1:80

smux:
  version: 2
  keepalive_enabled: true
  keepalive_every: 5s
  keepalive_timeout: 15s
  max_frame_size: 32768
  max_receive_buffer: 16777216
  max_stream_buffer: 16777216

tcp:
  no_delay: true
  keepalive: 15s
  read_buffer: 8388608
  write_buffer: 8388608
  conn_limit: 5000
  copy_buffer: 65536
  auto_tune: true

security:
  token: ""
  psk: ""
  auth_timeout: 10s

health:
  enabled: true
  interval: 15s
```

## 📊 Benchmarks

These are **relative guidance scores** for planning, not universal fixed numbers. Real output depends on CPU, memory, route quality, RTT, loss, and endpoint behavior.

### Transport comparison (relative)

| Transport      | Latency | Throughput | CPU Efficiency | DPI Resistance | Stability |
| -------------- | ------: | ---------: | -------------: | -------------: | --------: |
| `tcp`          |    9/10 |       8/10 |           9/10 |           3/10 |      9/10 |
| `tls`          |    8/10 |       8/10 |           8/10 |           6/10 |      9/10 |
| `ws`           |    7/10 |       7/10 |           7/10 |           7/10 |      8/10 |
| `wss`          |    7/10 |       7/10 |           6/10 |           8/10 |      8/10 |
| `kcp`          |    8/10 |       8/10 |           6/10 |           5/10 |      7/10 |
| `quic`         |    8/10 |       8/10 |           7/10 |           7/10 |      8/10 |
| `httpmimicry`  |    6/10 |       6/10 |           6/10 |           8/10 |      7/10 |
| `httpsmimicry` |    6/10 |       6/10 |           5/10 |           9/10 |      7/10 |
| `reality`      |    8/10 |       8/10 |           7/10 |           9/10 |      8/10 |

### Profile comparison (relative)

| Profile         | Latency | Throughput | CPU Efficiency | Typical Use               |
| --------------- | ------: | ---------: | -------------: | ------------------------- |
| `performance`   |    9/10 |       9/10 |           8/10 | high-speed general use    |
| `latency`       |   10/10 |       8/10 |           8/10 | low-delay paths           |
| `balanced`      |    8/10 |       8/10 |           8/10 | daily operations          |
| `aggressive`    |    7/10 |       9/10 |           6/10 | max throughput under load |
| `cpu-efficient` |    6/10 |       6/10 |          10/10 | weaker VPS/hardware       |
| `gaming`        |   10/10 |       7/10 |           8/10 | realtime sessions         |

### Suggested measurement flow

```bash
# receiver
iperf3 -s

# sender through tunnel
iperf3 -c <target_ip> -p <target_port> -t 30
iperf3 -c <target_ip> -p <target_port> -t 30 -R

# latency
ping -c 50 <target_ip>

# service resource snapshot
systemctl status nodelay-server
systemctl status nodelay-client
```

## 🔐 Security Notes

- Keep `security.psk` identical on both peers (or disabled on both).
- Do not enable `insecure_skip_verify` outside controlled testing.
- Use valid certificates for TLS-based transports.
- Keep obfuscation/mimicry settings aligned between client and server.

---

## راهنمای فارسی

**نو دیلی** یک تونل لایه 4 با عملکرد بالا است که برای اپراتورهایی طراحی شده که نیاز به یک لایه تونل سریع و پایدار بین دو هاست دارند، با پشتیبانی از مدل‌های فورواردینگ معکوس و مستقیم.

این پروژه سه هدف عملی دارد:

- **کیفیت اتصال**: هندشیک سریع‌تر، سشن‌های پایدار مالتی‌پلکس، و بازیابی خودکار.
- **انعطاف عملیاتی**: انتخاب ترنسپورت‌های مختلف و پروفایل‌های آماده برای شرایط شبکه متفاوت.
- **مقاومت در شبکه‌های محدود**: لایه‌های اختیاری mimicry و obfuscation برای سناریوهای DPI.

نو دیلی می‌تواند به‌عنوان هسته تونل سبک برای سرویس‌هایی مثل گیت‌وی HTTPS، رله بازی، VPN Endpoint، API و کنترل‌پلین خصوصی استفاده شود.

## ✨ قابلیت‌های اصلی

### 1) حالت‌های تونل

- **Reverse**: کلاینت سشن را به سمت سرور باز می‌کند و سرور پورت‌های مپ‌شده را اکسپوز می‌کند
- **Direct**: سرور ترافیک ورودی را می‌گیرد و مستقیم به مقصد فوروارد می‌کند

### 2) ترنسپورت‌ها

- `tcp`, `tls`, `ws`, `wss`, `kcp`, `quic`
- `httpmimicry`, `httpsmimicry`
- `reality`

### 3) مدیریت سشن و مالتی‌پلکس

- مالتی‌پلکس استریم‌ها با SMUX روی هر سشن.
- Connection Pool برای مسیرهای موازی و پایداری بهتر سرویس
- پشتیبانی از چند Endpoint در هر دو سمت:
  `server.listens` و `client.servers`
- پشتیبانی از هر دو الگو:
  چند کلاینت به یک سرور (`multi-client`) و یک کلاینت به چند سرور (`multi-server`)
- می‌توانید در یک کانفیگ چند نوع transport را همزمان بالا بیاورید
  (مثلا `tcp` + `ws` + `reality`) با افزودن endpointهای متعدد در `listens/servers`.
- در هسته محدودیت عددی ثابت برای تعداد endpoint وجود ندارد؛ محدودیت عملی از منابع
  سیستم می‌آید (پورت‌ها، file descriptor، CPU/RAM و پهنای‌باند).
- استراتژی انتخاب Endpoint در کلاینت با `client.connection_strategy`:
  `parallel` (تقسیم workerها روی endpointها) یا `priority` (اولویت ترتیبی با failover)
- Health check و reconnect با backoff + jitter.
- در حالت `reverse` و با چند listen/کلاینت، mappingها از یک session pool مشترک سرویس
  می‌گیرند (round-robin بین sessionهای فعال) و به listen/کلاینت خاص pin نمی‌شوند.

### 🔥 پخش بار بین چند تانل 🔥

می‌توانید بین همین دو سرور، چند تانل همزمان بالا بیاورید و ترافیک را بین ترنسپورت‌های مختلف پخش کنید.

- چند endpoint در `server.listens` و `client.servers` تعریف کنید (مثلا `reality` + `httpsmimicry` + `tcp`).
- برای پخش فعال سشن/ورکرها بین endpointها، روی کلاینت `client.connection_strategy: parallel` بگذارید.
- اگر failover ترتیبی می‌خواهید (و نه پخش همزمان)، از `priority` استفاده کنید.
- این قابلیت جزو هسته اصلی NoDelay است و برای پایداری بهتر در مسیرهای ناپایدار یا throttling روی یک ترنسپورت خاص، بسیار کلیدی است.

### 4) لایه امنیت

- احراز هویت مبتنی بر Token (اختیاری)
- رمزنگاری بر پایه PSK برای کنترل/داده
- ACL برای رفتار allow-list
- قابلیت TLS/uTLS/REALITY بسته به ترنسپورت انتخابی

### 5) ضد DPI و شکل‌دهی ترافیک

- Obfuscation اختیاری (padding, timing, chunking, burst)
- HTTP/HTTPS Mimicry برای شبیه‌سازی ترافیک مرورگر
- انتخاب fingerprint در uTLS
- تنظیمات Fragment برای الگوهای خاص ترافیکی

### 6) پروفایل‌های آماده

- `balanced`
- `performance`
- `aggressive`
- `latency`
- `cpu-efficient`
- `gaming`

ابتدا مقدارهای پیش‌فرض پروفایل اعمال می‌شود و بعد تنظیمات سفارشی کاربر روی همان فیلدها override می‌کند.

## 🚀 استقرار

مخزن پروژه:

- https://github.com/ChownYourLife/NoDelayTunnel

اسکریپت استقرار:

- https://raw.githubusercontent.com/ChownYourLife/NoDelayTunnel/main/deploy.py

شروع سریع:

```bash
curl -fsSL https://raw.githubusercontent.com/ChownYourLife/NoDelayTunnel/main/deploy.py -o deploy.py
sudo python3 deploy.py
```

### قبل از ساخت تونل، اول Benchmark بگیرید (توصیه‌شده)

قبل از اینکه کانفیگ سرور/کلاینت تونل را بسازید، بین دو VPS یک تست اتصال مستقیم بگیرید.

- داخل `deploy.py` از گزینه `🌐 Direct Connectivity Test (iperf3)` استفاده کنید (یا در مسیر نصب کلاینت، پرامپت Benchmark را تایید کنید).
- تست را در هر دو جهت بگیرید (آپلود/دانلود) و بعد تصمیم بگیرید:
  - اگر آپلود و دانلود بیشتر از `150-200` مگابیت بودند: کیفیت لینک برای تونل مناسب است.
  - اگر کمتر از `100` مگابیت بودند: جای ایران/خارج را عوض کنید و دوباره تست بگیرید.
- اگر لینک مستقیم ضعیف باشد، صرفا با tuning تونل معمولا مشکل throughput کامل حل نمی‌شود.

### `deploy.py` چه کار می‌کند؟

- نصب یا آپدیت باینری `nodelay`
- ساخت فایل‌های کانفیگ سرور/کلاینت در `/etc/nodelay/`
- ساخت و مدیریت سرویس‌های systemd
- ارائه کنترل‌های معمول سرویس (start/stop/restart/status/logs)
- امکان اعمال تنظیمات اختیاری شبکه لینوکس (مثل BBR/fq_codel/sysctl presets)
- پشتیبانی از تعریف endpointهای اضافه و تنظیم `connection_strategy` کلاینت از منوی تعاملی

### حالت‌های تولید کانفیگ (نسخه جدید)

- در حالت `Default`، اسکریپت یک کانفیگ سبک می‌سازد و از پیش‌فرض‌های runtime + `profile` انتخاب‌شده استفاده می‌شود.
- در حالت `Default`، سکشن‌های tuning داخل فایل نوشته نمی‌شوند: `smux`, `tcp`, `udp`, `kcp`, `quic`, `reconnect`.
- در حالت `Advanced`، همین سکشن‌ها به‌صورت explicit داخل فایل نوشته می‌شوند و همه فیلدها قابل تنظیم هستند.
- در بخش ویرایش Multi Tunnel، اگر گزینه **Edit advanced tuning** را بزنید، کانفیگ همان instance با tuningهای explicit ذخیره می‌شود.

## 🧪 نمونه کانفیگ

این نمونه‌ها حالت کامل و explicit هستند (معادل خروجی deploy در حالت `Advanced`).

### نمونه 0: چند endpoint + استراتژی اتصال

سرور (چند listen endpoint):

```yaml
mode: server
profile: performance

server:
  listens:
    - type: tcp
      address: ":9999"
      path: /tunnel
    - type: ws
      address: ":8080"
      path: /ws
  mappings:
    - name: web-443
      mode: reverse
      protocol: tcp
      bind: 0.0.0.0:443
      target: 127.0.0.1:443
```

کلاینت (چند upstream endpoint + استراتژی):

```yaml
mode: client
profile: performance

client:
  pool_size: 4
  connection_strategy: parallel # parallel | priority
  servers:
    - type: tcp
      address: 203.0.113.10:9999
      path: /tunnel
    - type: ws
      address: 203.0.113.11:8080
      path: /ws
```

نکته‌ها:

- اگر `listens`/`servers` را نگذارید، runtime برای هر سمت یک endpoint پیش‌فرض در نظر می‌گیرد.
- در `parallel`، workerها بین endpointها پخش می‌شوند؛ در `priority` ابتدا endpoint اول تست می‌شود و در صورت خطا failover ترتیبی انجام می‌شود.

### نمونه 0.1: Multi-client (چند کلاینت خارج -> یک سرور ایران)

سرور ایران:

```yaml
mode: server
profile: balanced

server:
  listens:
    - type: tcp
      address: ":9999"
      path: /tunnel
  mappings:
    - name: web-443
      mode: reverse
      protocol: tcp
      bind: 0.0.0.0:443
      target: 127.0.0.1:443
```

کلاینت خارج شماره 1:

```yaml
mode: client
profile: balanced

client:
  pool_size: 3
  connection_strategy: priority
  servers:
    - type: tcp
      address: ir-server.example.com:9999
      path: /tunnel
```

کلاینت خارج شماره 2 (همان سرور ایران، instance جدا):

```yaml
mode: client
profile: performance

client:
  pool_size: 2
  connection_strategy: priority
  servers:
    - type: tcp
      address: ir-server.example.com:9999
      path: /tunnel
```

### نمونه 0.2: Multi-server (یک کلاینت خارج -> چند سرور ایران)

کلاینت خارج:

```yaml
mode: client
profile: performance

client:
  pool_size: 6
  connection_strategy: parallel # برای failover ترتیبی از priority استفاده کنید
  servers:
    - type: tls
      address: ir-server-1.example.com:443
      path: /tunnel
      tls:
        server_name: ir-server-1.example.com
        insecure_skip_verify: false
    - type: tls
      address: ir-server-2.example.com:443
      path: /tunnel
      tls:
        server_name: ir-server-2.example.com
        insecure_skip_verify: false
```

سرور ایران شماره 1/2 (ساختار یکسان، فقط Host/IP متفاوت):

```yaml
mode: server
profile: performance

server:
  listens:
    - type: tls
      address: ":443"
      path: /tunnel
      tls:
        cert_file: /etc/nodelay/certs/fullchain.pem
        key_file: /etc/nodelay/certs/privkey.pem
  mappings:
    - name: web-443
      mode: reverse
      protocol: tcp
      bind: 0.0.0.0:443
      target: 127.0.0.1:443
```

### نمونه 1: Reverse + REALITY

کانفیگ کامل سرور (حالت Advanced/Explicit):

```yaml
mode: server
profile: latency

server:
  listen:
    type: reality
    address: ":1999"
    path: /tunnel
    tls:
      cert_file: ""
      key_file: ""
      ca_file: ""
      require_client_cert: false
  mappings:
    - name: web-443
      mode: reverse
      protocol: tcp
      bind: 0.0.0.0:443
      target: 127.0.0.1:443

security:
  token: ""
  psk: "YOUR_SHARED_PSK"
  auth_timeout: 10s
  acl:
    enabled: false
    allow: ["*"]

smux:
  version: 2
  keepalive_enabled: true
  keepalive_every: 5s
  keepalive_timeout: 15s
  max_frame_size: 32768
  max_receive_buffer: 16777216
  max_stream_buffer: 16777216

tcp:
  no_delay: true
  keepalive: 15s
  read_buffer: 8388608
  write_buffer: 8388608
  conn_limit: 5000
  copy_buffer: 65536
  auto_tune: true

udp:
  read_buffer: 8388608
  write_buffer: 8388608
  max_datagram_size: 65507
  session_idle_timeout: 2m

kcp:
  data_shards: 10
  parity_shards: 3
  no_delay: 1
  interval: 20
  resend: 2
  no_congestion: 1
  mtu: 1200
  send_window: 512
  recv_window: 512

quic:
  alpn: nodelay-quic-v1
  handshake_timeout: 10s
  max_idle_timeout: 60s
  keepalive_period: 15s

health:
  enabled: true
  interval: 15s

reconnect:
  min_delay: 500ms
  max_delay: 15s
  factor: 1.8
  jitter: true

obfuscation:
  enabled: true
  max_padding: 12
  max_timing_ms: 8
  min_chunk: 32
  max_chunk: 512
  burst_enabled: false
  burst_interval: 5s
  burst_count: 0

http_mimicry:
  enabled: false
  path: /search
  browser: chrome
  fake_host: www.google.com
  cookie_enabled: true
  chunked_encoding: false
  custom_headers:
    X-Requested-With: XMLHttpRequest
    Referer: https://www.google.com/

frag:
  enabled: false
  split_pos: 0
  fake_ttl: 0
  reverse_order: false

utls:
  enabled: false
  fingerprint: chrome

reality:
  enabled: true
  dest: "www.microsoft.com:443"
  server_names: ["www.microsoft.com", "microsoft.com"]
  short_id: "052bb7e1"
  private_key: "SERVER_PRIVATE_KEY_HEX"
  public_key: ""
```

کانفیگ کامل کلاینت (حالت Advanced/Explicit):

```yaml
mode: client
profile: latency

client:
  pool_size: 3
  server:
    type: reality
    address: your-server.example.com:1999
    path: /tunnel

security:
  token: ""
  psk: "YOUR_SHARED_PSK"
  auth_timeout: 10s
  acl:
    enabled: false
    allow: ["*"]

smux:
  version: 2
  keepalive_enabled: true
  keepalive_every: 5s
  keepalive_timeout: 15s
  max_frame_size: 32768
  max_receive_buffer: 16777216
  max_stream_buffer: 16777216

tcp:
  no_delay: true
  keepalive: 15s
  read_buffer: 8388608
  write_buffer: 8388608
  conn_limit: 5000
  copy_buffer: 65536
  auto_tune: true

udp:
  read_buffer: 8388608
  write_buffer: 8388608
  max_datagram_size: 65507
  session_idle_timeout: 2m

kcp:
  data_shards: 10
  parity_shards: 3
  no_delay: 1
  interval: 20
  resend: 2
  no_congestion: 1
  mtu: 1200
  send_window: 512
  recv_window: 512

quic:
  alpn: nodelay-quic-v1
  handshake_timeout: 10s
  max_idle_timeout: 60s
  keepalive_period: 15s

health:
  enabled: true
  interval: 15s

reconnect:
  min_delay: 500ms
  max_delay: 15s
  factor: 1.8
  jitter: true

obfuscation:
  enabled: true
  max_padding: 12
  max_timing_ms: 8
  min_chunk: 32
  max_chunk: 512
  burst_enabled: false
  burst_interval: 5s
  burst_count: 0

http_mimicry:
  enabled: false
  path: /search
  browser: chrome
  fake_host: www.google.com
  cookie_enabled: true
  chunked_encoding: false
  custom_headers:
    X-Requested-With: XMLHttpRequest
    Referer: https://www.google.com/

frag:
  enabled: false
  split_pos: 0
  fake_ttl: 0
  reverse_order: false

utls:
  enabled: true
  fingerprint: chrome

reality:
  enabled: true
  dest: "www.microsoft.com:443"
  server_names: ["www.microsoft.com", "microsoft.com"]
  short_id: "052bb7e1"
  private_key: ""
  public_key: "SERVER_PUBLIC_KEY_HEX"
```

### نمونه 2: Reverse + HTTPS Mimicry

کانفیگ کامل سرور (حالت Advanced/Explicit):

```yaml
mode: server
profile: balanced

server:
  listen:
    type: httpsmimicry
    address: ":443"
    path: /search
    tls:
      cert_file: /etc/nodelay/certs/fullchain.pem
      key_file: /etc/nodelay/certs/privkey.pem
      ca_file: ""
      require_client_cert: false
  mappings:
    - name: tls-8443
      mode: reverse
      protocol: tcp
      bind: 0.0.0.0:8443
      target: 127.0.0.1:8443

smux:
  version: 2
  keepalive_enabled: true
  keepalive_every: 5s
  keepalive_timeout: 15s
  max_frame_size: 32768
  max_receive_buffer: 16777216
  max_stream_buffer: 16777216

tcp:
  no_delay: true
  keepalive: 15s
  read_buffer: 8388608
  write_buffer: 8388608
  conn_limit: 5000
  copy_buffer: 65536
  auto_tune: true

security:
  token: ""
  psk: "YOUR_SHARED_PSK"
  auth_timeout: 10s

health:
  enabled: true
  interval: 15s

reconnect:
  min_delay: 500ms
  max_delay: 15s
  factor: 1.8
  jitter: true

obfuscation:
  enabled: false
  max_padding: 8
  max_timing_ms: 5
  min_chunk: 64
  max_chunk: 1024
  burst_enabled: false
  burst_interval: 5s
  burst_count: 0

http_mimicry:
  enabled: true
  path: /search
  browser: chrome
  fake_host: www.google.com
  cookie_enabled: true
  chunked_encoding: false
  custom_headers:
    X-Requested-With: XMLHttpRequest
    Referer: https://www.google.com/

frag:
  enabled: false
  split_pos: 0
  fake_ttl: 0
  reverse_order: false

utls:
  enabled: false
  fingerprint: chrome

reality:
  enabled: false
  dest: "www.microsoft.com:443"
  server_names: []
  short_id: ""
  private_key: ""
  public_key: ""
```

کانفیگ کامل کلاینت (حالت Advanced/Explicit):

```yaml
mode: client
profile: balanced

client:
  pool_size: 3
  server:
    type: httpsmimicry
    address: your-server.example.com:443
    path: /search
    tls:
      server_name: your-server.example.com
      insecure_skip_verify: false

smux:
  version: 2
  keepalive_enabled: true
  keepalive_every: 5s
  keepalive_timeout: 15s
  max_frame_size: 32768
  max_receive_buffer: 16777216
  max_stream_buffer: 16777216

tcp:
  no_delay: true
  keepalive: 15s
  read_buffer: 8388608
  write_buffer: 8388608
  conn_limit: 5000
  copy_buffer: 65536
  auto_tune: true

security:
  token: ""
  psk: "YOUR_SHARED_PSK"
  auth_timeout: 10s

reconnect:
  min_delay: 500ms
  max_delay: 15s
  factor: 1.8
  jitter: true

obfuscation:
  enabled: false
  max_padding: 8
  max_timing_ms: 5
  min_chunk: 64
  max_chunk: 1024
  burst_enabled: false
  burst_interval: 5s
  burst_count: 0

http_mimicry:
  enabled: true
  path: /search
  browser: chrome
  fake_host: www.google.com
  cookie_enabled: true
  chunked_encoding: false

utls:
  enabled: true
  fingerprint: chrome

reality:
  enabled: false
  dest: "www.microsoft.com:443"
  server_names: []
  short_id: ""
  private_key: ""
  public_key: ""
```

### نمونه 3: Reverse + KCP برای TCP/UDP

کانفیگ کامل سرور (حالت Advanced/Explicit):

```yaml
mode: server
profile: performance

server:
  listen:
    type: kcp
    address: ":4000"
  mappings:
    - name: wg-udp
      mode: reverse
      protocol: udp
      bind: 0.0.0.0:51820
      target: 127.0.0.1:51820
    - name: app-tcp
      mode: reverse
      protocol: tcp
      bind: 0.0.0.0:9443
      target: 127.0.0.1:9443

smux:
  version: 2
  keepalive_enabled: true
  keepalive_every: 5s
  keepalive_timeout: 15s
  max_frame_size: 32768
  max_receive_buffer: 16777216
  max_stream_buffer: 16777216

tcp:
  no_delay: true
  keepalive: 15s
  read_buffer: 8388608
  write_buffer: 8388608
  conn_limit: 5000
  copy_buffer: 65536
  auto_tune: true

udp:
  read_buffer: 8388608
  write_buffer: 8388608
  max_datagram_size: 65507
  session_idle_timeout: 2m

kcp:
  data_shards: 10
  parity_shards: 3
  no_delay: 1
  interval: 20
  resend: 2
  no_congestion: 1
  mtu: 1200
  send_window: 512
  recv_window: 512

security:
  token: ""
  psk: "YOUR_SHARED_PSK"
  auth_timeout: 10s

obfuscation:
  enabled: false
  max_padding: 8
  max_timing_ms: 0
  min_chunk: 64
  max_chunk: 1024
  burst_enabled: false
  burst_interval: 5s
  burst_count: 0
```

کانفیگ کامل کلاینت (حالت Advanced/Explicit):

```yaml
mode: client
profile: performance

client:
  pool_size: 4
  server:
    type: kcp
    address: your-server.example.com:4000

smux:
  version: 2
  keepalive_enabled: true
  keepalive_every: 5s
  keepalive_timeout: 15s
  max_frame_size: 32768
  max_receive_buffer: 16777216
  max_stream_buffer: 16777216

tcp:
  no_delay: true
  keepalive: 15s
  read_buffer: 8388608
  write_buffer: 8388608
  conn_limit: 5000
  copy_buffer: 65536
  auto_tune: true

udp:
  read_buffer: 8388608
  write_buffer: 8388608
  max_datagram_size: 65507
  session_idle_timeout: 2m

kcp:
  data_shards: 10
  parity_shards: 3
  no_delay: 1
  interval: 20
  resend: 2
  no_congestion: 1
  mtu: 1200
  send_window: 512
  recv_window: 512

security:
  token: ""
  psk: "YOUR_SHARED_PSK"
  auth_timeout: 10s

reconnect:
  min_delay: 500ms
  max_delay: 15s
  factor: 1.8
  jitter: true
```

### نمونه 4: حالت Direct

```yaml
mode: server
profile: performance

server:
  listen:
    type: tcp
    address: ":8443"
  mappings:
    - name: direct-http
      mode: direct
      protocol: tcp
      bind: 127.0.0.1:18080
      target: 1.1.1.1:80

smux:
  version: 2
  keepalive_enabled: true
  keepalive_every: 5s
  keepalive_timeout: 15s
  max_frame_size: 32768
  max_receive_buffer: 16777216
  max_stream_buffer: 16777216

tcp:
  no_delay: true
  keepalive: 15s
  read_buffer: 8388608
  write_buffer: 8388608
  conn_limit: 5000
  copy_buffer: 65536
  auto_tune: true

security:
  token: ""
  psk: ""
  auth_timeout: 10s

health:
  enabled: true
  interval: 15s
```

## 📊 بنچمارک

این اعداد **نسبی** هستند و معیار قطعی جهانی نیستند. خروجی واقعی به CPU، RAM، کیفیت مسیر، RTT، Loss و رفتار endpoint بستگی دارد.

### مقایسه نسبی ترنسپورت‌ها

| ترنسپورت       | تاخیر | توان عبوری | بهره‌وری CPU | مقاومت DPI | پایداری |
| -------------- | ----: | ---------: | -----------: | ---------: | ------: |
| `tcp`          |  9/10 |       8/10 |         9/10 |       3/10 |    9/10 |
| `tls`          |  8/10 |       8/10 |         8/10 |       6/10 |    9/10 |
| `ws`           |  7/10 |       7/10 |         7/10 |       7/10 |    8/10 |
| `wss`          |  7/10 |       7/10 |         6/10 |       8/10 |    8/10 |
| `kcp`          |  8/10 |       8/10 |         6/10 |       5/10 |    7/10 |
| `quic`         |  8/10 |       8/10 |         7/10 |       7/10 |    8/10 |
| `httpmimicry`  |  6/10 |       6/10 |         6/10 |       8/10 |    7/10 |
| `httpsmimicry` |  6/10 |       6/10 |         5/10 |       9/10 |    7/10 |
| `reality`      |  8/10 |       8/10 |         7/10 |       9/10 |    8/10 |

### مقایسه نسبی پروفایل‌ها

| پروفایل         | تاخیر | توان عبوری | بهره‌وری CPU | کاربرد معمول               |
| --------------- | ----: | ---------: | -----------: | -------------------------- |
| `performance`   |  9/10 |       9/10 |         8/10 | استفاده عمومی با سرعت بالا |
| `latency`       | 10/10 |       8/10 |         8/10 | مسیرهای کم‌تاخیر           |
| `balanced`      |  8/10 |       8/10 |         8/10 | عملیات روزمره              |
| `aggressive`    |  7/10 |       9/10 |         6/10 | بیشینه throughput زیر بار  |
| `cpu-efficient` |  6/10 |       6/10 |        10/10 | VPS یا سخت‌افزار ضعیف      |
| `gaming`        | 10/10 |       7/10 |         8/10 | ترافیک real-time           |

### روش پیشنهادی اندازه‌گیری

```bash
# receiver
iperf3 -s

# sender through tunnel
iperf3 -c <target_ip> -p <target_port> -t 30
iperf3 -c <target_ip> -p <target_port> -t 30 -R

# latency
ping -c 50 <target_ip>

# service resource snapshot
systemctl status nodelay-server
systemctl status nodelay-client
```

## 🔐 نکات امنیتی

- مقدار `security.psk` در دو سمت باید یکسان باشد (یا در هر دو غیرفعال باشد)
- `insecure_skip_verify` را فقط در محیط تست استفاده کنید
- برای ترنسپورت‌های مبتنی بر TLS از گواهی معتبر استفاده کنید
- تنظیمات mimicry/obfuscation را در سمت کلاینت و سرور هماهنگ نگه دارید
