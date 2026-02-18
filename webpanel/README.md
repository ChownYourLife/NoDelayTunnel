# NoDelay Web Panel

Web dashboard for NoDelay tunnel management.

Features:
- Host resources (CPU, memory, disk, load, uptime, host network throughput)
- Tunnel list with service status and estimated per-service throughput
- Create tunnel instances
- Edit tunnel YAML configs
- Start/stop/restart/delete tunnel services
- View recent journal logs per tunnel

Run manually:
```bash
sudo python3 webpanel/server.py --host 0.0.0.0 --port 8787
```

Authentication:
- Basic Auth is enabled when these env vars are set:
  - `NODELAY_WEBPANEL_USER`
  - `NODELAY_WEBPANEL_PASS`
- You can store them in `webpanel/.env` (same directory as `server.py`).

Use `deploy.py` Operations menu to install it as systemd service.
