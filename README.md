## SentinelOne Collector (Scalyr Agent 2)

![Status](https://img.shields.io/badge/status-beta-yellow.svg)
![Platform](https://img.shields.io/badge/platform-Rocky%209%20%7C%20Ubuntu%2024.04-10b981.svg)
![Agent](https://img.shields.io/badge/agent-scalyr--agent--2%20v2.2.19%20(Yvette)-4f46e5.svg)
![Upstream](https://img.shields.io/badge/upstream-github.com%2Fscalyr%2Fscalyr--agent--2-6366f1.svg)

![SentinelOne Collector overview](images/masterbuilders.jpg)

Field guide and install notes for running **Scalyr Agent 2** as the **SentinelOne Collector** on **Rocky Linux 9** and **Ubuntu 24.04 LTS**, using a dedicated Python virtualenv and a simple control wrapper.

> [!TIP]
> Want to see how the sausage is made? Keep reading for the manual walkthrough.  
> In a hurry? Skip the rest and run the **TURBO installer** (auto-detects your OS and runs the right script):
>
> ```bash
> # Auto-detects Ubuntu 24.04 or Rocky Linux 9 and runs the appropriate installer
> curl -fsSL -L "https://gist.githubusercontent.com/sva-s1/de9927ea3429fa800318860a0d32c4a9/raw/turbo-collector-setup.sh" -o /tmp/turbo-collector-setup.sh && sudo bash /tmp/turbo-collector-setup.sh
> ```
>
> The auto-selector will install `curl` and `ca-certificates` using your system's package manager, then fetch and run the platform-specific installer.

> [!IMPORTANT]
> If this guide saves you time, please **star the repo on GitHub** so others can find it more easily.

Upstream agent code and full documentation live in the official project:  
[`https://github.com/scalyr/scalyr-agent-2`](https://github.com/scalyr/scalyr-agent-2)

---

### Project layout

- **Install guide (Rocky Linux 9)**: end‑to‑end venv + wrapper + systemd + starter `agent.json`  
  → [`docs/INSTALL-ROCKY9.MD`](docs/INSTALL-ROCKY9.MD)
- **Install guide (Ubuntu 24.04 LTS)**: end‑to‑end venv + wrapper + systemd + starter `agent.json`  
  → [`docs/INSTALL-UBUNTU24-04.MD`](docs/INSTALL-UBUNTU24-04.MD)
- **Install guide (air‑gapped / no‑internet)**: prep and offline install flow  
  → [`docs/INSTALL-AIRGAPPED.MD`](docs/INSTALL-AIRGAPPED.MD)
- **Upstream agent code, full docs, and changelog**  
  → [`https://github.com/scalyr/scalyr-agent-2`](https://github.com/scalyr/scalyr-agent-2)

---

### High‑level architecture

```text
┌──────────────────────────────┐
│ FortiGate / other devices    │
│  - Syslog over TCP/UDP 514   │
└──────────────┬───────────────┘
               │
          Syslog (514/tcp,514/udp)
               │
      ┌────────▼────────┐
      │ Collector VM    │
      │  Rocky 9 /      │
      │  Ubuntu 24.04    │
      │                 │
      │  scalyr-agent-2 │
      │  (Python venv)  │
      └────────┬────────┘
               │ HTTPS
               │
      ┌────────▼──────────────────────┐
      │ SentinelOne backend (XDR /    │
      │ SDL ingestion API)            │
      └───────────────────────────────┘
```

The **starter `agent.json`** shipped in this repo is configured to:

- listen for **FortiGate syslog** on **TCP/UDP 514**
- write messages into `fortigate.log`
- use the **`marketplace-fortinetfortigate-latest`** [OCSF](https://schema.ocsf.io/) parser

You can add more `syslog_monitor` entries for additional products (other firewalls, appliances, etc.); just ensure **each monitor uses a unique port (or port pair)** and distinct `message_log` / `parser` values.
