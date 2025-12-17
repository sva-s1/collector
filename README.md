## SentinelOne Collector (Scalyr Agent 2)

![Status](https://img.shields.io/badge/status-experimental-orange.svg)
![Platform](https://img.shields.io/badge/platform-Rocky%20Linux%209-10b981.svg)
![Agent](https://img.shields.io/badge/agent-scalyr--agent--2%20v2.2.19%20(Yvette)-4f46e5.svg)
![Upstream](https://img.shields.io/badge/upstream-github.com%2Fscalyr%2Fscalyr--agent--2-6366f1.svg)

![SentinelOne Collector overview](images/readme.jpg)

Field guide and install notes for running **Scalyr Agent 2** as the **SentinelOne Collector** on Rocky Linux 9 and similar distros, using a dedicated Python virtualenv and a simple control wrapper.

> [!TIP]
> If this guide saves you time, please **star the repo on GitHub** so others can find it more easily.

Upstream agent code and full documentation live in the official project:  
[`https://github.com/scalyr/scalyr-agent-2`](https://github.com/scalyr/scalyr-agent-2)

---

### Project layout

- **Install guide (online Rocky 9)**: end‑to‑end venv + wrapper + systemd + starter `agent.json`  
  → [`docs/INSTALL.md`](docs/INSTALL.md)
- **Install guide (air‑gapped / no‑internet)**: prep and offline install flow  
  → [`docs/INSTALL-AIRGAPPED.md`](docs/INSTALL-AIRGAPPED.MD)
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
      │  Rocky Linux 9  │
      │                 │
      │  scalyr-agent-2 │
      │  (Python venv)  │
      └────────┬────────┘
               │ HTTPS
               │
      ┌────────▼──────────────────────┐
      │ SentinelOne backend (XDR /    │
      │ Scalyr SaaS ingestion API)    │
      └───────────────────────────────┘
```

The **starter `agent.json`** shipped in this repo is configured to:

- listen for **FortiGate syslog** on **TCP/UDP 514**
- write messages into `fortigate.log`
- use the **`marketplace-fortinetfortigate-latest`** parser

You can add more `syslog_monitor` entries for additional products (other firewalls, appliances, etc.); just ensure **each monitor uses a unique port (or port pair)** and distinct `message_log` / `parser` values.
