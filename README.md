## SentinelOne Collector (Scalyr Agent 2)

![Status](https://img.shields.io/badge/status-beta-yellow.svg)
![Platform](https://img.shields.io/badge/platform-Rocky%20Linux%209-10b981.svg)
![Agent](https://img.shields.io/badge/agent-scalyr--agent--2%20v2.2.19%20(Yvette)-4f46e5.svg)
![Upstream](https://img.shields.io/badge/upstream-github.com%2Fscalyr%2Fscalyr--agent--2-6366f1.svg)

![SentinelOne Collector overview](images/masterbuilders.jpg)

Field guide and install notes for running **Scalyr Agent 2** as the **SentinelOne Collector** on Rocky Linux 9 and similar distros, using a dedicated Python virtualenv and a simple control wrapper.

> [!TIP]
> Want to see how the sausage is made? Keep reading for the manual walkthrough.  
> In a hurry? Skip the rest and run the **TURBO installer** (TLDR for the rest of us 😄):
>
> ```bash
> sudo dnf -y install curl ca-certificates >/dev/null && curl -fsSL -L "https://gist.githubusercontent.com/sva-s1/05a6c839ea650713892dbc49257dc6f5/raw/turbo-collector-setup.sh" -o /tmp/turbo-collector-setup.sh && sudo bash /tmp/turbo-collector-setup.sh
> ```

> [!IMPORTANT]
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
      │ SDL ingestion API)            │
      └───────────────────────────────┘
```

The **starter `agent.json`** shipped in this repo is configured to:

- listen for **FortiGate syslog** on **TCP/UDP 514**
- write messages into `fortigate.log`
- use the **`marketplace-fortinetfortigate-latest`** [OCSF](https://schema.ocsf.io/) parser

You can add more `syslog_monitor` entries for additional products (other firewalls, appliances, etc.); just ensure **each monitor uses a unique port (or port pair)** and distinct `message_log` / `parser` values.
