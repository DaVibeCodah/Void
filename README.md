# Vo!d — Universal Anti-Bot / Anti-DDoS Protection System

A self-optimizing, modular, edge-native protection layer. Drop it in front of
any website or API. No vendor lock-in. Full source.

---

## Architecture

```
Internet
   │
   ▼
┌──────────────────────────────────┐
│  L1: Kernel / eBPF (XDP + TC)   │  ← SYN flood drop, IP blocklist, TCP fingerprint
│  Language: C (eBPF) + Rust/Aya  │    at NIC line speed, before kernel network stack
└──────────────────┬───────────────┘
                   │
┌──────────────────▼───────────────┐
│  L2: Edge Proxy (Rust)           │  ← TLS termination, JA3/JA4, HTTP/2 fingerprint
│  hyper + tokio + rustls          │    request normalization, rate limiting, session mgmt
└──────────────────┬───────────────┘
                   │
┌──────────────────▼───────────────┐
│  L3: Request Analysis            │  ← Header anomalies, honeypot check, timing jitter,
│  (inline in edge proxy)          │    URL encoding bypass detection, param pollution
└──────────────────┬───────────────┘
                   │
┌──────────────────▼───────────────┐
│  L4: Behavior / ML Engine        │  ← Isolation Forest, LSTM sequences, Transformer
│  (Python / FastAPI)              │    coordination, DBSCAN clusters, graph community
└──────────────────┬───────────────┘
                   │
┌──────────────────▼───────────────┐
│  L5: Scoring Engine              │  ← Weighted signal aggregation → risk score 0–100+
│  (inline in edge proxy)          │    fully configurable weights per signal
└──────────────────┬───────────────┘
                   │
         ┌─────────┴──────────┐
         │  Action Dispatch   │
         └─────────┬──────────┘
    ┌──────────────┼──────────────────┬──────────────┐
    ▼              ▼                  ▼               ▼
  Allow      JS Challenge         Proof-of-Work    Block
             (score 40–60)        (score 60–80)    (score 100+)
                              WASM Challenge
                              (score 65–85)
                              CAPTCHA
                              (score 80–100)
```

---

## Directory Structure

```
void/
├── edge-proxy/          # Rust reverse proxy — the hot path
│   ├── src/
│   │   ├── main.rs        — entry point, TCP listener
│   │   ├── middleware.rs  — main pipeline orchestrator
│   │   ├── scorer.rs      — signal weighting & score aggregation
│   │   ├── normalizer.rs  — URL/header normalization engine
│   │   ├── tls_fp.rs      — JA3/JA4 TLS fingerprinting
│   │   ├── http2_fp.rs    — HTTP/2 SETTINGS fingerprint + timing
│   │   ├── ip_intel.rs    — ASN/geo/TOR/VPN classification
│   │   ├── ratelimit.rs   — sliding window + token bucket + EWMA burst
│   │   ├── session.rs     — session store, browser fingerprint, telemetry
│   │   ├── proxy.rs       — upstream forwarding + challenge page builder
│   │   └── config.rs      — config loading
│   ├── Cargo.toml
│   └── Dockerfile
│
├── behavior-engine/     # Python ML engine — called async from edge proxy
│   ├── main.py            — FastAPI app, model lifecycle, background tasks
│   ├── models/
│   │   ├── isolation_forest.py  — unsupervised anomaly detection
│   │   ├── sequence_lstm.py     — bot session navigation classifier
│   │   ├── transformer.py       — cross-session coordination detector
│   │   ├── dbscan_cluster.py    — fingerprint bot farm clustering
│   │   └── graph_engine.py      — Louvain community detection on traffic graph
│   ├── analyzers/
│   │   ├── timing.py       — inter-request jitter & burst analysis
│   │   └── geo_velocity.py — impossible location transition detection
│   ├── api/
│   │   ├── routes.py       — challenge verification, telemetry analysis
│   │   └── schemas.py      — Pydantic models
│   ├── requirements.txt
│   └── Dockerfile
│
├── ebpf/               # Kernel-space programs
│   └── src/
│       ├── shield.bpf.c   — XDP SYN guard + TC rate monitor (C/eBPF)
│       └── loader.rs      — Aya-based eBPF loader (Rust)
│
├── config/
│   ├── edge-config.yml    — full protection policy (rates, scores, honeypots)
│   └── prometheus.yml     — metrics scrape config
│
├── docker/
│   └── docker-compose.yml — full stack: proxy + ML engine + Redis + Grafana
│
└── scripts/
    └── deploy.sh          — one-command deploy
```

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/yourorg/void
cd void

# 2. Deploy (replace with your backend URL)
./scripts/deploy.sh --upstream http://your-backend:3000

# 3. Point your DNS / load balancer at port 8080
```

---

## Signal Score Reference

| Signal | Score Delta | Notes |
|---|---|---|
| `navigator.webdriver = true` | +60 | Direct automation detection |
| `automation_framework_detected` | +55 | Puppeteer/Playwright/Selenium |
| `honeypot_accessed` | +50 | Any access to trap endpoint |
| `request_flood` | +45 | Flood pattern detected |
| `fp_in_known_bot_cluster` | +45 | DBSCAN/graph cluster member |
| `canary_triggered` | +60 | Hidden canary URL accessed |
| `rate_limit_violated` | +40 | Per-IP or per-endpoint limit |
| `slow_http_attack` | +40 | Slowloris / slow POST |
| `geo_velocity_violation` | +40 | Impossible location change |
| `is_tor_exit` | +35 | TOR exit node |
| `burst_detected` | +35 | EWMA spike ≥5x baseline |
| `no_mouse_activity` | +30 | No client-side mouse events |
| `user_agent_bot` | +30 | UA contains bot/spider/curl |
| `linear_mouse_movement` | +25 | Straight-line cursor paths |
| `ja4_suspicious` | +25 | TLS fingerprint mismatch |
| `screen_size_zero` | +25 | Headless browser indicator |
| `chunked_encoding_conflict` | +25 | RFC 7230 TE+CL violation |
| `no_languages` | +20 | navigator.languages empty |
| `is_datacenter_asn` | +20 | AWS/GCP/Azure/DO/Vultr |
| `zero_timing_jitter` | +20 | <2ms stddev across requests |
| `navigator_webdriver` | +60 | Highest-confidence bot signal |

---

## Challenge Escalation

```
Score  0–20   →  Allow (pass through)
Score 20–40   →  Invisible challenge (silent JS probe, telemetry collection)
Score 40–60   →  JavaScript challenge (environment validation + fingerprint)
Score 60–80   →  Proof-of-Work (SHA256 partial collision, difficulty 4–20 bits)
Score 65–85   →  WASM challenge (WebAssembly compute task)
Score 80–100  →  CAPTCHA
Score 100+    →  Hard block (403, IP blacklisted at kernel via eBPF)
```

PoW difficulty scales linearly within the 60–80 band:
- Score 60 → 4 bits  (~65K SHA256 attempts)
- Score 70 → 12 bits (~4B attempts)
- Score 80 → 20 bits (~1T attempts, CAPTCHA preferred at this point)

---

## ML Models

| Model | Type | Purpose |
|---|---|---|
| Isolation Forest | Unsupervised | Feature-space anomaly detection, no labels needed |
| LSTM + Attention | Supervised | Session endpoint sequence → bot probability |
| Transformer Encoder | Semi-supervised | Cross-session coordination (distributed attacks) |
| DBSCAN | Unsupervised | Fingerprint bot farm cluster detection |
| Graph (Louvain) | Unsupervised | Traffic graph community detection for botnets |

All models retrain nightly on accumulated traffic + confirmed labels from CAPTCHA completions.

---

## Deployment Requirements

| Component | Requirement |
|---|---|
| Edge Proxy (Rust) | Any Linux x86_64, 2+ CPU cores, 512MB RAM minimum |
| eBPF Programs | Linux kernel ≥ 5.19, NET_ADMIN + SYS_ADMIN caps |
| Behavior Engine | Python 3.12+, 4+ CPU cores, 4GB RAM (for ML models) |
| Redis | 4GB RAM recommended for rate limit state |
| GeoIP databases | Free MaxMind GeoLite2 (City + ASN) |

eBPF is optional — the system falls back to software-only mode automatically if
the kernel version is insufficient or capabilities are unavailable.

---

## Windows Support

Vo!d runs on Windows via Docker Desktop. All detection and ML layers are fully cross-platform.

```powershell
# PowerShell (run as Administrator for best performance)
.\scripts\deploy-windows.ps1 -Upstream http://your-backend:3000
```

### What works on Windows

| Feature | Linux | Windows |
|---|---|---|
| TLS fingerprinting (JA3/JA4) | ✓ | ✓ |
| HTTP/2 fingerprinting | ✓ | ✓ |
| Request normalization | ✓ | ✓ |
| All rate limiting scopes | ✓ | ✓ |
| Session & browser fingerprinting | ✓ | ✓ |
| IP intelligence (GeoIP/ASN/TOR) | ✓ | ✓ |
| ML behavior engine (all 5 models) | ✓ | ✓ |
| Challenge system (PoW/WASM/CAPTCHA) | ✓ | ✓ |
| Honeypots & canaries | ✓ | ✓ |
| Scoring & escalation engine | ✓ | ✓ |
| eBPF XDP (NIC-level, pre-kernel) | ✓ | ✗ * |
| eBPF TC (kernel TCP inspection) | ✓ | ✗ * |

\* On Windows, SYN flood protection runs as a software in-process filter (`platform.rs`).
This provides identical protection with ~5-10% more latency under active SYN floods
compared to the eBPF XDP path which drops packets before the kernel network stack.
All other protection layers are identical.

### Requirements (Windows)
- Windows 10 version 2004+ or Windows Server 2019+
- Docker Desktop 4.x with WSL2 backend
- 8GB RAM recommended
- Run PowerShell as Administrator for WFP packet filtering
