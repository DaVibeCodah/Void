 # Void
Vo!d is a drop-in bot and DDoS protection. No vendor. No fees. Full source.


# Vo!d

**Self-hosted anti-bot and DDoS protection. Drop it in front of any website or API.**

Vo!d is a multi-layer traffic protection system that combines a high-performance Rust edge proxy, a Python ML engine, and optional eBPF kernel programs. It detects and stops bots, scrapers, credential stuffers, and DDoS attacks — with no third-party vendor, no per-request fees, and full source access.

---

## How It Works

```
Internet
   │
   ▼
┌──────────────────────────────────────┐
│  L1: eBPF / XDP  (optional)          │  SYN flood drop, IP blocklist at NIC line
│  C (eBPF) + Rust/Aya                 │  speed — before the kernel network stack
└───────────────────┬──────────────────┘
                    │
┌───────────────────▼──────────────────┐
│  L2: Edge Proxy  (Rust)              │  TLS termination, JA3/JA4 fingerprinting,
│  hyper + tokio + rustls              │  HTTP/2 fingerprinting, request normalization,
└───────────────────┬──────────────────┘  rate limiting, session management
                    │
┌───────────────────▼──────────────────┐
│  L3: Request Analysis  (inline)      │  Header anomalies, honeypots, timing jitter,
│                                      │  URL encoding bypass, parameter pollution
└───────────────────┬──────────────────┘
                    │
┌───────────────────▼──────────────────┐
│  L4: ML Behavior Engine  (Python)    │  Isolation Forest, LSTM, Transformer,
│  FastAPI + scikit-learn + PyTorch    │  DBSCAN clustering, graph community detection
└───────────────────┬──────────────────┘
                    │
┌───────────────────▼──────────────────┐
│  L5: Scoring Engine  (inline)        │  Weighted signal aggregation → risk score
└───────────────────┬──────────────────┘  0–100+, fully configurable
                    │
          ┌─────────┴──────────┐
          │   Action Dispatch  │
          └─────────┬──────────┘
     ┌───────────────┼───────────────────┬─────────────┐
     ▼               ▼                   ▼              ▼
   Allow       JS Challenge          Proof-of-Work    Block
               (score 40–60)         (score 60–80)    (score 100+)
                               WASM Challenge
                               (score 65–85)
                               CAPTCHA
                               (score 80–100)
```

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/yourname/void
cd void

# 2. Deploy (replace with your backend URL)
./scripts/deploy.sh --upstream http://your-backend:3000

# 3. Point your DNS / load balancer at port 8080
```

The deploy script handles secrets, TLS certificate generation, Docker builds, and stack startup automatically.

**Windows (PowerShell as Administrator):**
```powershell
.\scripts\deploy-windows.ps1 -Upstream http://your-backend:3000
```

---

## Requirements

| Component | Requirement |
|---|---|
| Edge Proxy (Rust) | Linux or Windows x86_64, 2+ cores, 512MB RAM |
| Behavior Engine (Python) | Python 3.12+, 4+ cores, 4GB RAM |
| Redis | 4GB RAM recommended |
| GeoIP databases | Free [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) (City + ASN) |
| eBPF (optional) | Linux kernel ≥ 5.19, `NET_ADMIN` + `SYS_ADMIN` caps |
| Docker | Docker + Docker Compose (all platforms) |

eBPF is optional. If the kernel version is insufficient or capabilities are unavailable, Vo!d falls back to software-only mode automatically.

---

## Directory Structure

```
void/
├── edge-proxy/             # Rust reverse proxy — the hot path
│   ├── src/
│   │   ├── main.rs         — TCP listener, entry point
│   │   ├── middleware.rs   — main pipeline orchestrator
│   │   ├── scorer.rs       — signal weighting & score aggregation
│   │   ├── normalizer.rs   — URL/header normalization
│   │   ├── tls_fp.rs       — JA3/JA4 TLS fingerprinting
│   │   ├── http2_fp.rs     — HTTP/2 SETTINGS fingerprint + timing
│   │   ├── ip_intel.rs     — ASN/geo/TOR/VPN classification
│   │   ├── ratelimit.rs    — sliding window + token bucket + EWMA burst
│   │   ├── session.rs      — session store, browser fingerprint, telemetry
│   │   ├── proxy.rs        — upstream forwarding + challenge page serving
│   │   └── config.rs       — config loading from env + YAML
│   ├── Cargo.toml
│   └── Dockerfile
│
├── behavior-engine/        # Python ML engine — called async from edge proxy
│   ├── main.py             — FastAPI app, model lifecycle, background tasks
│   ├── models/
│   │   ├── isolation_forest.py  — unsupervised anomaly detection
│   │   ├── sequence_lstm.py     — bot session navigation classifier
│   │   ├── transformer.py       — cross-session coordination detector
│   │   ├── dbscan_cluster.py    — fingerprint bot farm clustering
│   │   └── graph_engine.py      — Louvain community detection on traffic graph
│   ├── analyzers/
│   │   ├── timing.py            — inter-request jitter & burst analysis
│   │   └── geo_velocity.py      — impossible location transition detection
│   ├── api/
│   │   ├── routes.py            — challenge verification, telemetry
│   │   └── schemas.py           — Pydantic request/response models
│   ├── requirements.txt
│   └── Dockerfile
│
├── ebpf/                   # Kernel-space programs
│   └── src/
│       ├── shield.bpf.c    — XDP SYN guard + TC rate monitor (C/eBPF)
│       └── loader.rs       — Aya-based eBPF loader (Rust)
│
├── config/
│   ├── edge-config.yml     — protection policy (rates, scores, honeypots)
│   └── prometheus.yml      — metrics scrape config
│
├── docker/
│   ├── docker-compose.yml           — full Linux stack
│   └── docker-compose.windows.yml  — Windows/Docker Desktop stack
│
└── scripts/
    ├── deploy.sh            — one-command Linux deploy
    └── deploy-windows.ps1  — one-command Windows deploy
```

---

## ML Models

All models start from scratch on first run and improve automatically from accumulated traffic. Labeled data from CAPTCHA completions and human review feeds back into nightly retraining.

| Model | Type | Purpose |
|---|---|---|
| Isolation Forest | Unsupervised | Feature-space anomaly detection — no labels needed to start |
| LSTM + Attention | Supervised | Session endpoint sequence → bot probability |
| Transformer Encoder | Semi-supervised | Cross-session coordination detection for distributed attacks |
| DBSCAN | Unsupervised | Fingerprint-based bot farm cluster detection |
| Graph (Louvain) | Unsupervised | Traffic graph community detection for botnets |

Models retrain every 24 hours on the Redis training buffer. The graph runs community detection every 5 minutes and pushes confirmed bot fingerprints into the DBSCAN cluster store in real time.

---

## Signal Score Reference

| Signal | Score | Notes |
|---|---|---|
| `navigator.webdriver = true` | +60 | Direct automation detection |
| `canary_triggered` | +60 | Hidden canary URL accessed |
| `automation_framework_detected` | +55 | Puppeteer / Playwright / Selenium |
| `honeypot_accessed` | +50 | Any trap endpoint hit |
| `fp_in_known_bot_cluster` | +45 | DBSCAN/graph cluster member |
| `request_flood` | +45 | Flood pattern detected |
| `geo_velocity_violation` | +40 | Impossible location transition |
| `rate_limit_violated` | +40 | Per-IP or per-endpoint limit exceeded |
| `slow_http_attack` | +40 | Slowloris / slow POST detected |
| `is_tor_exit` | +35 | TOR exit node |
| `burst_detected` | +35 | EWMA spike ≥ 5× baseline |
| `no_mouse_activity` | +30 | No client-side mouse events |
| `user_agent_bot` | +30 | UA contains bot/spider/curl |
| `linear_mouse_movement` | +25 | Straight-line cursor paths |
| `ja4_suspicious` | +25 | TLS fingerprint mismatch |
| `screen_size_zero` | +25 | Headless browser indicator |
| `chunked_encoding_conflict` | +25 | RFC 7230 TE+CL violation |
| `is_datacenter_asn` | +20 | AWS / GCP / Azure / DO / Vultr |
| `no_languages` | +20 | `navigator.languages` empty |
| `zero_timing_jitter` | +20 | < 2ms stddev across requests |

Scores are additive and weighted. All weights are configurable in `config/edge-config.yml`.

---

## Challenge Escalation

| Score | Action |
|---|---|
| 0 – 20 | Allow (pass through) |
| 20 – 40 | Invisible challenge (silent JS probe + telemetry collection) |
| 40 – 60 | JavaScript challenge (environment validation + fingerprint) |
| 60 – 80 | Proof-of-Work (SHA256 partial collision, difficulty 4–20 bits) |
| 65 – 85 | WASM challenge (WebAssembly compute task) |
| 80 – 100 | CAPTCHA |
| 100+ | Hard block (403 + IP blacklisted at kernel via eBPF) |

PoW difficulty scales linearly with score in the 60–80 band:
- Score 60 → 4 bits (~65K SHA256 hashes)
- Score 70 → 12 bits (~4B hashes)
- Score 80 → 20 bits (~1T hashes — CAPTCHA preferred at this point)

---

## Configuration

All protection policy is in `config/edge-config.yml`. No code changes needed.

```yaml
scoring:
  block_threshold:        100
  captcha_threshold:       80
  pow_threshold:           60
  js_challenge_threshold:  40
  invisible_threshold:     20

rate_limits:
  per_ip:
    rps: 100
    burst: 200
    window_seconds: 60
    action: challenge

  endpoints:
    "/api/auth/login":
      rps: 5
      burst: 10
      window_seconds: 60
      action: block

honeypots:
  paths:
    - "/.env"
    - "/.git/config"
    - "/wp-login.php"
    # ... add your own
```

Full reference with all options is in [`config/edge-config.yml`](config/edge-config.yml).

---

## Metrics & Monitoring

Prometheus metrics are exposed at `/__void/metrics`. A Grafana dashboard is included in the Docker Compose stack — available at `http://localhost:3000` after deploy.

---

## Windows Support

All detection and ML layers run on Windows via Docker Desktop. The only difference is eBPF, which requires Linux.

| Feature | Linux | Windows |
|---|---|---|
| TLS fingerprinting (JA3/JA4) | ✓ | ✓ |
| HTTP/2 fingerprinting | ✓ | ✓ |
| Request normalization | ✓ | ✓ |
| Rate limiting (all scopes) | ✓ | ✓ |
| Session & browser fingerprinting | ✓ | ✓ |
| IP intelligence (GeoIP / ASN / TOR) | ✓ | ✓ |
| ML behavior engine (all 5 models) | ✓ | ✓ |
| Challenge system (PoW / WASM / CAPTCHA) | ✓ | ✓ |
| Honeypots & canaries | ✓ | ✓ |
| Scoring & escalation engine | ✓ | ✓ |
| eBPF XDP (NIC-level, pre-kernel) | ✓ | ✗ * |
| eBPF TC (kernel TCP inspection) | ✓ | ✗ * |

\* On Windows, SYN flood protection runs as a software in-process filter (`platform.rs`). Protection is equivalent with ~5–10% more latency under active SYN floods compared to the eBPF XDP path.

---

## Tech Stack

| Layer | Language / Framework |
|---|---|
| Edge proxy | Rust — hyper, tokio, rustls, h2 |
| ML engine | Python — FastAPI, scikit-learn, PyTorch, NetworkX |
| eBPF programs | C (eBPF) + Rust (Aya loader) |
| Session / rate limit state | Redis |
| Metrics | Prometheus + Grafana |
| Deployment | Docker Compose |

---

## License

Business Source License (BUSL 1.1)
