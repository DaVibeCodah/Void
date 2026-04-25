"""
Transformer-Based Coordination Detector
Detects coordinated multi-session attacks by analyzing cross-session behavioral
patterns using a lightweight Transformer encoder.

Attack scenario: 100k IPs each sending 1 req/10s — undetectable per-IP,
but globally the traffic is coordinated. This model finds the coordination.
"""
import torch
import torch.nn as nn
import numpy as np
import time
import os
import logging
from collections import deque, defaultdict
from dataclasses import dataclass

logger = logging.getLogger(__name__)

MODEL_PATH = os.environ.get("TRANSFORMER_MODEL_PATH", "/models/coordination_transformer.pt")
WINDOW_SIZE = 60      # 60-second analysis window
MAX_IPS_PER_WINDOW = 10_000
EMBED_DIM = 32
NUM_HEADS = 4
NUM_LAYERS = 2
COORDINATION_THRESHOLD = 0.7


@dataclass
class IPSignature:
    ip: str
    timestamp: float
    endpoint: str
    ua_hash: str
    fp_hash: str
    asn: int


class CoordinationTransformer(nn.Module):
    """
    Analyzes a window of IP signatures to detect coordination.
    Input: batch of IP feature vectors in time order
    Output: coordination score [0, 1]
    """
    def __init__(self, input_dim: int, embed_dim: int, num_heads: int, num_layers: int):
        super().__init__()
        self.input_proj = nn.Linear(input_dim, embed_dim)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=embed_dim,
            nhead=num_heads,
            dim_feedforward=embed_dim * 4,
            dropout=0.1,
            batch_first=True,
        )
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        self.classifier = nn.Sequential(
            nn.Linear(embed_dim, 16),
            nn.ReLU(),
            nn.Linear(16, 1),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (1, T, input_dim)
        projected = self.input_proj(x)              # (1, T, embed_dim)
        encoded   = self.encoder(projected)         # (1, T, embed_dim)
        pooled    = encoded.mean(dim=1)             # (1, embed_dim)
        return self.classifier(pooled).squeeze(-1)  # (1,)


class CoordinationDetector:
    def __init__(self):
        self.window: deque[IPSignature] = deque()
        self.ip_rates: defaultdict[str, list[float]] = defaultdict(list)
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model: CoordinationTransformer | None = None
        self._load_or_init()

    def _load_or_init(self):
        # Input: [timestamp_norm, endpoint_hash, ua_hash, fp_hash, asn_norm, rate]
        input_dim = 6
        self.model = CoordinationTransformer(input_dim, EMBED_DIM, NUM_HEADS, NUM_LAYERS)

        if os.path.exists(MODEL_PATH):
            try:
                state = torch.load(MODEL_PATH, map_location=self.device)
                self.model.load_state_dict(state)
                logger.info("Loaded coordination transformer from disk")
            except Exception as e:
                logger.warning(f"Failed to load transformer: {e}")

        self.model.to(self.device)
        self.model.eval()

    def _featurize_signature(self, sig: IPSignature, window_start: float) -> list[float]:
        def hash_to_norm(h: str) -> float:
            if not h:
                return 0.0
            try:
                return int(h[:8], 16) / 0xFFFFFFFF
            except (ValueError, TypeError):
                return 0.0

        t_norm = (sig.timestamp - window_start) / WINDOW_SIZE
        ep_hash = hash_to_norm(self._simple_hash(sig.endpoint))
        ua_hash = hash_to_norm(sig.ua_hash)
        fp_hash = hash_to_norm(sig.fp_hash)
        asn_norm = (sig.asn % 65536) / 65536.0
        rate = min(len(self.ip_rates.get(sig.ip, [])) / 100.0, 1.0)

        return [t_norm, ep_hash, ua_hash, fp_hash, asn_norm, rate]

    @staticmethod
    def _simple_hash(s: str) -> str:
        if not s:
            return "00000000"
        import hashlib
        return hashlib.md5(s.encode()).hexdigest()[:8]

    def add_request(self, sig: IPSignature):
        now = time.time()
        self.window.append(sig)
        self.ip_rates[sig.ip].append(now)

        # Prune old entries
        cutoff = now - WINDOW_SIZE
        while self.window and self.window[0].timestamp < cutoff:
            self.window.popleft()
        for ip in list(self.ip_rates.keys()):
            self.ip_rates[ip] = [t for t in self.ip_rates[ip] if t > cutoff]
            if not self.ip_rates[ip]:
                del self.ip_rates[ip]

    def score(self, ip: str, signals) -> float:
        """
        Returns coordination score [0, 1].
        High score = this request appears to be part of a coordinated attack.
        """
        if len(self.window) < 20:
            return self._heuristic_coordination_score()

        now = time.time()
        window_start = now - WINDOW_SIZE

        # Sample up to 200 recent signatures for transformer input
        recent = list(self.window)[-200:]
        features = [self._featurize_signature(sig, window_start) for sig in recent]
        X = torch.tensor([features], dtype=torch.float32, device=self.device)  # (1, T, 6)

        with torch.no_grad():
            score = self.model(X).item()

        return float(score)

    def _heuristic_coordination_score(self) -> float:
        """
        Fast heuristic when transformer not ready.
        Detects distributed low-rate attack pattern:
        Many unique IPs hitting same endpoints at similar rate.
        """
        if len(self.window) < 5:
            return 0.0

        now = time.time()
        cutoff = now - WINDOW_SIZE

        # Count unique IPs and endpoint distribution
        recent = [s for s in self.window if s.timestamp > cutoff]
        if not recent:
            return 0.0

        unique_ips = len(set(s.ip for s in recent))
        endpoint_counter: defaultdict[str, int] = defaultdict(int)
        for s in recent:
            endpoint_counter[s.endpoint] += 1

        # Attack signature: many IPs, few endpoints, low per-IP rate
        if unique_ips < 10:
            return 0.0

        top_endpoint_fraction = max(endpoint_counter.values()) / len(recent)
        per_ip_rate = len(recent) / max(unique_ips, 1)

        # Many IPs → same endpoint → low per-IP rate = distributed attack
        if top_endpoint_fraction > 0.6 and per_ip_rate < 5:
            score = min(1.0, top_endpoint_fraction * (unique_ips / 100.0))
            if score > 0.5:
                logger.warning(
                    f"Distributed low-rate attack detected: "
                    f"{unique_ips} IPs, {len(recent)} reqs/{WINDOW_SIZE}s, "
                    f"top_endpoint={top_endpoint_fraction:.2f}, score={score:.2f}"
                )
            return score

        return 0.0

    def retrain(self):
        """Placeholder for online learning pipeline."""
        pass
