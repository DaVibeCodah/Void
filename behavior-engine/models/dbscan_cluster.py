"""
DBSCAN Fingerprint Clusterer
Finds dense clusters of near-identical browser fingerprints.
Bot farms use the same fingerprint spoofed across thousands of IPs.

Uses locality-sensitive hashing for efficient approximate matching,
then DBSCAN for cluster refinement.
"""
import numpy as np
import hashlib
import logging
import time
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from collections import defaultdict, deque
from dataclasses import dataclass

logger = logging.getLogger(__name__)

MAX_BUFFER = 100_000
CLUSTER_TTL = 86400  # 24 hours


@dataclass
class FingerprintVector:
    hash: str
    canvas_hash: str
    webgl_hash: str
    font_hash: str
    screen_w: int
    screen_h: int
    tz_offset: int
    hardware_concurrency: int
    device_memory: float
    plugin_count: int
    touch_points: int
    timestamp: float


class FingerprintClusterer:
    def __init__(self):
        self.buffer: deque[FingerprintVector] = deque(maxlen=MAX_BUFFER)
        self.known_bot_clusters: dict[str, float] = {}  # hash -> last_seen
        self.cluster_labels: dict[str, int] = {}  # hash -> cluster_id
        self._last_cluster_run = 0

    def vectorize(self, fp: FingerprintVector) -> np.ndarray:
        """Convert fingerprint to numeric feature vector."""
        # Normalize hashes to numeric via first 8 hex chars → int
        def hash_to_float(h: str) -> float:
            if not h:
                return 0.0
            try:
                return int(h[:8], 16) / 0xFFFFFFFF
            except ValueError:
                return 0.0

        return np.array([
            hash_to_float(fp.canvas_hash),
            hash_to_float(fp.webgl_hash),
            hash_to_float(fp.font_hash),
            fp.screen_w / 4096.0,
            fp.screen_h / 4096.0,
            (fp.tz_offset + 720) / 1440.0,
            fp.hardware_concurrency / 32.0,
            fp.device_memory / 64.0,
            fp.plugin_count / 20.0,
            float(fp.touch_points > 0),
        ], dtype=np.float32)

    def add_fingerprint(self, fp: FingerprintVector):
        self.buffer.append(fp)

        # Run clustering every 5 minutes or every 10k samples
        now = time.time()
        if now - self._last_cluster_run > 300 or len(self.buffer) % 10000 == 0:
            self.run_clustering()

    def run_clustering(self):
        """Run DBSCAN on buffered fingerprints to find bot clusters."""
        if len(self.buffer) < 50:
            return

        fps = list(self.buffer)
        X = np.array([self.vectorize(fp) for fp in fps])
        X_scaled = StandardScaler().fit_transform(X)

        # DBSCAN: eps tuned for fingerprint similarity
        # eps=0.1 means fingerprints within 10% distance are neighbors
        db = DBSCAN(eps=0.08, min_samples=5, n_jobs=-1)
        labels = db.fit_predict(X_scaled)

        # Group by cluster label
        cluster_groups: dict[int, list[FingerprintVector]] = defaultdict(list)
        for fp, label in zip(fps, labels):
            if label != -1:  # -1 = noise/outlier
                cluster_groups[label].append(fp)

        new_bot_clusters = 0
        for cluster_id, cluster_fps in cluster_groups.items():
            if len(cluster_fps) < 5:
                continue

            # Check if all FPs in cluster share the same canvas/webgl hash
            # (indicating same actual browser config = bot farm)
            canvas_hashes = set(fp.canvas_hash for fp in cluster_fps if fp.canvas_hash)
            webgl_hashes  = set(fp.webgl_hash for fp in cluster_fps if fp.webgl_hash)

            # Highly similar fingerprints across many entries = bot farm
            is_bot_cluster = (
                len(canvas_hashes) <= 2  # same canvas rendering
                and len(webgl_hashes) <= 2  # same GPU
                and len(cluster_fps) >= 5
            )

            for fp in cluster_fps:
                self.cluster_labels[fp.hash] = cluster_id
                if is_bot_cluster:
                    self.known_bot_clusters[fp.hash] = time.time()

            if is_bot_cluster:
                new_bot_clusters += 1
                logger.warning(
                    f"Bot cluster detected: id={cluster_id}, size={len(cluster_fps)}, "
                    f"canvas_variants={len(canvas_hashes)}, webgl_variants={len(webgl_hashes)}"
                )

        # Clean expired cluster entries
        cutoff = time.time() - CLUSTER_TTL
        self.known_bot_clusters = {
            h: ts for h, ts in self.known_bot_clusters.items()
            if ts > cutoff
        }

        self._last_cluster_run = time.time()
        if new_bot_clusters:
            logger.info(f"DBSCAN: {new_bot_clusters} new bot clusters detected, "
                        f"{len(self.known_bot_clusters)} total known bot FPs")

    def is_in_known_cluster(self, fp_hash: str) -> bool:
        return fp_hash in self.known_bot_clusters

    def add_to_known_cluster(self, fp_hash: str):
        """Manually mark a fingerprint as bot-cluster member (from graph engine)."""
        self.known_bot_clusters[fp_hash] = time.time()

    def stats(self) -> dict:
        return {
            "buffer_size": len(self.buffer),
            "known_bot_fps": len(self.known_bot_clusters),
            "cluster_labels": len(self.cluster_labels),
        }
