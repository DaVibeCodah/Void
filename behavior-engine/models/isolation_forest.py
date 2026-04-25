"""
Isolation Forest Anomaly Detector
Detects abnormal request patterns in high-dimensional feature space.
No labeled data required — operates purely on unsupervised anomaly isolation.
"""
import numpy as np
import pickle
import os
import logging
from collections import deque
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

MODEL_PATH = os.environ.get("MODEL_PATH", "/models/isolation_forest.pkl")
TRAINING_BUFFER_SIZE = 50_000
CONTAMINATION = 0.05  # Expected fraction of anomalies


class IsolationForestDetector:
    def __init__(self):
        self.model: IsolationForest | None = None
        self.scaler = StandardScaler()
        self.training_buffer: deque = deque(maxlen=TRAINING_BUFFER_SIZE)
        self.feedback_labels: dict = {}  # session_id -> bool (is_bot)
        self._load_or_init()

    def _load_or_init(self):
        if os.path.exists(MODEL_PATH):
            try:
                with open(MODEL_PATH, "rb") as f:
                    saved = pickle.load(f)
                    self.model  = saved["model"]
                    self.scaler = saved["scaler"]
                logger.info("Loaded Isolation Forest model from disk")
                return
            except Exception as e:
                logger.warning(f"Failed to load model: {e}")

        # Initialize with default parameters
        self.model = IsolationForest(
            n_estimators=200,
            max_samples="auto",
            contamination=CONTAMINATION,
            random_state=42,
            n_jobs=-1,
        )
        logger.info("Initialized fresh Isolation Forest model")

    def extract_features(self, signals) -> np.ndarray:
        """
        Extract a fixed-length feature vector from the signal set.
        All features normalized to [0, 1] range.
        """
        def b(val) -> float:
            return 1.0 if val else 0.0

        features = np.array([
            # Network features
            b(signals.is_datacenter_asn),
            b(signals.is_tor_exit),
            b(signals.is_vpn_proxy),
            float(signals.ip_reputation_score or 0),

            # TLS features
            b(signals.ja3_suspicious),
            b(signals.ja4_suspicious),
            b(signals.tls_cipher_mismatch),
            b(signals.tls_ticket_reuse),

            # HTTP features
            b(signals.h2_settings_mismatch),
            b(signals.h2_pseudo_header_order_wrong),
            b(signals.user_agent_absent),
            b(signals.user_agent_bot),
            b(signals.accept_language_absent),
            b(signals.header_order_anomaly),

            # Request pattern
            b(signals.rate_limit_violated),
            b(signals.burst_detected),
            b(signals.zero_timing_jitter),
            b(signals.honeypot_accessed),
            b(signals.slow_http_attack),
            min(float(signals.url_encoding_layers or 0) / 5.0, 1.0),

            # Browser behavior
            b(signals.no_mouse_activity),
            b(signals.linear_mouse_movement),
            b(signals.zero_scroll_inertia),
            b(signals.no_keyboard_jitter),
            b(signals.no_focus_events),
            b(signals.navigator_webdriver),
            b(signals.plugin_count_zero),
            b(signals.screen_size_zero),
            b(signals.no_languages),

            # Fingerprint
            b(signals.fp_in_known_bot_cluster),
            b(signals.canvas_fp_anomaly),
            b(signals.automation_framework_detected),

            # Session behavior
            min(float(signals.navigation_entropy or 0.5), 1.0),
            min(float(signals.click_variance or 0.5), 1.0),
            min(float(signals.dwell_time_ms or 0) / 30000.0, 1.0),
        ], dtype=np.float32)

        return features.reshape(1, -1)

    def predict(self, features: np.ndarray) -> float:
        """
        Returns anomaly score in [0, 1] where 1.0 = most anomalous.
        Applies the fitted scaler before inference so the feature distribution
        matches what the model was trained on after the first retrain.
        """
        if self.model is None:
            return 0.5

        try:
            # Scale features if the scaler has been fitted (i.e. after first retrain).
            # On a fresh deployment with no saved model, the scaler is unfitted and
            # transform() would raise NotFittedError — fall back to raw features until
            # the first nightly retrain fits it.
            try:
                scaled = self.scaler.transform(features)
            except Exception:
                scaled = features
            raw_score = self.model.decision_function(scaled)[0]
            # Map to [0, 1]: decision_function typically in [-0.5, 0.5]
            normalized = 1.0 - (raw_score + 0.5).clip(0, 1)
            return float(normalized)
        except Exception:
            return 0.5

    def record_feedback(self, session_id: str, is_bot: bool):
        self.feedback_labels[session_id] = is_bot

    def add_to_training_buffer(self, features: np.ndarray):
        self.training_buffer.append(features.flatten())

    def retrain_from_samples(self, samples: list[dict]):
        """
        Retrain on labeled samples from the Redis training buffer.
        Each sample has a 'signals' dict and a 'bot_score' float.

        Feature rows are built to match the 35-element vector produced by
        extract_features() exactly. Using a different feature space here would
        cause a shape mismatch on every subsequent predict() call, silently
        falling back to 0.5 for all requests.
        """
        if len(samples) < 200:
            logger.warning(f"Only {len(samples)} samples — need 200+ to retrain, skipping")
            return

        features = []
        for s in samples:
            sig = s.get("signals", {})
            # Build the same 35-element vector as extract_features().
            # Fields present in the compact Redis summary are used directly;
            # fields not stored there default to their zero/neutral value.
            row = [
                # Network (4)
                float(sig.get("is_datacenter_asn", False)),
                float(sig.get("is_tor_exit", False)),
                float(sig.get("is_vpn_proxy", False)),
                float(sig.get("ip_reputation_score", 0.0)),
                # TLS (4)
                float(sig.get("ja3_suspicious", False)),
                float(sig.get("ja4_suspicious", False)),
                float(sig.get("tls_cipher_mismatch", False)),
                float(sig.get("tls_ticket_reuse", False)),
                # HTTP (6)
                float(sig.get("h2_settings_mismatch", False)),
                float(sig.get("h2_pseudo_header_order_wrong", False)),
                float(sig.get("user_agent_absent", False)),
                float(sig.get("user_agent_bot", False)),
                float(sig.get("accept_language_absent", False)),
                float(sig.get("header_order_anomaly", False)),
                # Request pattern (6)
                float(sig.get("rate_limit_violated", False)),
                float(sig.get("burst_detected", False)),
                float(sig.get("zero_timing_jitter", False)),
                float(sig.get("honeypot_accessed", False)),
                float(sig.get("slow_http_attack", False)),
                min(float(sig.get("url_encoding_layers", 0)) / 5.0, 1.0),
                # Browser behavior (9)
                float(sig.get("no_mouse_activity",
                              1.0 if sig.get("mouse_events", 1) == 0 else 0.0)),
                float(sig.get("linear_mouse_movement", False)),
                float(sig.get("zero_scroll_inertia",
                              1.0 if sig.get("scroll_events", 1) == 0 else 0.0)),
                float(sig.get("no_keyboard_jitter", False)),
                float(sig.get("no_focus_events",
                              1.0 if sig.get("focus_events", 1) == 0 else 0.0)),
                float(sig.get("navigator_webdriver", sig.get("webdriver", False))),
                float(sig.get("plugin_count_zero",
                              1.0 if sig.get("plugin_count", 1) == 0 else 0.0)),
                float(sig.get("screen_size_zero", False)),
                float(0.0 if sig.get("has_languages", True) else 1.0),
                # Fingerprint (3)
                float(sig.get("fp_in_known_bot_cluster", False)),
                float(sig.get("canvas_fp_anomaly", False)),
                float(sig.get("automation_framework", sig.get("automation_framework_detected", False))),
                # Session behavior (3)
                float(sig.get("navigation_entropy", 0.5)),
                float(sig.get("click_variance", 0.5)),
                min(float(sig.get("dwell_time_ms", 0)) / 30000.0, 1.0),
            ]
            if len(row) != 35:
                logger.warning(f"Skipping malformed training sample: got {len(row)} features, expected 35")
                continue
            features.append(row)

        # Only extend training_buffer after all rows are validated — this way a
        # shape error or numpy failure during fit doesn't leave the buffer
        # half-populated with rows from a failed retrain cycle.
        for row in features:
            self.training_buffer.append(row)

        contamination = sum(1 for s in samples if s.get("bot_score", 0) > 0.7) / len(samples)
        contamination = max(0.01, min(0.5, contamination))
        logger.info(f"Retraining Isolation Forest: {len(samples)} samples, contamination={contamination:.3f}")

        X = np.array(list(self.training_buffer), dtype=np.float32)
        X = self.scaler.fit_transform(X)

        self.model = IsolationForest(
            n_estimators=300,
            max_samples=min(len(X), 10000),
            contamination=contamination,
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X)

        with open(MODEL_PATH, "wb") as f:
            pickle.dump({"model": self.model, "scaler": self.scaler}, f)
        logger.info("Isolation Forest retrained and saved")

    def retrain(self):
        """Retrain on the internal buffer only (used when no labeled samples available)."""
        if len(self.training_buffer) < 1000:
            logger.warning("Insufficient training data, skipping retrain")
            return

        logger.info(f"Retraining on {len(self.training_buffer)} samples")
        X = np.array(list(self.training_buffer), dtype=np.float32)
        X = self.scaler.fit_transform(X)

        self.model = IsolationForest(
            n_estimators=300,
            max_samples=min(len(X), 10000),
            contamination=CONTAMINATION,
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X)

        # Save to disk
        with open(MODEL_PATH, "wb") as f:
            pickle.dump({"model": self.model, "scaler": self.scaler}, f)

        logger.info("Isolation Forest retrained and saved")
