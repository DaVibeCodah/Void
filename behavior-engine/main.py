"""
Vo!d Behavior Engine
ML-powered traffic analysis: anomaly detection, botnet clustering, sequence analysis.
"""
from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.gzip import GZipMiddleware
from contextlib import asynccontextmanager
import asyncio
import logging

from .models.isolation_forest import IsolationForestDetector
from .models.sequence_lstm import SequenceBotClassifier
from .models.graph_engine import GraphEngine
from .models.dbscan_cluster import FingerprintClusterer
from .models.transformer import CoordinationDetector
from .analyzers.timing import TimingAnalyzer
from .analyzers.geo_velocity import GeoVelocityAnalyzer
from .api.routes import router
from .api.schemas import ScoreRequest, ScoreResponse

logger = logging.getLogger(__name__)

# ── Global model instances ────────────────────────────────────────────────
models = {}

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Loading Vo!d behavior models...")

    models["isolation_forest"] = IsolationForestDetector()
    models["sequence_lstm"]    = SequenceBotClassifier()
    models["graph_engine"]     = GraphEngine()
    models["fp_clusterer"]     = FingerprintClusterer()
    models["coordination"]     = CoordinationDetector()
    models["timing"]           = TimingAnalyzer()
    models["geo_velocity"]     = GeoVelocityAnalyzer()

    # Start background tasks
    asyncio.create_task(periodic_model_retrain())
    asyncio.create_task(periodic_graph_update())

    logger.info("All models loaded. Behavior engine ready.")
    yield
    logger.info("Shutting down behavior engine.")

app = FastAPI(title="Vo!d Behavior Engine", lifespan=lifespan)
app.add_middleware(GZipMiddleware, minimum_size=500)
app.include_router(router)


@app.post("/score", response_model=ScoreResponse)
async def score_request(req: ScoreRequest, background: BackgroundTasks):
    """
    Main scoring endpoint. Called by edge proxy for every request above
    the invisible challenge threshold. Target: P99 < 5ms.
    """
    signals = req.signals

    # ── 1. Isolation Forest anomaly score ────────────────────────────
    features = models["isolation_forest"].extract_features(signals)
    anomaly_score = models["isolation_forest"].predict(features)

    # ── 2. Sequence bot probability ───────────────────────────────────
    session_seq = req.session_endpoints or []
    seq_bot_prob = models["sequence_lstm"].predict(session_seq)

    # ── 3. Cross-session coordination detection ───────────────────────
    coord_score = models["coordination"].score(req.ip, signals)

    # ── 4. Fingerprint cluster membership ────────────────────────────
    in_botnet = False
    if signals.fingerprint_hash:
        in_botnet = models["fp_clusterer"].is_in_known_cluster(signals.fingerprint_hash)

    # ── 5. Enqueue graph update (non-blocking) ───────────────────────
    background.add_task(
        models["graph_engine"].add_edge,
        req.ip,
        signals.fingerprint_hash,
        req.session_id,
        req.endpoint,
    )

    response = ScoreResponse(
        anomaly_score=float(anomaly_score),
        sequence_bot_probability=float(seq_bot_prob),
        coordination_score=float(coord_score),
        in_botnet_cluster=in_botnet,
    )

    # Background: record to training buffer
    background.add_task(record_training_sample, req, response)

    return response


@app.get("/health")
async def health():
    return {"status": "ok", "models_loaded": len(models)}


@app.get("/graph/communities")
async def get_communities():
    """Return detected botnet communities for dashboard."""
    return models["graph_engine"].get_communities()


@app.post("/feedback")
async def feedback(session_id: str, was_bot: bool):
    """
    Accept confirmed bot/human labels from human review or CAPTCHA completion.
    Used for online learning.
    """
    models["isolation_forest"].record_feedback(session_id, was_bot)
    models["sequence_lstm"].record_feedback(session_id, was_bot)
    return {"ok": True}


async def periodic_model_retrain():
    """Retrain models nightly on accumulated labeled data from the training buffer."""
    while True:
        await asyncio.sleep(86400)  # 24 hours
        logger.info("Starting nightly model retraining...")
        try:
            # Pull training samples written by _record_training_sample in routes.py
            import redis as redis_lib, json, os
            r = redis_lib.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379"),
                                   decode_responses=True)
            raw_samples = r.lrange("void:training:samples", 0, -1)
            samples = []
            for raw in raw_samples:
                try:
                    samples.append(json.loads(raw))
                except Exception:
                    pass

            if samples:
                logger.info(f"Loaded {len(samples)} training samples from Redis buffer")
                # Retrain all models. Only clear the buffer once ALL succeed —
                # if any raises, the except block below catches it and the samples
                # remain for the next nightly run instead of being lost.
                models["isolation_forest"].retrain_from_samples(samples)
                models["sequence_lstm"].retrain()
                models["coordination"].retrain()
                # All three succeeded — safe to clear.
                r.delete("void:training:samples")
                logger.info("Nightly retraining complete. Buffer cleared.")
            else:
                logger.info("No training samples in buffer, skipping retrain.")
        except Exception as e:
            logger.error(f"Retraining failed: {e}")


async def periodic_graph_update():
    """Run community detection every 5 minutes."""
    while True:
        await asyncio.sleep(300)
        try:
            models["graph_engine"].run_community_detection()
            communities = models["graph_engine"].get_communities()
            # Push detected clusters to fingerprint clusterer
            for community in communities:
                if community["size"] > 3 and community["homogeneity"] > 0.8:
                    for fp_hash in community["fingerprint_hashes"]:
                        models["fp_clusterer"].add_to_known_cluster(fp_hash)
            logger.info(f"Graph update: {len(communities)} communities detected")
        except Exception as e:
            logger.error(f"Graph update failed: {e}")


async def record_training_sample(req: ScoreRequest, resp: ScoreResponse):
    """
    Store ML scoring request+response pair to the Redis training buffer.
    The nightly retrain job reads void:training:samples and uses these
    to improve the Isolation Forest and LSTM models.
    This mirrors the _record_training_sample in routes.py but captures
    the full signal set from the ML scoring path rather than just telemetry.
    """
    import json as _json, time as _time
    # Reuse the module-level Redis client from routes — creating a new TCP
    # connection on every background task call exhausts file descriptors under load.
    from .api.routes import get_redis
    try:
        r = get_redis()
        if not r:
            return
        record = {
            "session_id":       req.session_id or "unknown",
            "ts":               int(_time.time()),
            "bot_score":        round(float(resp.anomaly_score), 4),
            "challenge_passed": None,   # ML path — no challenge outcome yet
            "signals": {
                "anomaly_score":            round(float(resp.anomaly_score), 4),
                "sequence_bot_probability": round(float(resp.sequence_bot_probability), 4),
                "coordination_score":       round(float(resp.coordination_score), 4),
                "in_botnet_cluster":        resp.in_botnet_cluster,
                # Key signal flags for model features
                "is_datacenter_asn":        req.signals.is_datacenter_asn,
                "is_tor_exit":              req.signals.is_tor_exit,
                "navigator_webdriver":      req.signals.navigator_webdriver,
                "no_mouse_activity":        req.signals.no_mouse_activity,
                "automation_framework":     req.signals.automation_framework_detected,
                "fp_in_known_bot_cluster":  req.signals.fp_in_known_bot_cluster,
                "rate_limit_violated":      req.signals.rate_limit_violated,
            },
        }
        r.lpush("void:training:samples", _json.dumps(record))
        # Cap buffer at 100K entries to avoid unbounded growth
        r.ltrim("void:training:samples", 0, 99_999)
    except Exception as e:
        logger.warning(f"Failed to record ML training sample: {e}")
