"""
FastAPI routes for the behavior engine.
"""
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from .schemas import TelemetryPayload, FeedbackRequest
import hashlib, time, hmac, os, redis as redis_lib, math, json, logging

logger = logging.getLogger(__name__)

router = APIRouter()

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "change-me-in-production")
CHALLENGE_WINDOW_SECONDS = 300
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")

# Fail loudly at import time — never run with the default secret in production.
if CHALLENGE_SECRET == "change-me-in-production":
    import sys
    # Allow in test/dev if explicitly opted out, otherwise hard fail.
    if os.environ.get("VOID_ALLOW_INSECURE_SECRET") != "1":
        raise RuntimeError(
            "CHALLENGE_SECRET env var must be set to a strong random value before starting. "
            "Generate one with: openssl rand -hex 32\n"
            "To suppress this in local dev only: set VOID_ALLOW_INSECURE_SECRET=1"
        )
    logger.warning("Running with default CHALLENGE_SECRET — insecure, dev/test only")

# Redis client for stats and training buffer
_redis = None
def get_redis():
    global _redis
    if _redis is None:
        try:
            _redis = redis_lib.from_url(REDIS_URL, decode_responses=True)
        except Exception:
            pass
    return _redis


@router.get("/__void/stats")
@router.get("/stats")
async def get_live_stats():
    """
    Live protection stats served to the website counter bar.
    All counters are stored in Redis and incremented by the edge proxy
    as events occur.
    """
    r = get_redis()
    def rget(key, default=0):
        try:
            v = r.get(key) if r else None
            return int(v) if v is not None else default
        except Exception:
            return default

    bots_blocked           = rget("void:stats:bots_blocked_total")
    requests_today         = rget("void:stats:requests_today")
    requests_per_sec       = rget("void:stats:rps_current", 0)
    ddos_total             = rget("void:stats:ddos_attacks_total")
    fingerprints           = rget("void:stats:fingerprints_tracked")
    challenges_js          = rget("void:stats:challenges_js")
    challenges_pow         = rget("void:stats:challenges_pow")
    challenges_wasm        = rget("void:stats:challenges_wasm")
    challenges_captcha     = rget("void:stats:challenges_captcha")
    honeypot_hits          = rget("void:stats:honeypot_hits_today")
    botnet_cluster_members = rget("void:stats:botnet_cluster_members")

    return JSONResponse({
        "bots_blocked_total":      bots_blocked,
        "requests_today":          requests_today,
        "requests_per_sec":        requests_per_sec,
        "ddos_attacks_total":      ddos_total,
        "fingerprints_tracked":    fingerprints,
        "challenges_js":           challenges_js,
        "challenges_pow":          challenges_pow,
        "challenges_wasm":         challenges_wasm,
        "challenges_captcha":      challenges_captcha,
        "honeypot_hits_today":     honeypot_hits,
        "botnet_cluster_members":  botnet_cluster_members,
        "edge_latency_ms":         "<1",
        "source":                  "live",
        "timestamp":               int(time.time()),
    }, headers={"Access-Control-Allow-Origin": "*"})


@router.post("/__void/verify")
async def verify_challenge(payload: TelemetryPayload, request: Request):
    """
    Verifies a completed challenge response and analyzes the submitted telemetry.
    Returns a signed pass token if verification succeeds.

    The difficulty is encoded inside the signed token so the server is always
    the authority on what difficulty was required — the client cannot downgrade it.
    """
    difficulty = payload.result.get("difficulty") if payload.result else None
    if payload.type in ("pow", "wasm") and difficulty is None:
        raise HTTPException(status_code=400, detail="Missing difficulty in result")

    # Verify HMAC token — difficulty is part of the signed string.
    # Accept tokens from the current window OR the immediately previous one:
    # a token generated at second 299 of window N is valid; if the user's PoW
    # takes >1 second verification may land in window N+1, causing a false 403.
    # Accepting N-1 adds at most 5 extra minutes of token validity, which is fine.
    expected_current  = _generate_token(payload.seed, payload.type, difficulty)
    expected_previous = _generate_token(payload.seed, payload.type, difficulty, window_offset=-1)
    if not (hmac.compare_digest(payload.token, expected_current) or
            hmac.compare_digest(payload.token, expected_previous)):
        raise HTTPException(status_code=403, detail="Invalid challenge token")

    bot_score = _analyze_telemetry(payload.telemetry or {})

    if payload.type in ("pow", "wasm") and payload.result:
        nonce          = payload.result.get("nonce", 0)
        submitted_hash = payload.result.get("hash", "")
        if not _verify_pow(payload.seed, nonce, submitted_hash, int(difficulty)):
            raise HTTPException(status_code=403, detail="Invalid PoW solution")

    if bot_score > 0.9:
        return {"ok": False, "reason": "telemetry_failed", "escalate": "captcha"}

    # Wire up training sample recording
    _record_training_sample(
        session_id=payload.token[:16],
        telemetry=payload.telemetry or {},
        bot_score=bot_score,
        challenge_passed=True,
    )

    pass_token = _generate_pass_token(str(request.client.host), time.time())
    return {"ok": True, "pass_token": pass_token, "bot_score": bot_score}


@router.post("/__void/telemetry")
async def receive_telemetry(request: Request):
    """
    Receives passive telemetry from InvisibleChallenge injection.
    TELEMETRY_JS POSTs here after 4 seconds of observation on any page
    that received the invisible challenge script.
    Scores the telemetry and stores to the training buffer.
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    bot_score = _analyze_telemetry(body)

    # Store to Redis training buffer for nightly model retraining
    _record_training_sample(
        session_id=request.headers.get("x-void-session", "unknown"),
        telemetry=body,
        bot_score=bot_score,
        challenge_passed=None,  # no challenge — passive observation only
    )

    # If telemetry is strongly bot-like, flag this session for escalation
    # on the next request (edge proxy checks void:session:escalate:<session_id>)
    if bot_score > 0.7:
        r = get_redis()
        if r:
            session_id = request.headers.get("x-void-session", "")
            if session_id:
                r.setex(f"void:session:escalate:{session_id}", 300, str(bot_score))
                logger.info(f"Passive telemetry flagged session {session_id[:8]}... bot_score={bot_score:.2f}")

    return {"ok": True, "bot_score": bot_score}


def _verify_pow(seed: str, nonce: int, submitted_hash: str, difficulty_bits: int) -> bool:
    """
    Verify a SHA256 proof-of-work solution.

    difficulty_bits is BITS (matching the client JS exactly).
    4 bits  → 1 leading zero hex char  → ~16 attempts avg
    8 bits  → 2 leading zero hex chars → ~256 attempts avg
    16 bits → 4 leading zero hex chars → ~65K attempts avg
    20 bits → 5 leading zero hex chars + partial nibble → ~1M attempts avg

    Units are consistent: both client and server use bits.
    The partial nibble check matches the client's nibbleMask logic exactly.
    """
    if difficulty_bits < 1 or difficulty_bits > 256:
        return False

    attempt  = seed + str(nonce)
    computed = hashlib.sha256(attempt.encode()).hexdigest()

    # Constant-time comparison of the full hash first
    if not hmac.compare_digest(computed, submitted_hash):
        return False

    full_zero_chars = difficulty_bits // 4
    remainder_bits  = difficulty_bits % 4

    # Check full leading-zero hex chars
    if computed[:full_zero_chars] != '0' * full_zero_chars:
        return False

    # Check the partial nibble if difficulty is not a multiple of 4
    # Client uses: nibbleMask = (0xF << (4 - remainderBits)) & 0xF
    # e.g. remainder=1 → mask=0b1000=0x8, remainder=2 → 0b1100=0xC, remainder=3 → 0b1110=0xE
    if remainder_bits > 0:
        if full_zero_chars >= len(computed):
            return False
        nibble = int(computed[full_zero_chars], 16)
        mask   = (0xF << (4 - remainder_bits)) & 0xF
        if nibble & mask != 0:
            return False

    return True


def _generate_token(seed: str, challenge_type: str, difficulty=None, window_offset: int = 0) -> str:
    """Generate a signed HMAC token with difficulty embedded in the payload.
    window_offset allows verifying tokens from the previous window to handle
    the race where a token is issued near a window boundary and verified after it."""
    window   = int(time.time()) // CHALLENGE_WINDOW_SECONDS + window_offset
    diff_str = str(difficulty) if difficulty is not None else "none"
    data     = f"{seed}:{challenge_type}:{diff_str}:{window}"
    mac = hmac.HMAC(
        key=CHALLENGE_SECRET.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256,
    )
    return mac.hexdigest()


def _generate_pass_token(ip: str, ts: float) -> str:
    """Generate a session pass token bound to the client IP and time window."""
    window = int(ts) // CHALLENGE_WINDOW_SECONDS
    data   = f"{ip}:{window}"
    mac = hmac.HMAC(
        key=CHALLENGE_SECRET.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256,
    )
    return mac.hexdigest()


def _record_training_sample(
    session_id: str,
    telemetry: dict,
    bot_score: float,
    challenge_passed: bool | None,
) -> None:
    """
    Store telemetry + label to Redis training buffer.
    The nightly retrain job reads void:training:samples and uses these
    to improve the Isolation Forest and LSTM models.

    Format: JSON lines pushed to a Redis list, capped at 100K entries.
    """
    r = get_redis()
    if not r:
        return
    try:
        record = {
            "session_id":      session_id,
            "ts":              int(time.time()),
            "bot_score":       round(bot_score, 4),
            "challenge_passed": challenge_passed,
            # Store the full set of signals that retrain_from_samples expects,
            # using the telemetry fields we have plus safe defaults for the rest.
            # This prevents the retrain from training on mostly-zero rows.
            "signals": {
                # Fields directly available from telemetry
                "webdriver":             telemetry.get("navigator", {}).get("webdriver", False),
                "navigator_webdriver":   telemetry.get("navigator", {}).get("webdriver", False),
                "plugin_count":          telemetry.get("navigator", {}).get("pluginCount", -1),
                "plugin_count_zero":     telemetry.get("navigator", {}).get("pluginCount", 1) == 0,
                "has_languages":         bool(telemetry.get("navigator", {}).get("languages")),
                "no_languages":          not bool(telemetry.get("navigator", {}).get("languages")),
                "mouse_events":          telemetry.get("mouse", {}).get("events", 0),
                "no_mouse_activity":     telemetry.get("mouse", {}).get("events", 0) == 0,
                "scroll_events":         telemetry.get("scroll", {}).get("events", 0),
                "zero_scroll_inertia":   telemetry.get("scroll", {}).get("events", 0) == 0,
                "focus_events":          telemetry.get("focus", {}).get("events", 0),
                "no_focus_events":       (telemetry.get("focus", {}).get("events", 0) == 0
                                          and telemetry.get("focus", {}).get("blurs", 0) == 0),
                "wasm_ok":               telemetry.get("wasmOk", None),
                "screen_size_zero":      (telemetry.get("navigator", {}).get("screen", {}).get("w", 1) == 0
                                          or telemetry.get("navigator", {}).get("screen", {}).get("h", 1) == 0),
                # Fields not available from telemetry — use neutral defaults
                # so they don't bias the model in either direction
                "is_datacenter_asn": False,
                "is_tor_exit": False,
                "is_vpn_proxy": False,
                "ip_reputation_score": 0.0,
                "ja3_suspicious": False,
                "ja4_suspicious": False,
                "tls_cipher_mismatch": False,
                "tls_ticket_reuse": False,
                "h2_settings_mismatch": False,
                "h2_pseudo_header_order_wrong": False,
                "user_agent_absent": False,
                "user_agent_bot": False,
                "accept_language_absent": False,
                "header_order_anomaly": False,
                "rate_limit_violated": False,
                "burst_detected": False,
                "zero_timing_jitter": False,
                "honeypot_accessed": False,
                "slow_http_attack": False,
                "url_encoding_layers": 0,
                "linear_mouse_movement": False,
                "no_keyboard_jitter": False,
                "fp_in_known_bot_cluster": False,
                "canvas_fp_anomaly": False,
                "automation_framework_detected": False,
                "navigation_entropy": 0.5,
                "click_variance": 0.5,
                "dwell_time_ms": 0,
            },
        }
        r.lpush("void:training:samples", json.dumps(record))
        # Cap buffer at 100K entries to avoid unbounded growth
        r.ltrim("void:training:samples", 0, 99_999)
    except Exception as e:
        logger.warning(f"Failed to record training sample: {e}")


def _analyze_telemetry(t: dict) -> float:
    """
    Analyze browser telemetry. Returns bot probability 0.0–1.0.
    """
    score  = 0.0
    checks = 0
    nav    = t.get("navigator", {})

    if nav.get("webdriver"):                                    score += 1.0
    checks += 1
    if nav.get("pluginCount", 1) == 0:                         score += 0.5
    checks += 1
    if not nav.get("languages"):                               score += 0.5
    checks += 1
    screen = nav.get("screen", {})
    if screen.get("w", 1) == 0 or screen.get("h", 1) == 0:    score += 0.8
    checks += 1

    mouse = t.get("mouse", {})
    if mouse.get("events", 0) == 0:                            score += 0.4
    checks += 1
    if mouse.get("teleports", 0) == 0 and mouse.get("events", 0) > 5:
        if _is_linear_path(mouse.get("paths", [])):            score += 0.6
    checks += 1

    if t.get("scroll", {}).get("events", 0) == 0:             score += 0.2
    checks += 1
    focus = t.get("focus", {})
    if focus.get("events", 0) == 0 and focus.get("blurs", 0) == 0:
                                                               score += 0.3
    checks += 1
    if not t.get("wasmOk"):                                    score += 0.4
    checks += 1

    timing = t.get("timing", {})
    if _is_zero_jitter(timing.get("eventLoop", [])):           score += 0.5
    checks += 1
    if _is_synthetic_raf(timing.get("raf", [])):               score += 0.6
    checks += 1

    return min(1.0, score / max(checks, 1))


def _is_linear_path(paths: list) -> bool:
    if len(paths) < 5:
        return False
    diffs = [(paths[i][0]-paths[i-1][0], paths[i][1]-paths[i-1][1])
             for i in range(1, len(paths))]
    if len(diffs) < 2:
        return False
    angles = []
    for i in range(1, len(diffs)):
        dot  = diffs[i][0]*diffs[i-1][0] + diffs[i][1]*diffs[i-1][1]
        mag1 = math.hypot(*diffs[i])
        mag2 = math.hypot(*diffs[i-1])
        if mag1 > 0 and mag2 > 0:
            angles.append(math.acos(max(-1.0, min(1.0, dot / (mag1 * mag2)))))
    if not angles:
        return False
    mean     = sum(angles) / len(angles)
    variance = sum((a - mean)**2 for a in angles) / len(angles)
    return variance < 0.01


def _is_zero_jitter(intervals: list) -> bool:
    if len(intervals) < 5:
        return False
    mean     = sum(intervals) / len(intervals)
    variance = sum((x - mean)**2 for x in intervals) / len(intervals)
    return variance**0.5 < 1.0


def _is_synthetic_raf(raf_times: list) -> bool:
    if len(raf_times) < 10:
        return False
    mean     = sum(raf_times) / len(raf_times)
    variance = sum((x - mean)**2 for x in raf_times) / len(raf_times)
    return variance**0.5 < 0.5

