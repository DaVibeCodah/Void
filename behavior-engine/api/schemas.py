"""
Pydantic schemas for the behavior engine API.
"""
from pydantic import BaseModel, Field
from typing import Optional


class SignalSetSchema(BaseModel):
    # Network
    is_datacenter_asn: bool = False
    is_tor_exit: bool = False
    is_vpn_proxy: bool = False
    is_cgnat: bool = False
    is_bogon: bool = False
    ip_reputation_score: float = 0.0
    geo_velocity_violation: bool = False

    # TLS
    ja3_suspicious: bool = False
    ja4_suspicious: bool = False
    tls_cipher_mismatch: bool = False
    tls_ticket_reuse: bool = False
    tls_handshake_anomaly: bool = False

    # HTTP
    h2_settings_mismatch: bool = False
    h2_pseudo_header_order_wrong: bool = False
    user_agent_absent: bool = False
    user_agent_bot: bool = False
    accept_language_absent: bool = False
    header_order_anomaly: bool = False

    # Request patterns
    rate_limit_violated: bool = False
    burst_detected: bool = False
    zero_timing_jitter: bool = False
    honeypot_accessed: bool = False
    canary_triggered: bool = False
    request_flood: bool = False
    slow_http_attack: bool = False

    # Request content
    json_entropy_high: bool = False
    param_pollution: bool = False
    chunked_encoding_conflict: bool = False
    invalid_crlf: bool = False
    path_traversal_attempt: bool = False
    url_encoding_layers: int = 0

    # Browser behavior
    no_mouse_activity: bool = False
    linear_mouse_movement: bool = False
    zero_scroll_inertia: bool = False
    no_keyboard_jitter: bool = False
    no_focus_events: bool = False
    navigator_webdriver: bool = False
    plugin_count_zero: bool = False
    screen_size_zero: bool = False
    no_languages: bool = False

    # Fingerprint
    fp_in_known_bot_cluster: bool = False
    canvas_fp_anomaly: bool = False
    webgl_fp_anomaly: bool = False
    automation_framework_detected: bool = False
    fingerprint_hash: Optional[str] = None

    # Session
    navigation_entropy: float = 0.5
    click_variance: float = 0.5
    dwell_time_ms: int = 0


class ScoreRequest(BaseModel):
    ip: str
    session_id: Optional[str] = None
    endpoint: Optional[str] = None
    session_endpoints: Optional[list[str]] = None
    signals: SignalSetSchema


class ScoreResponse(BaseModel):
    anomaly_score: float = Field(..., ge=0.0, le=1.0)
    sequence_bot_probability: float = Field(..., ge=0.0, le=1.0)
    coordination_score: float = Field(..., ge=0.0, le=1.0)
    in_botnet_cluster: bool = False


class FeedbackRequest(BaseModel):
    session_id: str
    was_bot: bool
    confidence: float = 1.0


class TelemetryPayload(BaseModel):
    """Browser telemetry submitted by challenge engine."""
    token: str
    seed: str
    type: str  # js | pow | wasm | captcha
    result: Optional[dict] = None
    telemetry: Optional[dict] = None
