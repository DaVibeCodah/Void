use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub listen_addr: String,
    pub upstream: String,
    pub redis_url: String,
    pub behavior_engine_url: String,
    pub geoip_db: String,
    pub asn_db: String,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,

    /// Shared secret for HMAC-SHA256 challenge token signing.
    /// Must match CHALLENGE_SECRET in the behavior engine.
    pub challenge_secret: String,

    #[serde(default = "default_global_rps")]
    pub global_rps_limit: u64,

    #[serde(default = "default_per_ip_rps")]
    pub per_ip_rps_limit: u64,

    #[serde(default = "default_per_session_rps")]
    pub per_session_rps_limit: u64,

    #[serde(default)]
    pub endpoint_limits: HashMap<String, EndpointLimit>,

    #[serde(default)]
    pub honeypot_paths: Vec<String>,

    #[serde(default = "default_block_score")]
    pub block_score_threshold: u32,

    #[serde(default = "default_captcha_score")]
    pub captcha_score_threshold: u32,

    #[serde(default = "default_pow_score")]
    pub pow_score_threshold: u32,

    #[serde(default = "default_jschallenge_score")]
    pub js_challenge_score_threshold: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct EndpointLimit {
    pub rps: u64,
    pub burst: u64,
    pub action: LimitAction,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum LimitAction {
    Block,
    Challenge,
    Captcha,
    ProofOfWork,
    SlowDown,
}

fn default_global_rps() -> u64 { 100_000 }
fn default_per_ip_rps() -> u64 { 100 }
fn default_per_session_rps() -> u64 { 30 }
fn default_block_score() -> u32 { 100 }
fn default_captcha_score() -> u32 { 80 }
fn default_pow_score() -> u32 { 60 }
fn default_jschallenge_score() -> u32 { 40 }

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let challenge_secret = std::env::var("CHALLENGE_SECRET")
            .unwrap_or_else(|_| "change-me-in-production".into());
        if challenge_secret == "change-me-in-production" {
            if std::env::var("VOID_ALLOW_INSECURE_SECRET").as_deref() != Ok("1") {
                anyhow::bail!(
                    "CHALLENGE_SECRET env var must be set to a strong random value. \
                     Generate one with: openssl rand -hex 32\n\
                     To suppress in local dev only: set VOID_ALLOW_INSECURE_SECRET=1"
                );
            }
            eprintln!("WARNING: Running with default CHALLENGE_SECRET — insecure, dev/test only");
        }
        Ok(Config {
            listen_addr:          std::env::var("LISTEN_ADDR").unwrap_or("0.0.0.0:8080".into()),
            upstream:             std::env::var("UPSTREAM").expect("UPSTREAM required"),
            redis_url:            std::env::var("REDIS_URL").unwrap_or("redis://127.0.0.1:6379".into()),
            behavior_engine_url:  std::env::var("BEHAVIOR_ENGINE_URL").unwrap_or("http://127.0.0.1:8000".into()),
            geoip_db:             std::env::var("GEOIP_DB").unwrap_or("/data/GeoLite2-City.mmdb".into()),
            asn_db:               std::env::var("ASN_DB").unwrap_or("/data/GeoLite2-ASN.mmdb".into()),
            tls_cert:             std::env::var("TLS_CERT").ok(),
            tls_key:              std::env::var("TLS_KEY").ok(),
            challenge_secret,
            global_rps_limit:     100_000,
            per_ip_rps_limit:     100,
            per_session_rps_limit: 30,
            endpoint_limits:      HashMap::new(),
            honeypot_paths:       vec![
                "/.env".into(),
                "/.git/config".into(),
                "/wp-login.php".into(),
                "/admin/config.php".into(),
                "/api/v0/users".into(),
                "/phpinfo.php".into(),
                "/server-status".into(),
                "/.aws/credentials".into(),
                "/config.yml".into(),
                "/backup.zip".into(),
            ],
            block_score_threshold:       100,
            captcha_score_threshold:     80,
            pow_score_threshold:         60,
            js_challenge_score_threshold: 40,
        })
    }
}
