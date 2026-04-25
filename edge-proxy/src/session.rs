/// Session Management & Browser Fingerprint Tracking
use redis::aio::MultiplexedConnection;
use redis::AsyncCommands;
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Session {
    pub id: String,
    pub ip: String,
    pub fingerprint_hash: Option<String>,
    pub created_at: u64,
    pub last_seen: u64,
    pub request_count: u64,
    pub risk_score: u32,
    pub action: String,

    // Geo tracking for velocity detection
    pub last_latitude: Option<f64>,
    pub last_longitude: Option<f64>,

    // Behavior tracking
    pub endpoints_visited: Vec<String>,
    pub mouse_events_received: bool,
    pub keyboard_events_received: bool,
    pub scroll_events_received: bool,
    pub focus_events_received: bool,
    pub challenge_passed: bool,
    pub challenge_type: Option<String>,

    // Timing
    pub timing_intervals: Vec<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BrowserFingerprint {
    pub canvas_hash: Option<String>,
    pub webgl_hash: Option<String>,
    pub webgl_vendor: Option<String>,
    pub webgl_renderer: Option<String>,
    pub audio_hash: Option<String>,
    pub font_hash: Option<String>,
    pub screen_width: Option<u32>,
    pub screen_height: Option<u32>,
    pub color_depth: Option<u8>,
    pub device_memory: Option<f32>,
    pub hw_concurrency: Option<u32>,
    pub touch_points: Option<u32>,
    pub timezone: Option<String>,
    pub languages: Vec<String>,
    pub plugins: Vec<String>,
    pub navigator_webdriver: bool,
    pub webusb_available: bool,
    pub webbluetooth_available: bool,
    pub wasm_available: bool,
    pub intl_hash: Option<String>,
    pub css_font_metrics_hash: Option<String>,
    pub webgpu_hash: Option<String>,
    pub offscreen_canvas_hash: Option<String>,
    pub combined_hash: String,
}

impl BrowserFingerprint {
    pub fn compute_combined_hash(&mut self) {
        let parts = vec![
            self.canvas_hash.clone().unwrap_or_default(),
            self.webgl_hash.clone().unwrap_or_default(),
            self.audio_hash.clone().unwrap_or_default(),
            self.font_hash.clone().unwrap_or_default(),
            self.screen_width.map(|x| x.to_string()).unwrap_or_default(),
            self.screen_height.map(|x| x.to_string()).unwrap_or_default(),
            self.timezone.clone().unwrap_or_default(),
            self.intl_hash.clone().unwrap_or_default(),
        ];
        let combined = parts.join("|");
        self.combined_hash = format!("{:x}", Sha256::digest(combined.as_bytes()))[..16].to_string();
    }

    /// Detect anomalies consistent with headless/automation environments
    pub fn anomaly_score(&self) -> u32 {
        let mut score = 0u32;

        if self.navigator_webdriver                { score += 60; }
        if self.plugins.is_empty()                  { score += 15; }
        if self.languages.is_empty()                { score += 20; }
        if self.screen_width == Some(0)
        || self.screen_height == Some(0)            { score += 25; }
        if self.touch_points == Some(0)
        && self.screen_width.unwrap_or(1) < 500    { score += 10; }

        // Headless Chrome often has 0 plugins, specific UA pattern
        // Device memory missing is unusual for real browsers
        if self.device_memory.is_none()             { score += 8; }
        if self.hw_concurrency.is_none()            { score += 8; }

        score
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BehaviorTelemetry {
    // Mouse
    pub mouse_path: Vec<(f64, f64, u64)>,  // (x, y, timestamp_ms)
    pub click_count: u32,
    pub linear_movement_ratio: f32,   // 0=chaotic, 1=perfectly linear
    pub acceleration_variance: f32,
    pub teleport_count: u32,          // sudden large jumps

    // Scroll
    pub scroll_events: Vec<(f64, u64)>,  // (delta_y, timestamp)
    pub scroll_inertia_score: f32,    // 0=no inertia, 1=natural
    pub scroll_velocity_variance: f32,

    // Keyboard
    pub keydown_intervals: Vec<u64>,  // ms between keydowns
    pub typing_rhythm_entropy: f32,   // 0=robot, 1=human
    pub paste_event_count: u32,

    // Focus
    pub focus_events: u32,
    pub blur_events: u32,
    pub visibility_change_count: u32,
    pub time_on_page_ms: u64,

    // Hover
    pub hover_events: u32,
    pub hover_delay_variance: f32,
}

impl BehaviorTelemetry {
    pub fn mouse_entropy_score(&self) -> f32 {
        if self.mouse_path.len() < 5 { return 0.5; }

        // Compute curvature variance along the path
        let mut angles: Vec<f64> = Vec::new();
        for i in 1..self.mouse_path.len() - 1 {
            let (x0, y0, _) = self.mouse_path[i-1];
            let (x1, y1, _) = self.mouse_path[i];
            let (x2, y2, _) = self.mouse_path[i+1];
            let dx1 = x1 - x0; let dy1 = y1 - y0;
            let dx2 = x2 - x1; let dy2 = y2 - y1;
            let angle = (dx1*dx2 + dy1*dy2)
                / ((dx1.powi(2) + dy1.powi(2)).sqrt().max(0.001)
                *  (dx2.powi(2) + dy2.powi(2)).sqrt().max(0.001));
            angles.push(angle.acos());
        }

        if angles.is_empty() { return 0.0; }
        let variance = statistical_variance(&angles);
        // High variance = human, low variance = bot
        (variance.min(1.0) as f32).clamp(0.0, 1.0)
    }

    pub fn typing_rhythm_entropy(&self) -> f32 {
        if self.keydown_intervals.len() < 3 { return 0.5; }
        let intervals: Vec<f64> = self.keydown_intervals.iter().map(|&x| x as f64).collect();
        let variance = statistical_variance(&intervals);
        // Human typing: variance typically 20–200ms, bot: 0–5ms
        if variance < 1.0 { 0.0 }
        else { (variance.log10() / 3.0).min(1.0) as f32 }
    }

    pub fn is_bot_like(&self) -> bool {
        self.mouse_entropy_score() < 0.1
            && self.typing_rhythm_entropy() < 0.1
            && self.focus_events == 0
            && self.scroll_inertia_score < 0.1
    }
}

fn statistical_variance(data: &[f64]) -> f64 {
    if data.len() < 2 { return 0.0; }
    let mean = data.iter().sum::<f64>() / data.len() as f64;
    data.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (data.len() - 1) as f64
}

pub struct SessionStore {
    redis: MultiplexedConnection,
    ttl_seconds: usize,
}

impl SessionStore {
    pub fn new(redis: MultiplexedConnection) -> Self {
        Self { redis, ttl_seconds: 3600 }
    }

    pub async fn get(&mut self, session_id: &str) -> Option<Session> {
        let key = format!("session:{}", session_id);
        let data: Option<String> = self.redis.get(&key).await.ok()?;
        data.and_then(|d| serde_json::from_str(&d).ok())
    }

    pub async fn set(&mut self, session: &Session) -> anyhow::Result<()> {
        let key = format!("session:{}", session.id);
        let data = serde_json::to_string(session)?;
        let _: () = self.redis.set_ex(key, data, self.ttl_seconds).await?;
        Ok(())
    }

    pub async fn add_fingerprint_to_cluster(
        &mut self,
        fp_hash: &str,
        ip: &str,
    ) -> anyhow::Result<u64> {
        let key = format!("fp_cluster:{}", fp_hash);
        let count: u64 = self.redis.sadd(&key, ip).await?;
        let _: () = self.redis.expire(&key, 86400).await?;
        // Return total IPs sharing this fingerprint
        let total: u64 = self.redis.scard(&key).await?;
        Ok(total)
    }

    pub async fn fingerprint_cluster_size(&mut self, fp_hash: &str) -> u64 {
        let key = format!("fp_cluster:{}", fp_hash);
        self.redis.scard::<_, u64>(&key).await.unwrap_or(0)
    }
}
