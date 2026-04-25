/// HTTP/2 Fingerprinting
/// Analyzes SETTINGS frames, pseudo-header order, WINDOW_UPDATE values,
/// and PRIORITY frames to distinguish real browsers from bots.
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Http2Fingerprint {
    pub settings: Vec<(u16, u32)>,       // (identifier, value)
    pub window_update_increment: u32,    // initial WINDOW_UPDATE
    pub pseudo_header_order: Vec<String>, // :method, :path, :scheme, :authority
    pub priority_weight: Option<u8>,
    pub priority_stream_dep: Option<u32>,
    pub priority_exclusive: Option<bool>,
    pub fingerprint_hash: String,
    pub profile: BrowserProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub enum BrowserProfile {
    Chrome,
    Firefox,
    Safari,
    Edge,
    CurlLibcurl,
    PythonHttpx,
    GoHttpClient,
    NodeFetch,
    Automation,
    #[default]
    Unknown,
}

// Known browser SETTINGS profiles
// Format: (HEADER_TABLE_SIZE, MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE, MAX_HEADER_LIST_SIZE)
const CHROME_SETTINGS: &[(u16, u32)] = &[
    (1, 65536),     // HEADER_TABLE_SIZE
    (3, 1000),      // MAX_CONCURRENT_STREAMS
    (4, 6291456),   // INITIAL_WINDOW_SIZE
    (6, 262144),    // MAX_HEADER_LIST_SIZE
];

const FIREFOX_SETTINGS: &[(u16, u32)] = &[
    (1, 65536),
    (4, 131072),
    (5, 16384),
];

const CURL_SETTINGS: &[(u16, u32)] = &[
    (3, 100),
    (4, 65536),
];

impl Http2Fingerprint {
    /// Compare settings against known browser profiles
    pub fn identify_profile(&mut self) {
        self.profile = if self.settings_match(CHROME_SETTINGS)
            && self.window_update_increment == 15663105
        {
            BrowserProfile::Chrome
        } else if self.settings_match(FIREFOX_SETTINGS)
            && self.window_update_increment == 12517377
        {
            BrowserProfile::Firefox
        } else if self.settings_match(CURL_SETTINGS) {
            BrowserProfile::CurlLibcurl
        } else {
            BrowserProfile::Unknown
        };

        // Check pseudo-header order
        // Chrome/Edge: :method :authority :scheme :path
        // curl: :method :path :scheme :authority
        let order: Vec<&str> = self.pseudo_header_order.iter().map(|s| s.as_str()).collect();
        if order == vec![":method", ":path", ":scheme", ":authority"] {
            // This is curl order — suspicious if UA claims to be a browser
            self.profile = BrowserProfile::CurlLibcurl;
        }
    }

    pub fn is_browser_consistent(&self, user_agent: &str) -> bool {
        let ua_lower = user_agent.to_lowercase();
        let is_chrome_ua  = ua_lower.contains("chrome") && !ua_lower.contains("chromium");
        let is_firefox_ua = ua_lower.contains("firefox");

        match self.profile {
            BrowserProfile::Chrome  => is_chrome_ua,
            BrowserProfile::Firefox => is_firefox_ua,
            BrowserProfile::CurlLibcurl => {
                ua_lower.contains("curl") || ua_lower.contains("libcurl")
            }
            BrowserProfile::Unknown => true, // give benefit of doubt
            _ => true,
        }
    }

    fn settings_match(&self, expected: &[(u16, u32)]) -> bool {
        expected.iter().all(|(id, val)| {
            self.settings.iter().any(|(sid, sval)| sid == id && sval == val)
        })
    }

    /// Compute a hash of the H2 fingerprint for clustering
    pub fn compute_hash(&mut self) {
        use sha2::{Sha256, Digest};
        let repr = format!(
            "settings:{:?};window:{};pseudo:{:?};priority_weight:{:?}",
            self.settings,
            self.window_update_increment,
            self.pseudo_header_order,
            self.priority_weight,
        );
        self.fingerprint_hash = format!("{:x}", Sha256::digest(repr.as_bytes()));
    }
}

/// Timing analysis for request patterns
#[derive(Debug, Default)]
pub struct TimingAnalyzer {
    intervals: Vec<f64>,  // inter-request intervals in ms
}

impl TimingAnalyzer {
    pub fn record_interval(&mut self, ms: f64) {
        self.intervals.push(ms);
        // Keep last 50 intervals
        if self.intervals.len() > 50 {
            self.intervals.remove(0);
        }
    }

    pub fn mean(&self) -> f64 {
        if self.intervals.is_empty() { return 0.0; }
        self.intervals.iter().sum::<f64>() / self.intervals.len() as f64
    }

    pub fn stddev(&self) -> f64 {
        if self.intervals.len() < 2 { return 0.0; }
        let mean = self.mean();
        let variance = self.intervals.iter()
            .map(|x| (x - mean).powi(2))
            .sum::<f64>()
            / (self.intervals.len() - 1) as f64;
        variance.sqrt()
    }

    /// Returns true if timing jitter is near-zero (bot indicator)
    pub fn is_zero_jitter(&self) -> bool {
        if self.intervals.len() < 5 { return false; }
        self.stddev() < 2.0  // less than 2ms stddev over 5+ requests
    }

    /// Returns true if requests are suspiciously periodic
    pub fn is_perfectly_periodic(&self) -> bool {
        if self.intervals.len() < 5 { return false; }
        let cv = self.stddev() / self.mean().max(1.0);
        cv < 0.02  // coefficient of variation < 2%
    }

    /// Detect burst: N requests within T milliseconds
    pub fn is_burst(&self, window_count: usize, window_ms: f64) -> bool {
        if self.intervals.len() < window_count { return false; }
        let recent: f64 = self.intervals.iter().rev().take(window_count).sum();
        recent < window_ms
    }
}
