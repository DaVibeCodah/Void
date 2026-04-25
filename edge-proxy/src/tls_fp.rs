/// TLS Fingerprinting — JA3, JA3S, JA4
/// Extracts fingerprints from ClientHello messages.
use md5;
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsFingerprint {
    pub ja3:  String,
    pub ja3_hash: String,
    pub ja4:  String,
    pub sni:  Option<String>,
    pub version: u16,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub elliptic_curves: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
    pub alpn: Vec<String>,
    pub ticket_size: usize,
    pub is_resumption: bool,
}

// Grease values — must be filtered when building JA3
const GREASE: &[u16] = &[
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a,
    0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a,
    0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
];

fn filter_grease_u16(v: &[u16]) -> Vec<u16> {
    v.iter().copied().filter(|x| !GREASE.contains(x)).collect()
}

impl TlsFingerprint {
    /// Build JA3 string: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
    pub fn compute_ja3(&mut self) {
        let ciphers: Vec<String>   = filter_grease_u16(&self.cipher_suites).iter().map(|x| x.to_string()).collect();
        let exts:    Vec<String>   = filter_grease_u16(&self.extensions).iter().map(|x| x.to_string()).collect();
        let curves:  Vec<String>   = filter_grease_u16(&self.elliptic_curves).iter().map(|x| x.to_string()).collect();
        let fmts:    Vec<String>   = self.ec_point_formats.iter().map(|x| x.to_string()).collect();

        self.ja3 = format!(
            "{},{},{},{},{}",
            self.version,
            ciphers.join("-"),
            exts.join("-"),
            curves.join("-"),
            fmts.join("-"),
        );
        self.ja3_hash = format!("{:x}", md5::compute(&self.ja3));
    }

    /// Build JA4 fingerprint (improved JA3)
    /// Format: t{tls_version}{sni_flag}{cipher_count:02}{ext_count:02}{alpn}_{cipher_hash}_{ext_hash}
    pub fn compute_ja4(&mut self) {
        let version_str = match self.version {
            0x0304 => "13",
            0x0303 => "12",
            0x0302 => "11",
            0x0301 => "10",
            _      => "00",
        };

        let sni_flag  = if self.sni.is_some() { "d" } else { "i" };
        let alpn_str  = self.alpn.first()
            .map(|s| s.chars().take(2).collect::<String>())
            .unwrap_or("00".into());

        let filtered_ciphers = filter_grease_u16(&self.cipher_suites);
        let filtered_exts    = filter_grease_u16(&self.extensions);

        let cipher_count = filtered_ciphers.len().min(99);
        let ext_count    = filtered_exts.len().min(99);

        // Sort ciphers for cipher hash (order-independent for matching)
        let mut sorted_ciphers = filtered_ciphers.clone();
        sorted_ciphers.sort();
        let cipher_str: Vec<String> = sorted_ciphers.iter().map(|x| format!("{:04x}", x)).collect();
        let cipher_hash = &format!("{:x}", Sha256::digest(cipher_str.join(",").as_bytes()))[..12];

        // Extension hash uses ORDER (order matters for JA4)
        let ext_str: Vec<String> = filtered_exts.iter().map(|x| format!("{:04x}", x)).collect();
        let ext_hash = &format!("{:x}", Sha256::digest(ext_str.join(",").as_bytes()))[..12];

        self.ja4 = format!(
            "t{}{}{}{:02}{:02}_{}_{}",
            version_str, sni_flag, alpn_str,
            cipher_count, ext_count,
            cipher_hash, ext_hash
        );
    }

    /// Check if this fingerprint matches known browser profiles.
    pub fn is_known_browser(&self) -> bool {
        KNOWN_BROWSER_JA3.contains(&self.ja3_hash.as_str())
    }

    /// Check if this fingerprint is associated with known automation tools.
    pub fn is_automation_tool(&self) -> bool {
        KNOWN_BOT_JA3.contains(&self.ja3_hash.as_str())
    }

    /// Parse from raw ClientHello bytes.
    pub fn from_client_hello(bytes: &[u8]) -> Option<Self> {
        let mut fp = TlsFingerprint::default();

        if bytes.len() < 43 { return None; }

        let mut pos = 0;

        // Record layer: type=0x16 (handshake), version
        if bytes[pos] != 0x16 { return None; }
        pos += 1;
        let _record_version = u16::from_be_bytes([bytes[pos], bytes[pos+1]]);
        pos += 2;
        let record_len = u16::from_be_bytes([bytes[pos], bytes[pos+1]]) as usize;
        pos += 2;

        if bytes.len() < pos + record_len { return None; }

        // Handshake: type=0x01 (ClientHello)
        if bytes[pos] != 0x01 { return None; }
        pos += 1;
        pos += 3; // 24-bit length

        // ClientHello version
        fp.version = u16::from_be_bytes([bytes[pos], bytes[pos+1]]);
        pos += 2;

        // Random (32 bytes)
        pos += 32;

        // Session ID
        let sid_len = bytes[pos] as usize;
        pos += 1 + sid_len;

        if pos + 2 > bytes.len() { return Some(fp); }

        // Cipher suites
        let cs_len = u16::from_be_bytes([bytes[pos], bytes[pos+1]]) as usize;
        pos += 2;
        for i in (0..cs_len).step_by(2) {
            if pos + i + 1 < bytes.len() {
                let cs = u16::from_be_bytes([bytes[pos+i], bytes[pos+i+1]]);
                fp.cipher_suites.push(cs);
            }
        }
        pos += cs_len;

        // Compression methods
        if pos < bytes.len() {
            let comp_len = bytes[pos] as usize;
            pos += 1 + comp_len;
        }

        // Extensions
        if pos + 2 <= bytes.len() {
            let ext_total = u16::from_be_bytes([bytes[pos], bytes[pos+1]]) as usize;
            pos += 2;
            let ext_end = pos + ext_total;

            while pos + 4 <= ext_end && pos + 4 <= bytes.len() {
                let ext_type = u16::from_be_bytes([bytes[pos], bytes[pos+1]]);
                let ext_len  = u16::from_be_bytes([bytes[pos+2], bytes[pos+3]]) as usize;
                pos += 4;

                fp.extensions.push(ext_type);

                match ext_type {
                    0x0000 => { // SNI
                        if pos + 5 <= bytes.len() {
                            let name_len = u16::from_be_bytes([bytes[pos+3], bytes[pos+4]]) as usize;
                            if pos + 5 + name_len <= bytes.len() {
                                fp.sni = String::from_utf8(bytes[pos+5..pos+5+name_len].to_vec()).ok();
                            }
                        }
                    }
                    0x000a => { // Supported groups (elliptic curves)
                        if pos + 2 <= bytes.len() {
                            let groups_len = u16::from_be_bytes([bytes[pos], bytes[pos+1]]) as usize;
                            for i in (2..groups_len+2).step_by(2) {
                                if pos + i + 1 < bytes.len() {
                                    fp.elliptic_curves.push(u16::from_be_bytes([bytes[pos+i], bytes[pos+i+1]]));
                                }
                            }
                        }
                    }
                    0x000b => { // EC point formats
                        if pos < bytes.len() {
                            let fmts_len = bytes[pos] as usize;
                            for i in 1..=fmts_len {
                                if pos + i < bytes.len() {
                                    fp.ec_point_formats.push(bytes[pos+i]);
                                }
                            }
                        }
                    }
                    0x0010 => { // ALPN
                        if pos + 2 <= bytes.len() {
                            let alpn_len = u16::from_be_bytes([bytes[pos], bytes[pos+1]]) as usize;
                            let mut ap = pos + 2;
                            let alpn_end = pos + 2 + alpn_len;
                            while ap + 1 <= alpn_end && ap < bytes.len() {
                                let proto_len = bytes[ap] as usize;
                                ap += 1;
                                if ap + proto_len <= bytes.len() {
                                    if let Ok(proto) = std::str::from_utf8(&bytes[ap..ap+proto_len]) {
                                        fp.alpn.push(proto.to_string());
                                    }
                                }
                                ap += proto_len;
                            }
                        }
                    }
                    0x0023 => { // Session ticket
                        fp.ticket_size = ext_len;
                        fp.is_resumption = ext_len > 0;
                    }
                    _ => {}
                }

                pos += ext_len;
            }
        }

        fp.compute_ja3();
        fp.compute_ja4();
        Some(fp)
    }
}

// Known-good browser JA3 hashes (Chrome, Firefox, Safari, Edge)
static KNOWN_BROWSER_JA3: &[&str] = &[
    "cd08e31494f9531f560d64c695473da9", // Chrome 120
    "b32309a26951912be7dba376398abc3b", // Firefox 121
    "8aaf1e9da73ff5e8f91c7da5d98a498f", // Safari 17
    "579ccef312d18482fc42e2b822ca2430", // Edge 120
    "55cff36a5bd73e4a1388a5c1f5f0196c", // Chrome 119
    "b46c980e9e5ded0c8c6b0e3f7e49d0ce", // Firefox 120
];

// Known bot/automation JA3 hashes
static KNOWN_BOT_JA3: &[&str] = &[
    "a0e9f5d64349fb13191bc781f81f42e1", // python-requests
    "b9cc3f4efdc23a8fb2b1b84a39e1a3fc", // curl default
    "51c64c77e60f3980eea90869b68c58a8", // Scrapy
    "cca47fd36db5fb2bcd3ec5fdf3a24659", // Playwright default
    "3b5074b1b5d032e5620e32d6c177b83b", // Puppeteer default
    "6bea65232d2c3260b589d71cb9de80f5", // Selenium Chrome
];
