/// HTTP Request Normalization Engine
/// Prevents bypass attacks via URL encoding tricks, path traversal, etc.
use percent_encoding::percent_decode_str;
use unicode_normalization::UnicodeNormalization;

#[derive(Debug, Clone)]
pub struct NormalizedRequest {
    pub path: String,
    pub query: String,
    pub encoding_layers: u8,
    pub had_traversal: bool,
    pub had_null_byte: bool,
    pub had_crlf: bool,
    pub had_unicode_trick: bool,
    pub had_double_slash: bool,
}

pub struct Normalizer {
    pub max_encoding_depth: u8,
    pub max_path_depth: usize,
}

impl Default for Normalizer {
    fn default() -> Self {
        Self { max_encoding_depth: 5, max_path_depth: 32 }
    }
}

impl Normalizer {
    /// Full normalization pipeline for a raw request URI.
    pub fn normalize(&self, raw_uri: &str) -> Result<NormalizedRequest, NormError> {
        let (raw_path, query) = split_path_query(raw_uri);

        let mut encoding_layers: u8 = 0;
        let mut had_traversal = false;
        let mut had_null_byte = false;
        let mut had_crlf = false;
        let mut had_unicode_trick = false;
        let mut had_double_slash = false;

        let mut path = raw_path.to_string();

        // ── Step 1: Iterative percent-decode until stable ─────────────
        loop {
            let decoded = percent_decode_str(&path)
                .decode_utf8()
                .map_err(|_| NormError::InvalidEncoding)?
                .to_string();

            if decoded == path { break; }
            encoding_layers += 1;
            if encoding_layers > self.max_encoding_depth {
                return Err(NormError::TooManyEncodingLayers);
            }
            path = decoded;
        }

        // ── Step 2: Null byte detection ───────────────────────────────
        if path.contains('\0') {
            had_null_byte = true;
            path = path.replace('\0', "");
        }

        // ── Step 3: CRLF detection ────────────────────────────────────
        if path.contains('\r') || path.contains('\n') {
            had_crlf = true;
            path = path.replace('\r', "").replace('\n', "");
        }

        // ── Step 4: Control character removal ────────────────────────
        path = path.chars().filter(|c| !c.is_control()).collect();

        // ── Step 5: Unicode NFC normalization ─────────────────────────
        let nfc: String = path.nfc().collect();
        if nfc != path {
            had_unicode_trick = true;
        }
        path = nfc;

        // ── Step 6: Normalize backslashes ─────────────────────────────
        path = path.replace('\\', "/");

        // ── Step 7: Collapse double slashes ───────────────────────────
        while path.contains("//") {
            had_double_slash = true;
            path = path.replace("//", "/");
        }

        // ── Step 8: Resolve dot segments (RFC 3986 §5.2.4) ───────────
        let mut segments: Vec<&str> = Vec::new();
        for segment in path.split('/') {
            match segment {
                "." | "" => {}
                ".." => {
                    had_traversal = true;
                    segments.pop();
                }
                s => {
                    if segments.len() < self.max_path_depth {
                        segments.push(s);
                    }
                }
            }
        }
        path = format!("/{}", segments.join("/"));

        // ── Step 9: Strip trailing slash (except root) ────────────────
        if path.len() > 1 && path.ends_with('/') {
            path.pop();
        }

        // ── Step 10: Lowercase ────────────────────────────────────────
        path = path.to_lowercase();

        Ok(NormalizedRequest {
            path,
            query: query.to_string(),
            encoding_layers,
            had_traversal,
            had_null_byte,
            had_crlf,
            had_unicode_trick,
            had_double_slash,
        })
    }

    /// Detect anomalies in HTTP headers.
    pub fn check_headers(&self, headers: &[(String, String)]) -> HeaderAnomalies {
        let mut a = HeaderAnomalies::default();

        for (name, value) in headers {
            // CRLF injection in header values
            if value.contains('\r') || value.contains('\n') {
                a.crlf_in_header = true;
            }
            // Null bytes in headers
            if value.contains('\0') || name.contains('\0') {
                a.null_byte_in_header = true;
            }
            // Excessively long headers
            if value.len() > 8192 {
                a.oversized_header = true;
            }
            // Detect chunked + content-length conflict (RFC 7230 §3.3.2)
            if name.to_lowercase() == "transfer-encoding"
                && value.to_lowercase().contains("chunked")
            {
                a.has_chunked = true;
            }
            if name.to_lowercase() == "content-length" {
                a.has_content_length = true;
            }
        }

        if a.has_chunked && a.has_content_length {
            a.te_cl_conflict = true;
        }

        // Check for duplicate Host headers
        let host_count = headers.iter().filter(|(n, _)| n.to_lowercase() == "host").count();
        if host_count > 1 { a.duplicate_host = true; }

        // HTTP Parameter Pollution: detect duplicate query keys
        a
    }

    /// Parse and detect parameter pollution.
    pub fn check_query_params(&self, query: &str) -> QueryAnomalies {
        let mut seen = std::collections::HashMap::new();
        let mut has_pollution = false;

        for pair in query.split('&') {
            let key = pair.split('=').next().unwrap_or("").to_lowercase();
            if !key.is_empty() {
                *seen.entry(key).or_insert(0usize) += 1;
            }
        }
        for count in seen.values() {
            if *count > 1 { has_pollution = true; break; }
        }
        QueryAnomalies { parameter_pollution: has_pollution }
    }
}

fn split_path_query(uri: &str) -> (&str, &str) {
    match uri.find('?') {
        Some(i) => (&uri[..i], &uri[i + 1..]),
        None    => (uri, ""),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum NormError {
    #[error("Invalid percent-encoding")]
    InvalidEncoding,
    #[error("Too many encoding layers")]
    TooManyEncodingLayers,
}

#[derive(Debug, Default)]
pub struct HeaderAnomalies {
    pub crlf_in_header:      bool,
    pub null_byte_in_header: bool,
    pub oversized_header:    bool,
    pub has_chunked:         bool,
    pub has_content_length:  bool,
    pub te_cl_conflict:      bool,
    pub duplicate_host:      bool,
}

#[derive(Debug, Default)]
pub struct QueryAnomalies {
    pub parameter_pollution: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_equivalent_to_login() {
        let n = Normalizer::default();
        let cases = vec![
            "/login",
            "//login",
            "/./login",
            "/%2flogin",
            "/%252flogin",
            "/a/../login",
            "/LOGIN",
            "/login/",
        ];
        for case in &cases {
            let r = n.normalize(case).unwrap();
            assert_eq!(r.path, "/login", "Failed for: {}", case);
        }
    }

    #[test]
    fn test_traversal_detected() {
        let n = Normalizer::default();
        let r = n.normalize("/admin/../../etc/passwd").unwrap();
        assert!(r.had_traversal);
        assert_eq!(r.path, "/etc/passwd");
    }

    #[test]
    fn test_double_encoding_counted() {
        let n = Normalizer::default();
        let r = n.normalize("/%252flogin").unwrap();
        assert!(r.encoding_layers >= 2);
    }

    #[test]
    fn test_crlf_detected() {
        let n = Normalizer::default();
        let r = n.normalize("/path\r\nX-Injected: evil").unwrap();
        assert!(r.had_crlf);
    }
}
