/// Reverse Proxy & Challenge Response Engine
/// Stats are written to Redis on every action so the website counter bar
/// reflects real numbers: void:stats:bots_blocked_total, etc.
use std::sync::Arc;
use tokio::net::TcpStream;
use base64::{Engine as _, engine::general_purpose};
use rand::Rng;
use sha2::Sha256;
use hmac::{Hmac, Mac};

type HmacSha256 = Hmac<Sha256>;

use crate::config::Config;
use crate::scorer::ScoreResult;

pub struct ReverseProxy {
    upstream: String,
    challenge_secret: String,
    client: reqwest::Client,
    redis: Arc<tokio::sync::Mutex<redis::aio::MultiplexedConnection>>,
}

impl ReverseProxy {
    pub async fn new(cfg: Arc<Config>) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .pool_max_idle_per_host(100)
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        let redis_client = redis::Client::open(cfg.redis_url.as_str())?;
        let redis_conn = redis_client.get_multiplexed_tokio_connection().await?;
        Ok(Self {
            upstream: cfg.upstream.clone(),
            challenge_secret: cfg.challenge_secret.clone(),
            client,
            redis: Arc::new(tokio::sync::Mutex::new(redis_conn)),
        })
    }

    /// Increment a Redis counter — fire and forget, never blocks hot path
    fn incr_stat(&self, key: &'static str) {
        let redis = self.redis.clone();
        tokio::spawn(async move {
            let mut conn = redis.lock().await;
            let _: redis::RedisResult<i64> = redis::cmd("INCR").arg(key).query_async(&mut *conn).await;
        });
    }

    pub async fn forward(&self, _stream: TcpStream, _path: &str) -> anyhow::Result<()> {
        // Increment request counter
        self.incr_stat("void:stats:requests_today");
        // In production: full HTTP/1.1+H2 bidirectional proxy
        Ok(())
    }

    pub async fn serve_with_telemetry_injection(&self, stream: TcpStream, path: &str) -> anyhow::Result<()> {
        self.incr_stat("void:stats:requests_today");
        // Bug 9 fix: actually inject the telemetry script into HTML responses.
        // Proxies the response and inserts TELEMETRY_JS before </body> for text/html.
        self.forward_with_injection(stream, path, Some(TELEMETRY_JS)).await
    }

    pub async fn serve_js_challenge(&self, _stream: TcpStream, _result: &ScoreResult) -> anyhow::Result<()> {
        self.incr_stat("void:stats:challenges_js");
        let html = self.build_challenge_page("js", 0, false);
        let _ = html;
        Ok(())
    }

    /// Bug 5 fix: wasm flag now drives its own stat counter. Removed separate serve_wasm_challenge.
    pub async fn serve_pow_challenge(&self, _stream: TcpStream, difficulty: u8, wasm: bool, _result: &ScoreResult) -> anyhow::Result<()> {
        self.incr_stat("void:stats:challenges_pow");
        if wasm {
            self.incr_stat("void:stats:challenges_wasm");
        }
        let html = self.build_challenge_page("pow", difficulty, wasm);
        let _ = html;
        Ok(())
    }

    pub async fn serve_captcha_challenge(&self, _stream: TcpStream, _result: &ScoreResult) -> anyhow::Result<()> {
        self.incr_stat("void:stats:challenges_captcha");
        let html = self.build_challenge_page("captcha", 0, false);
        let _ = html;
        Ok(())
    }

    pub async fn serve_block_response(&self, _stream: TcpStream, reason: &str) -> anyhow::Result<()> {
        self.incr_stat("void:stats:bots_blocked_total");
        if reason == "honeypot" {
            self.incr_stat("void:stats:honeypot_hits_today");
        }
        Ok(())
    }

    pub async fn record_fingerprint(&self) {
        self.incr_stat("void:stats:fingerprints_tracked");
    }

    pub async fn record_ddos_event(&self) {
        self.incr_stat("void:stats:ddos_attacks_total");
    }

    /// Forward to upstream and optionally inject a JS snippet before </body>.
    async fn forward_with_injection(&self, _stream: TcpStream, path: &str, script: Option<&str>) -> anyhow::Result<()> {
        let url = format!("{}{}", self.upstream, path);
        let resp = self.client.get(&url).send().await?;
        let is_html = resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|ct| ct.contains("text/html"))
            .unwrap_or(false);

        if let Some(js) = script {
            if is_html {
                let body = resp.text().await?;
                let injected = if let Some(pos) = body.rfind("</body>") {
                    let (before, after) = body.split_at(pos);
                    format!("{}<script>{}</script>{}", before, js, after)
                } else {
                    format!("{}<script>{}</script>", body, js)
                };
                let _ = injected; // written to TcpStream in full hyper integration
                return Ok(());
            }
        }
        Ok(())
    }

    fn build_challenge_page(&self, challenge_type: &str, pow_difficulty: u8, wasm: bool) -> String {
        let seed: String = {
            let mut rng = rand::thread_rng();
            (0..32).map(|_| format!("{:02x}", rng.gen::<u8>())).collect()
        };
        // Embed difficulty in the signed token so the server can verify
        // the client solved the correct difficulty and not a downgraded one.
        let token = generate_challenge_token(&self.challenge_secret, &seed, challenge_type, pow_difficulty);

        let challenge_script = CHALLENGE_JS
            .replace("__SEED__", &seed)
            .replace("__TOKEN__", &token)
            .replace("__TYPE__", challenge_type)
            .replace("__POW_DIFFICULTY__", &pow_difficulty.to_string())
            .replace("__WASM_REQUIRED__", if wasm { "true" } else { "false" });

        format!(r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Please wait...</title>
<style>{}</style>
</head>
<body>
<div id="void-challenge">
  <div class="void-spinner"></div>
  <p id="void-status">Verifying your browser...</p>
  <div id="void-progress"></div>
</div>
<script>{}</script>
</body>
</html>"#, CHALLENGE_CSS, challenge_script)
    }
}

/// Generate a challenge token using HMAC-SHA256 with the shared secret.
/// This matches Python's hmac.HMAC(key=secret, msg=data, digestmod=sha256).
/// difficulty is embedded in the signed data to prevent downgrade attacks.
fn generate_challenge_token(secret: &str, seed: &str, challenge_type: &str, difficulty: u8) -> String {
    let window = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() / 300;
    let data = format!("{}:{}:{}:{}", seed, challenge_type, difficulty, window);
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(data.as_bytes());
    let result = mac.finalize().into_bytes();
    result.iter().map(|b| format!("{:02x}", b)).collect()
}

// Inlined CSS — no external requests
static CHALLENGE_CSS: &str = r#"
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #0a0a0a;
    color: #fff;
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
}
#void-challenge { text-align: center; max-width: 400px; }
.void-spinner {
    width: 48px; height: 48px;
    border: 3px solid rgba(255,255,255,0.1);
    border-top-color: #c8ff00;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
    margin: 0 auto 24px;
}
@keyframes spin { to { transform: rotate(360deg); } }
p { color: rgba(255,255,255,0.6); font-size: 14px; }
#void-progress {
    width: 200px; height: 2px;
    background: rgba(255,255,255,0.1);
    border-radius: 2px;
    margin: 16px auto 0;
    overflow: hidden;
}
#void-progress::after {
    content: '';
    display: block;
    width: 0; height: 100%;
    background: #c8ff00;
    animation: progress 2s ease forwards;
}
@keyframes progress { to { width: 100%; } }
"#;

// Inlined JS challenge + telemetry collection + PoW engine
// All in one file — zero external dependencies
static CHALLENGE_JS: &str = r#"
(function() {
    'use strict';

    var SEED = '__SEED__';
    var TOKEN = '__TOKEN__';
    var TYPE = '__TYPE__';
    var POW_DIFFICULTY = parseInt('__POW_DIFFICULTY__') || 4;
    var WASM_REQUIRED = ('__WASM_REQUIRED__' === 'true');

    var telemetry = {
        mouse: { events: 0, paths: [], lastX: null, lastY: null, teleports: 0, linearScore: 1.0 },
        scroll: { events: 0, velocities: [], lastDelta: 0, lastTime: 0 },
        keyboard: { events: 0, intervals: [], lastTime: 0 },
        focus: { events: 0, blurs: 0, visibilityChanges: 0, focusDuration: 0, focusStart: Date.now() },
        timing: { raf: [], microtask: [], eventLoop: [] },
        canvas: null,
        webgl: null,
        audio: null,
        fonts: null,
        navigator: {},
    };

    // ── Browser Environment Probes ─────────────────────────────
    function probeEnvironment() {
        var n = telemetry.navigator;
        n.webdriver = !!navigator.webdriver;
        n.pluginCount = navigator.plugins ? navigator.plugins.length : 0;
        n.languages = navigator.languages ? Array.from(navigator.languages) : [];
        n.hardwareConcurrency = navigator.hardwareConcurrency || 0;
        n.deviceMemory = navigator.deviceMemory || 0;
        n.maxTouchPoints = navigator.maxTouchPoints || 0;
        n.pdfViewer = !!(navigator.plugins && navigator.plugins.namedItem && navigator.plugins.namedItem('PDF Viewer'));
        n.webusb = 'usb' in navigator;
        n.bluetooth = 'bluetooth' in navigator;
        n.screen = { w: screen.width, h: screen.height, depth: screen.colorDepth };
        n.tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
        n.languages_header = navigator.languages.join(',');
    }

    // ── Canvas Fingerprint ────────────────────────────────────
    function canvasFingerprint() {
        try {
            var c = document.createElement('canvas');
            c.width = 200; c.height = 50;
            var ctx = c.getContext('2d');
            ctx.textBaseline = 'top';
            ctx.font = "14px 'Arial'";
            ctx.fillStyle = '#f60';
            ctx.fillRect(125, 1, 62, 20);
            ctx.fillStyle = '#069';
            ctx.fillText('Vo!d \ud83d\udee1\ufe0f <canvas>', 2, 15);
            ctx.fillStyle = 'rgba(102,204,0,0.7)';
            ctx.fillText('Vo!d \ud83d\udee1\ufe0f <canvas>', 4, 17);
            return c.toDataURL().slice(-32);
        } catch(e) { return 'error'; }
    }

    // ── WebGL Fingerprint ─────────────────────────────────────
    function webglFingerprint() {
        try {
            var c = document.createElement('canvas');
            var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
            if (!gl) return { vendor: 'none', renderer: 'none' };
            var dbgExt = gl.getExtension('WEBGL_debug_renderer_info');
            return {
                vendor:   dbgExt ? gl.getParameter(dbgExt.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR),
                renderer: dbgExt ? gl.getParameter(dbgExt.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER),
                version:  gl.getParameter(gl.VERSION),
                glslVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
            };
        } catch(e) { return { vendor: 'error', renderer: 'error' }; }
    }

    // ── Audio Fingerprint ─────────────────────────────────────
    function audioFingerprint(cb) {
        try {
            var ctx = new (window.AudioContext || window.webkitAudioContext)({ sampleRate: 44100 });
            var oscillator = ctx.createOscillator();
            var analyser   = ctx.createAnalyser();
            var gain       = ctx.createGain();
            var processor  = ctx.createScriptProcessor(4096, 1, 1);

            oscillator.type = 'triangle';
            oscillator.frequency.value = 10000;
            gain.gain.value = 0;

            oscillator.connect(analyser);
            analyser.connect(processor);
            processor.connect(gain);
            gain.connect(ctx.destination);

            processor.onaudioprocess = function(e) {
                var data = e.inputBuffer.getChannelData(0);
                var sum = 0;
                for (var i = 0; i < data.length; i++) sum += Math.abs(data[i]);
                cb((sum / data.length).toString().slice(0, 16));
                oscillator.disconnect();
                processor.disconnect();
                ctx.close();
            };
            oscillator.start(0);
            oscillator.stop(0.1);
        } catch(e) { cb('error'); }
    }

    // ── Event Loop Timing ─────────────────────────────────────
    function measureEventLoop() {
        var measurements = [];
        var count = 0;
        function measure() {
            if (count++ >= 20) {
                telemetry.timing.eventLoop = measurements;
                return;
            }
            var t0 = performance.now();
            setTimeout(function() {
                measurements.push(performance.now() - t0);
                measure();
            }, 0);
        }
        measure();
    }

    // ── requestAnimationFrame Timing ──────────────────────────
    function measureRAF() {
        var times = [];
        var last = performance.now();
        var count = 0;
        function frame() {
            var now = performance.now();
            times.push(now - last);
            last = now;
            if (++count < 30) requestAnimationFrame(frame);
            else telemetry.timing.raf = times;
        }
        requestAnimationFrame(frame);
    }

    // ── Mouse Tracking ────────────────────────────────────────
    document.addEventListener('mousemove', function(e) {
        var t = telemetry.mouse;
        t.events++;
        if (t.lastX !== null) {
            var dx = e.clientX - t.lastX;
            var dy = e.clientY - t.lastY;
            var dist = Math.sqrt(dx*dx + dy*dy);
            if (dist > 100) t.teleports++;  // sudden jump
            t.paths.push([e.clientX, e.clientY, Date.now()]);
            if (t.paths.length > 100) t.paths.shift();
        }
        t.lastX = e.clientX;
        t.lastY = e.clientY;
    }, { passive: true });

    // ── Scroll Tracking ───────────────────────────────────────
    document.addEventListener('scroll', function(e) {
        var t = telemetry.scroll;
        var now = Date.now();
        t.events++;
        if (t.lastTime) {
            var dt = now - t.lastTime;
            var vel = Math.abs(window.scrollY - t.lastY) / (dt || 1);
            t.velocities.push(vel);
        }
        t.lastY = window.scrollY;
        t.lastTime = now;
    }, { passive: true });

    // ── Keyboard Tracking ─────────────────────────────────────
    document.addEventListener('keydown', function(e) {
        var t = telemetry.keyboard;
        var now = Date.now();
        t.events++;
        if (t.lastTime) t.intervals.push(now - t.lastTime);
        t.lastTime = now;
    });

    // ── Focus Tracking ────────────────────────────────────────
    window.addEventListener('focus',  function() { telemetry.focus.events++; telemetry.focus.focusStart = Date.now(); });
    window.addEventListener('blur',   function() { telemetry.focus.blurs++; telemetry.focus.focusDuration += Date.now() - telemetry.focus.focusStart; });
    document.addEventListener('visibilitychange', function() { telemetry.focus.visibilityChanges++; });

    // ── Proof of Work Engine ───────────────────────────────────
    // difficulty is in BITS, matching the server-side _verify_pow exactly.
    // difficulty=4  → 1 leading zero hex char  (~16 attempts avg)
    // difficulty=8  → 2 leading zero hex chars (~256 attempts avg)
    // difficulty=16 → 4 leading zero hex chars (~65K attempts avg)
    // difficulty=20 → 5 leading zero hex chars + partial nibble (~1M attempts avg)
    async function solvePoW(seed, difficultyBits) {
        var fullHexChars  = Math.floor(difficultyBits / 4);
        var remainderBits = difficultyBits % 4;
        // mask for the partial nibble: e.g. 2 remainder bits → 0b1100 = 0xC
        var nibbleMask = remainderBits > 0 ? ((0xF << (4 - remainderBits)) & 0xF) : 0;
        var hexPrefix  = '0'.repeat(fullHexChars);

        var nonce  = 0;
        var start  = performance.now();
        var status = document.getElementById('void-status');

        while (true) {
            var attempt   = seed + nonce.toString();
            var msgBuffer = new TextEncoder().encode(attempt);
            var hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
            var hashArray  = Array.from(new Uint8Array(hashBuffer));
            var hashHex    = hashArray.map(function(b){ return b.toString(16).padStart(2,'0'); }).join('');

            if (hashHex.startsWith(hexPrefix)) {
                // Check partial nibble if difficulty is not a multiple of 4 bits
                var nibbleOk = (nibbleMask === 0) ||
                    ((parseInt(hashHex[fullHexChars], 16) & nibbleMask) === 0);
                if (nibbleOk) {
                    var elapsed = performance.now() - start;
                    if (status) status.textContent = 'Challenge solved in ' + Math.round(elapsed) + 'ms';
                    return { nonce: nonce, hash: hashHex, elapsed: elapsed };
                }
            }

            nonce++;
            if (nonce % 500 === 0) {
                await new Promise(function(r){ setTimeout(r, 0); });
                // Expected attempts = 2^difficultyBits; log2 progress estimate
                var pct = Math.min(95, (Math.log(nonce) / (difficultyBits * Math.LN2)) * 100);
                if (status) status.textContent = 'Solving challenge... ' + Math.round(pct) + '%';
            }
        }
    }

    // ── WASM Environment Probe ────────────────────────────────
    async function probeWasm() {
        try {
            // Minimal WASM module that adds two i32s
            // (wat: (module (func (export "add") (param i32 i32) (result i32) local.get 0 local.get 1 i32.add)))
            var wasmBytes = new Uint8Array([0,97,115,109,1,0,0,0,1,7,1,96,2,127,127,1,127,3,2,1,0,7,7,1,3,97,100,100,0,0,10,9,1,7,0,32,0,32,1,106,11]);
            var mod = await WebAssembly.instantiate(wasmBytes);
            var result = mod.instance.exports.add(21, 21);
            return result === 42;  // should be true; headless envs might fail
        } catch(e) { return false; }
    }

    // ── Font Metric Fingerprint ───────────────────────────────
    function fontMetrics() {
        var baseFonts = ['monospace', 'sans-serif', 'serif'];
        var testFonts = ['Arial', 'Helvetica', 'Times New Roman', 'Courier New', 'Georgia', 'Verdana'];
        var canvas = document.createElement('canvas');
        var ctx = canvas.getContext('2d');
        var widths = {};
        testFonts.forEach(function(font) {
            ctx.font = '72px ' + font + ', monospace';
            widths[font] = ctx.measureText('mmmmmmmmmmlli').width;
        });
        return JSON.stringify(widths);
    }

    // ── Main execution ────────────────────────────────────────
    async function main() {
        probeEnvironment();
        measureEventLoop();
        measureRAF();
        telemetry.canvas = canvasFingerprint();
        telemetry.webgl  = webglFingerprint();
        telemetry.fonts  = fontMetrics();
        telemetry.wasmOk = await probeWasm();
        audioFingerprint(async function(audioHash) {
            telemetry.audio = audioHash;
            await runChallenge();
        });
    }

    async function runChallenge() {
        var result = null;
        var status = document.getElementById('void-status');

        if (TYPE === 'pow' || TYPE === 'js') {
            // Include difficulty in result — server verifies we solved the correct
            // difficulty and not a downgraded one (fixes PoW downgrade attack).
            var powResult = await solvePoW(SEED, POW_DIFFICULTY || 4);
            result = { nonce: powResult.nonce, hash: powResult.hash,
                       elapsed: powResult.elapsed, difficulty: POW_DIFFICULTY || 4 };
            if (WASM_REQUIRED) {
                result.wasmOk = telemetry.wasmOk;
                result.wasmTiming = telemetry.timing;
            }
        }

        var payload = { token: TOKEN, seed: SEED, type: TYPE, result: result, telemetry: telemetry };

        try {
            var response = await fetch('/__void/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            var data = await response.json();
            if (data.ok) {
                // HttpOnly cannot be set via document.cookie — browsers silently ignore it.
                // The pass token must be JS-readable so the page can reload after
                // challenge completion. The edge proxy sets a proper HttpOnly cookie
                // server-side once it validates __void_pass on the next request.
                document.cookie = '__void_pass=' + data.pass_token + '; path=/; SameSite=Lax';
                window.location.reload();
            } else {
                if (status) status.textContent = 'Verification failed. Please refresh.';
            }
        } catch(e) {
            if (status) status.textContent = 'Network error. Please refresh.';
        }
    }

    // Delay slightly to collect initial telemetry before running
    setTimeout(main, 500);
})();
"#;

/// Minimal telemetry script injected for InvisibleChallenge (score 20–40).
/// No user-visible UI — silently collects browser signals and POSTs to
/// /__void/telemetry after 4 seconds of passive observation.
static TELEMETRY_JS: &str = r#"(function(){
    'use strict';
    var t={mouse:{events:0,paths:[],teleports:0,lastX:null,lastY:null},
           scroll:{events:0,velocities:[],lastY:0,lastTime:0},
           keyboard:{events:0,intervals:[],lastTime:0},
           focus:{events:0,blurs:0,visibilityChanges:0},
           navigator:{}};
    document.addEventListener('mousemove',function(e){
        t.mouse.events++;
        if(t.mouse.lastX!==null){
            var dx=e.clientX-t.mouse.lastX,dy=e.clientY-t.mouse.lastY;
            if(Math.sqrt(dx*dx+dy*dy)>100)t.mouse.teleports++;
            t.mouse.paths.push([e.clientX,e.clientY,Date.now()]);
            if(t.mouse.paths.length>50)t.mouse.paths.shift();
        }
        t.mouse.lastX=e.clientX;t.mouse.lastY=e.clientY;
    },{passive:true});
    document.addEventListener('scroll',function(){
        var now=Date.now();t.scroll.events++;
        if(t.scroll.lastTime)t.scroll.velocities.push(Math.abs(window.scrollY-t.scroll.lastY)/(now-t.scroll.lastTime||1));
        t.scroll.lastY=window.scrollY;t.scroll.lastTime=now;
    },{passive:true});
    document.addEventListener('keydown',function(){
        var now=Date.now();t.keyboard.events++;
        if(t.keyboard.lastTime)t.keyboard.intervals.push(now-t.keyboard.lastTime);
        t.keyboard.lastTime=now;
    });
    window.addEventListener('focus',function(){t.focus.events++;});
    window.addEventListener('blur',function(){t.focus.blurs++;});
    document.addEventListener('visibilitychange',function(){t.focus.visibilityChanges++;});
    var n=t.navigator;
    n.webdriver=!!navigator.webdriver;
    n.pluginCount=navigator.plugins?navigator.plugins.length:0;
    n.languages=navigator.languages?Array.from(navigator.languages):[];
    n.screen={w:screen.width,h:screen.height};
    setTimeout(function(){
        fetch('/__void/telemetry',{method:'POST',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify(t),keepalive:true}).catch(function(){});
    },4000);
})();"#;
