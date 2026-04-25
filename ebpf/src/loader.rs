/// eBPF program loader using Aya
/// Loads XDP and TC programs, exposes BPF maps to userspace.
use aya::{
    include_bytes_aligned,
    maps::{HashMap, Array},
    programs::{Xdp, XdpFlags, SchedClassifier, TcAttachType},
    Bpf,
};
use aya_log::BpfLogger;
use std::net::Ipv4Addr;
use tokio::signal;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let iface = std::env::var("INTERFACE").unwrap_or("eth0".into());
    info!("Loading Vo!d eBPF programs on interface: {}", iface);

    // Load compiled eBPF bytecode (embedded at compile time)
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/shield"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/shield"
    ))?;

    // Initialize BPF logger
    if let Err(e) = BpfLogger::init(&mut bpf) {
        warn!("Failed to init BPF logger: {}", e);
    }

    // ── Load XDP SYN Guard ────────────────────────────────────────────
    let program: &mut Xdp = bpf.program_mut("xdp_syn_guard").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::default())?;
    info!("XDP program attached to {}", iface);

    // ── Load TC Rate Monitor ──────────────────────────────────────────
    let _ = aya::programs::tc::TcHook::new(iface.as_str());
    let program: &mut SchedClassifier = bpf.program_mut("tc_rate_monitor").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, TcAttachType::Ingress)?;
    info!("TC program attached to {}", iface);

    // ── Expose map management via shared state ────────────────────────
    let blocklist_fd = bpf.map("ip_blocklist").unwrap();
    let tcp_fp_fd    = bpf.map("tcp_fingerprints").unwrap();
    let stats_fd     = bpf.map("global_stats_map").unwrap();

    // Spawn background task to expose maps to edge proxy via Unix socket
    tokio::spawn(async move {
        map_server(blocklist_fd, tcp_fp_fd, stats_fd).await;
    });

    info!("Vo!d eBPF stack running. Ctrl+C to stop.");
    signal::ctrl_c().await?;
    info!("Shutting down eBPF programs.");
    Ok(())
}

/// Block an IP at kernel level — called by the edge proxy when score > threshold
pub fn block_ip(bpf: &mut Bpf, ip: Ipv4Addr, reason: u8) -> anyhow::Result<()> {
    let mut map: HashMap<_, u32, u8> = HashMap::try_from(bpf.map_mut("ip_blocklist").unwrap())?;
    let key = u32::from(ip);
    map.insert(key, reason, 0)?;
    info!("Blocked IP {} at kernel level (reason={})", ip, reason);
    Ok(())
}

/// Unblock an IP (e.g., after CAPTCHA pass)
pub fn unblock_ip(bpf: &mut Bpf, ip: Ipv4Addr) -> anyhow::Result<()> {
    let mut map: HashMap<_, u32, u8> = HashMap::try_from(bpf.map_mut("ip_blocklist").unwrap())?;
    map.remove(&u32::from(ip))?;
    info!("Unblocked IP {}", ip);
    Ok(())
}

async fn map_server(
    _blocklist: &aya::maps::MapData,
    _tcp_fp: &aya::maps::MapData,
    _stats: &aya::maps::MapData,
) {
    // In production: expose BPF map operations via Unix domain socket
    // so the edge proxy Rust process can read TCP fingerprints and
    // write to the blocklist without needing eBPF capabilities itself.
}
