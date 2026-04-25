use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{info, warn};

mod config;
mod fingerprint;
mod http2_fp;
mod ip_intel;
mod middleware;
mod normalizer;
mod proxy;
mod ratelimit;
mod scorer;
mod session;
mod tls_fp;

use config::Config;
use middleware::ShieldMiddleware;
use proxy::ReverseProxy;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cfg = Arc::new(Config::from_env()?);
    let proxy = Arc::new(ReverseProxy::new(cfg.clone()).await?);
    let middleware = Arc::new(ShieldMiddleware::new(cfg.clone()).await?);

    let addr: SocketAddr = cfg.listen_addr.parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!("Vo!d edge proxy listening on {}", addr);

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let proxy = proxy.clone();
        let mw = middleware.clone();

        tokio::spawn(async move {
            if let Err(e) = mw.handle(stream, peer_addr, proxy).await {
                warn!("Connection error from {}: {}", peer_addr, e);
            }
        });
    }
}
