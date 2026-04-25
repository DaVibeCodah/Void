/// IP Intelligence Engine
/// ASN classification, geo lookup, TOR/VPN detection, reputation scoring.
use std::net::IpAddr;
use std::collections::HashSet;
use maxminddb::{geoip2, Reader};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IpIntelligence {
    pub ip: String,
    pub asn: Option<u32>,
    pub asn_org: Option<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub is_datacenter: bool,
    pub is_tor: bool,
    pub is_vpn: bool,
    pub is_proxy: bool,
    pub is_residential: bool,
    pub is_mobile: bool,
    pub is_cgnat: bool,
    pub is_bogon: bool,
    pub reputation_score: f32,  // 0.0 = clean, 1.0 = known bad
    pub threat_categories: Vec<String>,
}

pub struct IpIntelEngine {
    asn_reader:  Reader<Vec<u8>>,
    city_reader: Reader<Vec<u8>>,
    tor_exits:   HashSet<IpAddr>,
    datacenter_asns: HashSet<u32>,
    vpn_asns:    HashSet<u32>,
    reputation_cache: std::collections::HashMap<IpAddr, f32>,
}

impl IpIntelEngine {
    pub async fn new(asn_db: &str, city_db: &str) -> anyhow::Result<Self> {
        let asn_reader  = Reader::open_readfile(asn_db)?;
        let city_reader = Reader::open_readfile(city_db)?;
        let tor_exits   = Self::load_tor_exits().await;

        Ok(Self {
            asn_reader,
            city_reader,
            tor_exits,
            datacenter_asns: DATACENTER_ASNS.iter().copied().collect(),
            vpn_asns: VPN_ASNS.iter().copied().collect(),
            reputation_cache: Default::default(),
        })
    }

    pub fn classify(&self, addr: IpAddr) -> IpIntelligence {
        let mut intel = IpIntelligence {
            ip: addr.to_string(),
            is_bogon: is_bogon(addr),
            is_cgnat: is_cgnat(addr),
            is_tor: self.tor_exits.contains(&addr),
            ..Default::default()
        };

        // ASN lookup
        if let Ok(asn_record) = self.asn_reader.lookup::<geoip2::Asn>(addr) {
            intel.asn     = asn_record.autonomous_system_number;
            intel.asn_org = asn_record.autonomous_system_organization.map(|s| s.to_string());

            if let Some(asn) = intel.asn {
                intel.is_datacenter = self.datacenter_asns.contains(&asn);
                intel.is_vpn        = self.vpn_asns.contains(&asn);
            }
        }

        // Geo lookup
        if let Ok(city) = self.city_reader.lookup::<geoip2::City>(addr) {
            intel.country  = city.country.and_then(|c| c.iso_code).map(|s| s.to_string());
            intel.latitude  = city.location.as_ref().and_then(|l| l.latitude);
            intel.longitude = city.location.as_ref().and_then(|l| l.longitude);
        }

        // Reputation score
        if let Some(&rep) = self.reputation_cache.get(&addr) {
            intel.reputation_score = rep;
        }

        // Classify connection type
        intel.is_residential = !intel.is_datacenter && !intel.is_vpn
            && !intel.is_tor && !intel.is_cgnat;

        intel
    }

    /// Detect impossible geo velocity between two locations.
    pub fn is_geo_velocity_impossible(
        lat1: f64, lon1: f64, lat2: f64, lon2: f64,
        elapsed_seconds: f64,
    ) -> bool {
        let dist_km = haversine_km(lat1, lon1, lat2, lon2);
        // Max realistic travel speed: 1000 km/h (aircraft)
        let max_possible_km = 1000.0 * (elapsed_seconds / 3600.0);
        dist_km > max_possible_km + 50.0  // 50km tolerance
    }

    async fn load_tor_exits() -> HashSet<IpAddr> {
        // In production: fetch https://check.torproject.org/torbulkexitlist
        // For now, return empty set — populate via background refresh task
        HashSet::new()
    }

    /// Background refresh: reload TOR exits every 30 minutes.
    pub async fn refresh_tor_exits(&mut self) {
        match reqwest::get("https://check.torproject.org/torbulkexitlist").await {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(text) = resp.text().await {
                    self.tor_exits = text.lines()
                        .filter(|l| !l.starts_with('#'))
                        .filter_map(|l| l.trim().parse::<IpAddr>().ok())
                        .collect();
                    tracing::info!("Loaded {} TOR exit nodes", self.tor_exits.len());
                }
            }
            _ => tracing::warn!("Failed to refresh TOR exit list"),
        }
    }
}

fn haversine_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const R: f64 = 6371.0;
    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();
    let a = (dlat / 2.0).sin().powi(2)
          + lat1.to_radians().cos()
          * lat2.to_radians().cos()
          * (dlon / 2.0).sin().powi(2);
    R * 2.0 * a.sqrt().atan2((1.0 - a).sqrt())
}

fn is_bogon(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            // RFC 1918
            o[0] == 10
            || (o[0] == 172 && o[1] >= 16 && o[1] <= 31)
            || (o[0] == 192 && o[1] == 168)
            // Loopback
            || o[0] == 127
            // Link-local
            || (o[0] == 169 && o[1] == 254)
            // Multicast
            || o[0] >= 224
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

fn is_cgnat(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 100 && o[1] >= 64 && o[1] <= 127  // RFC 6598
        }
        _ => false,
    }
}

// Major datacenter ASNs
static DATACENTER_ASNS: &[u32] = &[
    16509,  // Amazon AWS
    14618,  // Amazon AWS-2
    15169,  // Google Cloud
    8075,   // Microsoft Azure
    20940,  // Akamai
    13335,  // Cloudflare
    32934,  // Facebook
    63949,  // Linode
    14061,  // DigitalOcean
    20473,  // Vultr
    46652,  // ServerHub
    29802,  // HVC-AS
    24940,  // Hetzner
    51167,  // Contabo
    36352,  // ColoCrossing
    55967,  // BL Networks
    46844,  // Sharktech
    40676,  // Psychz Networks
    62567,  // DigitalOcean-2
    135377, // Ucloud
    45102,  // Alibaba Cloud
    9394,   // Tencent Cloud
];

// Known VPN provider ASNs
static VPN_ASNS: &[u32] = &[
    9009,   // M247 (many VPNs use this)
    49981,  // WorldStream
    60068,  // Datacamp (VPN aggregator)
    200651, // AEZA
    57523,  // Chang Way Technologies
    136787, // TEFINCOM (NordVPN)
    212238, // Datacamp EU
];
