use std::borrow::Cow;
use std::fmt;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use log::info;
use trust_dns_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use trust_dns_resolver::proto::rr::rdata::txt::TXT;
use trust_dns_resolver::Resolver;

const IPCAST1: &str = "ipcast1.dynupdate.no-ip.com:8253";
const IPCAST2: &str = "ipcast2.dynupdate.no-ip.com:8253";

pub fn resolve(name: &str) -> anyhow::Result<SocketAddr> {
    name.to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("Failed to use system to lookup IP for {}", name))
}

pub struct DnsMethod {
    description: String,
    resolver: ResolverFactory,
    qname: String,
    record_type: RecordType,
}

#[allow(clippy::upper_case_acronyms)]
enum RecordType {
    A,
    AAAA,
    TXT,
}

impl fmt::Debug for DnsMethod {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.write_str(self.description.as_str())
    }
}

impl std::str::FromStr for DnsMethod {
    type Err = anyhow::Error;

    /**
     * <nameserver>:<port>:<qname>:<record type>
     */
    fn from_str(spec: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = spec.split(':').collect();
        if parts.len() != 4 {
            return Err(anyhow::anyhow!(
                "Failed to parse DNS method spec; expected 4 parts received {}",
                parts.len()
            ));
        }

        Ok(Self {
            description: spec.to_owned(),
            resolver: ResolverFactory::from_host_and_port(
                spec[0..=(parts[0].len() + parts[1].len())].to_owned(),
            )?,
            qname: parts[2].into(),
            record_type: parts[3].parse()?,
        })
    }
}

impl std::str::FromStr for RecordType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "A" => Ok(Self::A),
            "AAAA" => Ok(Self::AAAA),
            "TXT" => Ok(Self::TXT),
            _ => Err(anyhow::anyhow!("Unknown record type")),
        }
    }
}

impl DnsMethod {
    pub fn ipcast() -> Result<Self> {
        Ok(Self {
            description: "No-IP Anycast DNS Tools".to_owned(),
            resolver: ResolverFactory::for_ipcast()?,
            qname: "xip.".into(),
            record_type: RecordType::A,
        })
    }

    pub fn get_ip(&self) -> Result<IpAddr> {
        match self.record_type {
            RecordType::A => self.get_ip_a(),
            RecordType::AAAA => self.get_ip_aaaa(),
            RecordType::TXT => self.get_ip_txt(),
        }
    }

    fn get_ip_a(&self) -> Result<IpAddr> {
        let response = self.get_resolver()?.ipv4_lookup(self.qname.as_str())?;
        Ok(IpAddr::V4(
            response
                .iter()
                .next()
                .ok_or_else(|| anyhow::anyhow!("No answers in DNS response"))?
                .0,
        ))
    }

    fn get_ip_aaaa(&self) -> Result<IpAddr> {
        let response = self.get_resolver()?.ipv6_lookup(self.qname.as_str())?;
        Ok(IpAddr::V6(
            response
                .iter()
                .next()
                .ok_or_else(|| anyhow::anyhow!("No answers in DNS response"))?
                .0,
        ))
    }

    fn get_ip_txt(&self) -> Result<IpAddr> {
        let response = self.get_resolver()?.txt_lookup(self.qname.as_str())?;
        response.iter().find_map(parse_txt).ok_or_else(|| {
            anyhow::anyhow!("No answers that appeared to be IP addresses in DNS response")
        })
    }

    fn get_resolver(&self) -> Result<Resolver> {
        self.resolver.build()
    }
}

fn parse_txt(txt: &TXT) -> Option<IpAddr> {
    for v in txt.iter() {
        match std::str::from_utf8(v) {
            Ok(s) => match s.parse() {
                Ok(ip) => return Some(ip),
                Err(_) => info!("txt rdata does not look like IP address; rdata={}", s),
            },
            Err(e) => info!("failed to parse txt data as utf8; {}", e),
        }
    }

    None
}

struct ResolverFactory {
    nameservers: Vec<Cow<'static, str>>,
    opts: ResolverOpts,
}

impl ResolverFactory {
    fn new(nameservers: Vec<Cow<'static, str>>, opts: ResolverOpts) -> Self {
        Self { nameservers, opts }
    }

    fn build(&self) -> Result<Resolver> {
        let mut config = ResolverConfig::new();

        for ns in &self.nameservers {
            config.add_name_server(NameServerConfig {
                socket_addr: resolve(ns.as_ref()).with_context(||
                    format!(
                    "Failed to create dns method with {} as resolver; possibly no internet connection",
                    &ns)
                )?,
                protocol: Protocol::Udp,
                tls_dns_name: None,
                trust_negative_responses: true,
                bind_addr: None,
            })
        }

        Resolver::new(config, self.opts.clone()).map_err(Into::into)
    }

    fn for_ipcast() -> Result<Self> {
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_secs(5);
        opts.use_hosts_file = false;
        opts.attempts = 2;

        Ok(Self::new(vec![IPCAST1.into(), IPCAST2.into()], opts))
    }

    fn from_host_and_port(host_and_port: String) -> Result<Self> {
        let mut opts = ResolverOpts::default();
        opts.use_hosts_file = false;
        opts.attempts = 1;

        Ok(Self::new(vec![host_and_port.into()], opts))
    }
}
