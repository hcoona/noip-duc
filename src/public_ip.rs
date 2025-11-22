use std::net::{AddrParseError, IpAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use log::{debug, info, warn};
use url::Url;

use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

use crate::dns_method::{self, DnsMethod};
use crate::{Notification, Observer};

const IP_URL: &str = "http://ip1.dynupdate.no-ip.com";
const IP_URL_8245: &str = "http://ip1.dynupdate.no-ip.com:8245";
const IP_URL_AWS: &str = "http://169.254.169.254/latest/meta-data/public-ipv4";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("DNS method failed; {0}")]
    DnsMethod(#[from] dns_method::Error),

    #[error(transparent)]
    ParseError(#[from] ParseError),

    #[error(transparent)]
    HttpError(#[from] reqwest::Error),

    #[error("Failed to get IP request body from {0}; {1}")]
    ResponseBodyNotStr(String, String),

    #[error("Failed to parse IP from {0}; err={1}, body={2}")]
    ResponseParseIp(String, AddrParseError, String),

    #[error("Cancelled")]
    Cancelled,

    #[cfg(test)]
    #[error("Fail expected")]
    ExpectedFail,
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("Failed to parse IP URL; {0}")]
    UrlParse(#[from] url::ParseError),

    #[error("Failed to parse IP; {0}")]
    AddrParse(#[from] AddrParseError),

    #[error("Failed to parse IP; {0}")]
    DnsMethodError(#[from] dns_method::Error),

    #[error("Unknown IP method '{0}'")]
    UnknownMethod(String),
}

// TODO: Consider Box<DnsMethod> when making a list of IpMethod and getting rid of this clippy
// suppression
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum IpMethod {
    Dns(DnsMethod),
    Http(String),
    Static(IpAddr),

    #[cfg(test)]
    Fail(AtomicBool),
}

impl Clone for IpMethod {
    fn clone(&self) -> Self {
        match self {
            Self::Dns(d) => Self::Dns(d.clone()),
            Self::Http(s) => Self::Http(s.clone()),
            Self::Static(ip) => Self::Static(*ip),
            #[cfg(test)]
            Self::Fail(b) => Self::Fail(AtomicBool::new(b.load(Ordering::Relaxed))),
        }
    }
}

#[derive(Debug)]
pub struct IpMethods {
    methods: Vec<(IpMethod, AtomicBool)>,
}

impl Clone for IpMethods {
    fn clone(&self) -> Self {
        Self {
            methods: self
                .methods
                .iter()
                .map(|(m, b)| (m.clone(), AtomicBool::new(b.load(Ordering::Relaxed))))
                .collect(),
        }
    }
}

impl Default for IpMethods {
    fn default() -> Self {
        [
            IpMethod::Http(IP_URL.to_owned()),
            IpMethod::Http(IP_URL_8245.to_owned()),
        ]
        .into_iter()
        .collect()
    }
}

impl std::str::FromStr for IpMethod {
    type Err = ParseError;

    fn from_str(method: &str) -> Result<Self, Self::Err> {
        match method {
            "aws-metadata" => Ok(Self::Http(IP_URL_AWS.to_owned())),
            "dns" => Ok(Self::Dns(DnsMethod::ipcast()?)),
            "http" => Ok(Self::Http(IP_URL.to_owned())),
            "http-port-8245" => Ok(Self::Http(IP_URL_8245.to_owned())),

            #[cfg(test)]
            "fail" => Ok(Self::Fail(AtomicBool::new(false))),

            m if m.starts_with("dns:") => Ok(Self::Dns(m[4..].parse()?)),
            m if m.starts_with("http://") => Ok(Self::Http(Url::parse(m)?.to_string())),
            m if m.starts_with("https://") => Ok(Self::Http(Url::parse(m)?.to_string())),
            m if m.starts_with("static:") => Ok(Self::Static(m[7..].parse()?)),

            m => Err(ParseError::UnknownMethod(m.into())),
        }
    }
}

async fn get_ip_http_async(
    url: &str,
    timeout: Duration,
    client: &reqwest::Client,
) -> Result<IpAddr, Error> {
    let resp = client
        .get(url)
        .header("user-agent", crate::USER_AGENT)
        .timeout(timeout)
        .send()
        .await?;

    let body = resp
        .text()
        .await
        .map_err(|e| Error::ResponseBodyNotStr(url.into(), e.to_string()))?;

    body.parse()
        .map_err(|e| Error::ResponseParseIp(url.into(), e, body.clone()))
}

const fn retry_backoff(retry: u8) -> Duration {
    Duration::from_secs(match retry {
        0 => 3,
        1 => 6,
        2 => 30,
        3 => 300,
        4 => 600,
        _ => 1800,
    })
}

impl IpMethod {
    async fn try_get(
        &self,
        http_timeout: Duration,
        client: &reqwest::Client,
    ) -> Result<IpAddr, Error> {
        match self {
            Self::Http(url) => get_ip_http_async(url, http_timeout, client).await,
            Self::Dns(m) => m.get_ip().await.map_err(Into::into),
            Self::Static(ip) => Ok(*ip),

            #[cfg(test)]
            Self::Fail(b) => {
                if b.load(Ordering::Relaxed) {
                    panic!("failed ip method should not be called!");
                } else {
                    b.store(true, Ordering::Relaxed);
                    Err(Error::ExpectedFail)
                }
            }
        }
    }

    pub async fn get(
        &self,
        http_timeout: Duration,
        observer: impl Observer,
        client: &reqwest::Client,
        cancel: &CancellationToken,
    ) -> Result<IpAddr, Error> {
        let mut retries = 0u8;

        loop {
            let result: Result<IpAddr, Error> = tokio::select! {
                _ = cancel.cancelled() => Err(Error::Cancelled),
                res = self.try_get(http_timeout, client) => res,
            };

            match result {
                Ok(ip) => return Ok(ip),
                Err(e @ Error::Cancelled) => return Err(e),
                Err(error) => {
                    let next_try = retry_backoff(retries);

                    observer.notify(Notification::GetIpFailedWillRetry(
                        error.to_string(),
                        retries,
                        next_try,
                    ));

                    retries += 1;
                    tokio::select! {
                        _ = cancel.cancelled() => return Err(Error::Cancelled),
                        _ = sleep(next_try) => {}
                    }
                }
            }
        }
    }
}

impl std::str::FromStr for IpMethods {
    type Err = ParseError;

    fn from_str(methods: &str) -> Result<Self, Self::Err> {
        methods.split(',').map(IpMethod::from_str).collect()
    }
}

impl std::iter::FromIterator<IpMethod> for IpMethods {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = IpMethod>,
    {
        Self {
            methods: iter
                .into_iter()
                .map(|m| (m, AtomicBool::new(false)))
                .collect(),
        }
    }
}

impl IpMethods {
    pub fn empty() -> Self {
        Self {
            methods: Vec::new(),
        }
    }

    fn len(&self) -> usize {
        self.methods.len()
    }

    fn reset_failed(&self) {
        for i in 0..self.methods.len() {
            self.methods[i].1.store(false, Ordering::Relaxed);
        }
    }

    pub async fn get(
        &self,
        http_timeout: Duration,
        observer: impl Observer,
        client: &reqwest::Client,
        cancel: &CancellationToken,
    ) -> Result<IpAddr, Error> {
        if self.len() == 1 {
            return self.methods[0]
                .0
                .get(http_timeout, observer, client, cancel)
                .await;
        }

        let mut retries = 0u8;

        loop {
            for (m, had_error) in &self.methods {
                if cancel.is_cancelled() {
                    return Err(Error::Cancelled);
                }
                if had_error.load(Ordering::Relaxed) {
                    debug!("Skipping failed IP method {:?}", m);
                    continue;
                }

                info!("Attempting to get IP with method {:?}", m);

                let result: Result<IpAddr, Error> = tokio::select! {
                    _ = cancel.cancelled() => Err(Error::Cancelled),
                    res = m.try_get(http_timeout, client) => res,
                };

                match result {
                    Ok(ip) => return Ok(ip),
                    Err(e @ Error::Cancelled) => return Err(e),
                    Err(error) => {
                        warn!("Failed to get IP with method {:?}; {}", m, error);
                        had_error.store(true, Ordering::Relaxed);
                    }
                }
            }

            info!("Setting all failed IP methods to try again");
            self.reset_failed();

            let d = retry_backoff(retries);

            warn!(
                "Failed to get IP (retry={}), retrying after {}",
                retries,
                humantime::format_duration(d)
            );

            retries += 1;
            tokio::select! {
                _ = cancel.cancelled() => return Err(Error::Cancelled),
                _ = sleep(d) => {}
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::IpMethods;
    use crate::NotificationLogger;
    use std::sync::atomic::Ordering;
    use tokio_util::sync::CancellationToken;

    #[test]
    fn ipmethods_fromstr_for_one() {
        let x = "http".parse::<IpMethods>();
        assert!(x.is_ok());
        assert_eq!(1, x.unwrap().len());
    }

    #[test]
    fn ipmethods_fromstr_for_two() {
        let x = "dns,http".parse::<IpMethods>();
        assert!(x.is_ok());
        assert_eq!(2, x.unwrap().len());
    }

    #[test]
    fn ipmethods_fromstr_for_repeats() {
        let x = "dns,http,dns,http,dns,http,dns,http".parse::<IpMethods>();
        assert!(x.is_ok());
        assert_eq!(8, x.unwrap().len());
    }

    #[test]
    fn ipmethods_fromstr_for_all_formats() {
        let x = "aws-metadata,dns,http,http-port-8245,dns:localhost:1:h:A,http://h,https://h,static:169.254.1.1".parse::<IpMethods>();
        dbg!(&x);
        assert!(x.is_ok());
        assert_eq!(8, x.unwrap().len());
    }

    #[test]
    fn ipmethods_fromstr_fails_trailing_comma() {
        let x = "dns,http,".parse::<IpMethods>();
        assert!(x.is_err());
    }

    #[test]
    fn ipmethods_fromstr_fails_leading_comma() {
        let x = ",dns,http".parse::<IpMethods>();
        assert!(x.is_err());
    }

    #[test]
    fn ipmethods_fromstr_fails_first() {
        let x = "dns,x".parse::<IpMethods>();
        assert!(x.is_err());
    }

    #[test]
    fn ipmethods_fromstr_fails_second() {
        let x = "dns,x".parse::<IpMethods>();
        assert!(x.is_err());
    }

    #[tokio::test]
    async fn ipmethods_failed_methods_are_skipped() {
        // IpMethod::Fail panics if try_get is called twice
        let x = "fail,static:169.254.1.1"
            .parse::<IpMethods>()
            .expect("ip methods");
        let client = reqwest::Client::new();
        let cancel = CancellationToken::new();
        let _ = x
            .get(
                std::time::Duration::from_secs(1),
                NotificationLogger,
                &client,
                &cancel,
            )
            .await;
        assert!(x.methods[0].1.load(Ordering::Relaxed));
        //dbg!(x);
        //assert!(false);
    }

    #[tokio::test]
    #[should_panic]
    async fn ipmethods_failed_methods_reset_on_all_failed() {
        let x = "fail,fail".parse::<IpMethods>().expect("ip methods");
        // We expect this to panic because failed methods should be retried if all fail and Fail
        // always panic's on a second call.
        let client = reqwest::Client::new();
        let cancel = CancellationToken::new();
        let _ = x
            .get(
                std::time::Duration::from_secs(1),
                NotificationLogger,
                &client,
                &cancel,
            )
            .await;
    }
}
