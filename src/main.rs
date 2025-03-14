use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::process::Command;
use std::{thread, time::Duration};

use anyhow::Result;
use clap::Parser;
use log::{debug, error, info};

mod dns_method;
mod noip2;
mod public_ip;
mod update;

use public_ip::IpMethods;
use update::{update, UpdateError};

const USER_AGENT: &str = concat!(
    clap::crate_name!(),
    "/",
    clap::crate_version!(),
    " <support@noip.com>",
);

// This is used to handle --import since the `exclusive` and `conflicts_with` options don't seem to
// work in clap 3.0.0-beta.5. Perhaps they will work in the future or when it goes stable. This
// should be revisited.
#[derive(Debug, Parser)]
struct PreConfig {
    /// Import config from noip2 and display it as environment variables.
    #[clap(long, parse(from_os_str), default_missing_value = "/etc/no-ip2.conf")]
    import: PathBuf,
}

#[derive(Debug, Parser)]
#[clap(about = "No-IP Dynamic Update Client", version = clap::crate_version!())]
struct Config {
    /// Your www.noip.com username. For better security, use Update Group credentials. https://www.noip.com/members/dns/dyn-groups.php
    #[clap(short, long, env = "NOIP_USERNAME")]
    username: String,

    /// Your www.noip.com password. For better security, use Update Group credentials. https://www.noip.com/members/dns/dyn-groups.php
    #[clap(short, long, env = "NOIP_PASSWORD")]
    password: String,

    /// Comma separated list of groups and hostnames to update. This may be empty when using group
    /// credentials and updating all hosts in the group.
    // use std::vec::Vec to avoid Clap magic
    #[clap(short = 'g', long, env = "NOIP_HOSTNAMES", parse(try_from_str = parse_hostnames))]
    hostnames: Option<std::vec::Vec<String>>,

    /// How often to check for a new IP address. Minimum: every 2 minutes.
    #[clap(long, env = "NOIP_CHECK_INTERVAL", default_value = "5m", parse(try_from_str = humantime::parse_duration))]
    check_interval: Duration,

    /// Timeout when making HTTP requests.
    #[clap(long, env = "NOIP_HTTP_TIMEOUT", default_value = "10s", parse(try_from_str = humantime::parse_duration))]
    http_timeout: Duration,

    /// Fork into the background
    #[clap(long)]
    daemonize: bool,

    /// When daemonizing, become this user.
    #[clap(long, env = "NOIP_DAEMON_USER")]
    daemon_user: Option<String>,

    /// When daemonizing, become this group.
    #[clap(long, env = "NOIP_DAEMON_GROUP")]
    daemon_group: Option<String>,

    /// When daemonizing, write process id to this file.
    #[clap(long, env = "NOIP_DAEMON_PID_FILE", parse(from_os_str))]
    daemon_pid_file: Option<PathBuf>,

    /// Increase logging verbosity. May be used multiple times.
    #[clap(short, long, parse(from_occurrences))]
    verbose: i32,

    /// Set the log level. Possible values: trace, debug, info, warn, error, critical. Overrides --verbose.
    #[clap(short, long, env = "NOIP_LOG_LEVEL")]
    log_level: Option<LogLevel>,

    /// Command to run when the IP address changes. It is run with the environment variables
    /// CURRENT_IP and LAST_IP set. Also, {{CURRENT_IP}} and {{LAST_IP}} are replaced with the
    /// respective values. This allows you to provide the variables as arguments to your command or
    /// read them from the environment. The command is always executed in a shell, sh or cmd on
    /// windows.
    ///
    /// Example
    ///
    ///   noip_duc -e 'mail -s "IP changed to {{CURRENT_IP}} from {{LAST_IP}}" user@example.com'
    #[clap(short = 'e', long, env = "NOIP_EXEC_ON_CHANGE")]
    exec_on_change: Option<String>,

    /// Methods used to discover public IP as a comma separated list. They are tried in order
    /// until a public IP is found. Failed methods are not retried unless all methods fail.
    ///
    /// Possible values are
    /// - 'aws-metadata': uses the AWS metadata URL to get the Elastic IP
    ///                   associated with your instance.
    /// - 'dns': Use No-IP's DNS public IP lookup system.
    /// - 'dns:<nameserver>:<port>:<qname>:<record type>': custom DNS lookup.
    /// - 'http': No-IP's HTTP method (the default).
    /// - 'http-port-8245': No-IP's HTTP method on port 8245.
    /// - 'static:<ip address>': always use this IP address. Helpful with --once.
    /// - HTTP URL: An HTTP URL that returns only an IP address.
    #[clap(
        long,
        env = "NOIP_IP_METHOD",
        default_value = "dns,http,http-port-8245",
        verbatim_doc_comment
    )]
    ip_method: IpMethods,

    /// Find the public IP and send an update, then exit. This is a good method to verify correct
    /// credentials.
    #[clap(long)]
    once: bool,

    /// Import config from noip2 and display it as environment variables.
    #[clap(long, default_value = "/etc/no-ip2.conf")]
    import: Option<Option<PathBuf>>,
}

#[derive(Debug)]
enum LogLevel {
    Trace,
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

impl std::str::FromStr for LogLevel {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use LogLevel::*;
        Ok(match s.to_lowercase().as_str() {
            "trace" => Trace,
            "debug" => Debug,
            "info" => Info,
            "warn" | "warning" => Warning,
            "error" => Error,
            "critical" => Critical,
            _ => anyhow::bail!("unknown log level"),
        })
    }
}

use std::fmt;
impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use LogLevel::*;
        match self {
            Trace => f.write_str("trace"),
            Debug => f.write_str("debug"),
            Info => f.write_str("info"),
            Warning => f.write_str("warning"),
            Error => f.write_str("error"),
            Critical => f.write_str("critical"),
        }
    }
}

// May be hostnames or group names
fn parse_hostnames(s: &str) -> Result<Vec<String>> {
    if s.len() >= 4000 {
        anyhow::bail!("hostnames too long");
    }

    let hostnames: Vec<String> = s.split(',').map(|s| s.trim().to_owned()).collect();

    for h in &hostnames {
        // Group names are alphanumeric only
        if h.chars().all(|c| char::is_ascii_alphanumeric(&c)) {
            continue;
        }
        if !is_hostname(h) {
            anyhow::bail!(
                "invalid hostname {}. Hostnames must be a comma separated list of hostnames and group names.",
                h
            );
        }
    }

    Ok(hostnames)
}

fn is_hostname(h: &str) -> bool {
    if h.split('.').count() > 63 {
        return false;
    }

    h.split('.').all(is_label)
}

// Must be all alphanumeric or hyphen. Since these will always be A or AAAA they cannot
// start with `_` like TXT or SRV can.
fn is_label(s: &str) -> bool {
    s.chars().all(|c| char::is_ascii_alphanumeric(&c) || c == '-')
        // Cannot start with hyphen or be empty
        && s.chars().next().map_or(false, |c| c != '-')
        // Cannot end with hyphen or be empty
        && s.chars().last().map_or(false, |c| c != '-')
}

fn main() -> anyhow::Result<()> {
    // Handle --import first to avoid required --username and --password
    if let Ok(c) = PreConfig::try_parse() {
        let imported = noip2::import(&c.import)?;
        print!("{}", imported);
        return Ok(());
    };

    let config = Config::parse();

    if config.check_interval < Duration::from_secs(120) {
        anyhow::bail!("--check_interval must be no less than 2 minutes");
    }

    let log_level = config.log_level.as_ref().unwrap_or(match config.verbose {
        0 => &LogLevel::Info,
        1 => &LogLevel::Debug,
        _ => &LogLevel::Trace,
    });

    if config.daemonize {
        // TODO: set up logging to a file
        env_logger::Builder::from_env(
            env_logger::Env::default().default_filter_or(log_level.to_string()),
        )
        .init();
        daemonize(&config)?;
    } else {
        env_logger::Builder::from_env(
            env_logger::Env::default().default_filter_or(log_level.to_string()),
        )
        .init();
    }

    debug!("{:?}", config);

    updater(&config)
}

fn daemonize(c: &Config) -> Result<()> {
    use daemonize::Daemonize;

    let mut daemonize = Daemonize::new().working_directory("/");

    if let Some(user) = &c.daemon_user {
        daemonize = match user.parse::<u32>() {
            Err(_) => daemonize.user(user.as_str()),
            Ok(uid) => daemonize.user(uid),
        }
    }

    if let Some(group) = &c.daemon_group {
        daemonize = match group.parse::<u32>() {
            Err(_) => daemonize.group(group.as_str()),
            Ok(gid) => daemonize.group(gid),
        }
    }

    if let Some(pid_file) = &c.daemon_pid_file {
        daemonize = daemonize.pid_file(pid_file).chown_pid_file(true);
    }

    daemonize.start()?;

    info!("running in background");

    Ok(())
}

fn updater(c: &Config) -> Result<()> {
    let mut last_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
    let mut retries = 0u8;
    let mut last_error: Option<UpdateError> = None;

    info!("Starting update loop");

    loop {
        debug!("checking for new ip");

        let ip = c.ip_method.get(c.http_timeout);

        if last_ip != ip {
            info!("got new ip; ip={}, last_ip={}", ip, last_ip);

            match update(
                &c.username,
                &c.password,
                c.hostnames.as_ref(),
                ip,
                c.http_timeout,
            ) {
                Ok(changed) => {
                    info!("update succeeded; ip={}, changed={}", ip, changed);

                    if changed {
                        if let Some(ref cmd_tmpl) = c.exec_on_change {
                            exec_command(cmd_tmpl, ip.to_string(), last_ip.to_string());
                        }
                    }

                    last_ip = ip;
                    retries = 0;
                    last_error = None;
                }
                Err(e) => {
                    error!("update failed; {}", e);
                    last_error = Some(e);
                    retries += 1;
                }
            }
        } else {
            debug!("got same ip; ip={}, last_ip={}", ip, last_ip);
        }

        if c.once {
            info!("In --once mode, exiting.");
            return match last_error {
                Some(e) => Err(e.into()),
                None => Ok(()),
            };
        }

        let dur = match last_error {
            Some(ref e) => e.retry_backoff(retries, c.check_interval),
            None => c.check_interval,
        };

        info!("checking ip again in {}", humantime::format_duration(dur));
        thread::sleep(dur);
    }
}

fn exec_command(cmd_tmpl: &str, ip: impl AsRef<str>, last_ip: impl AsRef<str>) {
    use std::str::from_utf8;

    fn shell() -> Command {
        if cfg!(target_os = "windows") {
            let mut cmd = Command::new("cmd");
            cmd.arg("/C");
            cmd
        } else {
            let mut cmd = Command::new("sh");
            cmd.arg("-c");
            cmd
        }
    }

    let cmd = cmd_tmpl
        .replace("{{CURRENT_IP}}", ip.as_ref())
        .replace("{{LAST_IP}}", last_ip.as_ref());

    debug!("running command; exec_on_change={cmd}");

    match shell()
        .arg(&cmd)
        .env("CURRENT_IP", ip.as_ref())
        .env("LAST_IP", last_ip.as_ref())
        .output()
    {
        Ok(output) => {
            if output.status.success() {
                info!(
                    "command success for `{}`; stdout={}, stderr={}",
                    &cmd,
                    from_utf8(&output.stdout).unwrap_or(""),
                    from_utf8(&output.stderr).unwrap_or("")
                );
            } else {
                error!(
                    "command failed for `{}`; exit={}, stdout={}, stderr={}'",
                    &cmd,
                    output.status.code().unwrap_or(-1),
                    from_utf8(&output.stdout).unwrap_or(""),
                    from_utf8(&output.stderr).unwrap_or("")
                );
            }
        }
        Err(e) => {
            error!("failed to execute cmd `{cmd}`; {e:?}");
        }
    }
}
