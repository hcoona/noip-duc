use std::net::{IpAddr, Ipv4Addr};
use std::process::Stdio;
use std::time::Duration;

mod control;
mod observer;

pub mod dns_method;
pub mod noip2;
pub mod public_ip;
pub mod update;

pub use control::*;
pub use observer::*;

use public_ip::{Error as IpError, IpMethods};
use update::{update, UpdateError};

use tokio_util::sync::CancellationToken;

const USER_AGENT: &str = concat!(
    clap::crate_name!(),
    "/",
    clap::crate_version!(),
    " <support@noip.com>",
);

pub struct Config<'a> {
    pub username: &'a str,
    pub password: &'a str,
    pub hostnames: Option<&'a std::vec::Vec<String>>,
    pub check_interval: Duration,
    pub http_timeout: Duration,
    pub exec_on_change: Option<&'a str>,
    pub ip_method: &'a IpMethods,
    pub once: bool,
}

pub async fn updater(
    c: Config<'_>,
    observer: impl Observer + Clone,
    mut control: impl Controller,
    cancel: CancellationToken,
) -> Result<(), UpdateError> {
    let mut last_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
    let mut retries = 0u8;
    let mut last_error: Option<UpdateError> = None;

    let client = reqwest::Client::builder()
        .connect_timeout(c.http_timeout)
        .user_agent(USER_AGENT)
        .build()
        .map_err(|e| UpdateError::Connection(format!("{e}")))?;

    loop {
        observer.notify(Notification::CheckIp);

        let ip = match tokio::select! {
            _ = cancel.cancelled() => {
                observer.notify(Notification::Quitting);
                return Ok(());
            }
            res = c
                .ip_method
                .get(c.http_timeout, observer.clone(), &client, &cancel) => res,
        } {
            Ok(ip) => ip,
            Err(IpError::Cancelled) => {
                observer.notify(Notification::Quitting);
                return Ok(());
            }
            Err(e) => {
                // Should not happen; IpMethods::get retries internally for non-cancel errors
                observer.notify(Notification::GetIpFailedWillRetry(
                    e.to_string(),
                    retries,
                    Duration::from_secs(0),
                ));
                continue;
            }
        };

        if last_ip != ip {
            observer.notify(Notification::IpChanged {
                current: ip,
                previous: last_ip,
            });

            match tokio::select! {
                _ = cancel.cancelled() => {
                    observer.notify(Notification::Quitting);
                    return Ok(());
                }
                res = update(c.username, c.password, c.hostnames, ip, c.http_timeout, &client) => res,
            } {
                Ok(changed) => {
                    observer.notify(Notification::Updated {
                        current: ip,
                        previous: last_ip,
                    });

                    if changed {
                        if let Some(cmd_tmpl) = c.exec_on_change {
                            exec_command(
                                cmd_tmpl,
                                ip.to_string(),
                                last_ip.to_string(),
                                &observer,
                                &cancel,
                            )
                            .await;
                        }
                    }

                    last_ip = ip;
                    retries = 0;
                    last_error = None;
                }
                Err(e) => {
                    observer.notify(Notification::UpdateFailed(e.clone()));
                    last_error = Some(e);
                    retries += 1;
                }
            }
        } else {
            observer.notify(Notification::NoUpdateNeeded(ip));
        }

        if c.once {
            return match last_error {
                Some(e) => Err(e),
                None => Ok(()),
            };
        }

        let dur = match last_error {
            Some(ref e) => e.retry_backoff(retries, c.check_interval),
            None => c.check_interval,
        };

        observer.notify(Notification::NextCheck(dur));

        let start = std::time::Instant::now();

        loop {
            let remaining = dur.saturating_sub(start.elapsed());

            if remaining.is_zero() {
                break;
            }

            let ctrl_future = control.recv_timeout(remaining);

            tokio::select! {
                _ = cancel.cancelled() => {
                    observer.notify(Notification::Quitting);
                    return Ok(());
                }
                ctrl = ctrl_future => {
                    match ctrl {
                        Some(Control::UpdateNow) => break,
                        Some(Control::NotifyNextCheck) => {
                            observer.notify(Notification::NextCheck(dur - start.elapsed()));
                        }
                        Some(Control::Quit) | None => {
                            observer.notify(Notification::Quitting);
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
}

async fn exec_command<T: Observer>(
    cmd_tmpl: &str,
    ip: impl AsRef<str>,
    last_ip: impl AsRef<str>,
    observer: &T,
    cancel: &CancellationToken,
) {
    use tokio::process::Command;

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

    observer.notify(Notification::ExecCommand(cmd.clone()));

    let child = match shell()
        .arg(&cmd)
        .env("CURRENT_IP", ip.as_ref())
        .env("LAST_IP", last_ip.as_ref())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            observer.notify(Notification::ExecCommandError {
                command: cmd.clone(),
                exit: -1,
                stdout: String::new(),
                stderr: format!("{e}"),
            });
            return;
        }
    };

    let pid = child.id();
    let mut wait_fut = Box::pin(child.wait_with_output());

    tokio::select! {
        _ = cancel.cancelled() => {
            request_command_shutdown(pid);

            // Wait up to 3s for it to exit to stay within the global shutdown budget
            match tokio::time::timeout(Duration::from_secs(3), &mut wait_fut).await {
                Ok(Ok(output)) => {
                    notify_command_output(observer, &cmd, output);
                }
                Ok(Err(e)) => {
                    observer.notify(Notification::ExecCommandError {
                        command: cmd.clone(),
                        exit: -1,
                        stdout: String::new(),
                        stderr: format!("{e}"),
                    });
                }
                Err(_) => {
                    // Force kill
                    force_command_shutdown(pid);

                    match wait_fut.await {
                        Ok(output) => notify_command_output(observer, &cmd, output),
                        Err(e) => observer.notify(Notification::ExecCommandError {
                            command: cmd.clone(),
                            exit: -1,
                            stdout: String::new(),
                            stderr: format!("{e}"),
                        }),
                    }
                }
            }
        }
        output = &mut wait_fut => {
            match output {
                Ok(output) => notify_command_output(observer, &cmd, output),
                Err(e) => observer.notify(Notification::ExecCommandError {
                    command: cmd.clone(),
                    exit: -1,
                    stdout: String::new(),
                    stderr: format!("{e}"),
                }),
            }
        }
    }
}

fn notify_command_output<T: Observer>(observer: &T, cmd: &str, output: std::process::Output) {
    use std::str::from_utf8;
    if output.status.success() {
        observer.notify(Notification::ExecCommandSuccess {
            command: cmd.to_string(),
            stdout: from_utf8(&output.stdout).unwrap_or("").to_string(),
            stderr: from_utf8(&output.stderr).unwrap_or("").to_string(),
        });
    } else {
        observer.notify(Notification::ExecCommandError {
            command: cmd.to_string(),
            exit: output.status.code().unwrap_or(-1),
            stdout: from_utf8(&output.stdout).unwrap_or("").to_string(),
            stderr: from_utf8(&output.stderr).unwrap_or("").to_string(),
        });
    }
}

#[cfg(target_family = "unix")]
fn request_command_shutdown(pid: Option<u32>) {
    if let Some(pid) = pid {
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid as i32),
            nix::sys::signal::Signal::SIGTERM,
        );
    }
}

#[cfg(target_family = "unix")]
fn force_command_shutdown(pid: Option<u32>) {
    if let Some(pid) = pid {
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid as i32),
            nix::sys::signal::Signal::SIGKILL,
        );
    }
}

#[cfg(all(not(target_family = "unix"), target_os = "windows"))]
fn request_command_shutdown(pid: Option<u32>) {
    if let Some(pid) = pid {
        let _ = taskkill(pid, false);
    }
}

#[cfg(all(not(target_family = "unix"), target_os = "windows"))]
fn force_command_shutdown(pid: Option<u32>) {
    if let Some(pid) = pid {
        let _ = taskkill(pid, true);
    }
}

#[cfg(all(not(target_family = "unix"), not(target_os = "windows")))]
fn request_command_shutdown(_pid: Option<u32>) {}

#[cfg(all(not(target_family = "unix"), not(target_os = "windows")))]
fn force_command_shutdown(_pid: Option<u32>) {}

#[cfg(target_os = "windows")]
fn taskkill(pid: u32, force: bool) -> std::io::Result<()> {
    use std::process::Stdio as StdStdio;

    let mut cmd = std::process::Command::new("taskkill");
    cmd.arg("/PID").arg(pid.to_string()).arg("/T");
    if force {
        cmd.arg("/F");
    }
    cmd.stdout(StdStdio::null()).stderr(StdStdio::null());
    cmd.status().map(|_| ())
}
