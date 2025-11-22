use std::time::Duration;

use async_trait::async_trait;
use tokio::time::sleep;

pub enum Control {
    UpdateNow,
    NotifyNextCheck,
    Quit,
}

#[async_trait]
pub trait Controller {
    async fn recv_timeout(&mut self, timeout: Duration) -> Option<Control>;
}

pub struct SleepOnlyController;

#[async_trait]
impl Controller for SleepOnlyController {
    async fn recv_timeout(&mut self, timeout: Duration) -> Option<Control> {
        sleep(timeout).await;
        Some(Control::UpdateNow)
    }
}

#[async_trait]
impl Controller for tokio::sync::mpsc::Receiver<Control> {
    async fn recv_timeout(&mut self, timeout: Duration) -> Option<Control> {
        tokio::select! {
            ctrl = self.recv() => ctrl,
            _ = sleep(timeout) => Some(Control::UpdateNow),
        }
    }
}
