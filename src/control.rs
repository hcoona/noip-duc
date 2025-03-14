use std::sync::mpsc;
use std::thread;
use std::time::Duration;

pub enum Control {
    UpdateNow,
    NotifyNextCheck,
}

pub trait ControlChannel {
    fn recv_timeout(&self, timeout: Duration) -> Option<Control>;
}

pub struct SleepOnlyControl;

impl ControlChannel for SleepOnlyControl {
    fn recv_timeout(&self, timeout: Duration) -> Option<Control> {
        thread::sleep(timeout);
        Some(Control::UpdateNow)
    }
}

impl ControlChannel for mpsc::Receiver<Control> {
    fn recv_timeout(&self, timeout: Duration) -> Option<Control> {
        self.recv_timeout(timeout).ok()
    }
}
