use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};

use super::dodwan::{self, DodwanWs};
use super::packets::{D3csFrame, D3csRequest};

#[derive(Clone)]
pub struct NetworkManager {
    inner: Arc<NetworkManagerInner>,
}

struct NetworkManagerInner {
    node_id: String,
    dodwan_config: dodwan::DodwanConfig,
    runtime_dir: PathBuf,
    joined: AtomicBool,
    subscriptions: Mutex<HashSet<String>>,
    offsets: Mutex<HashMap<String, u64>>,
    dodwan_ws: Mutex<Option<DodwanWs>>,
    pending_payloads: Mutex<VecDeque<String>>,
}

impl NetworkManager {
    pub fn new(node_id: &str, runtime_dir: &str) -> Result<Self> {
        if node_id.trim().is_empty() {
            return Err(anyhow!("node_id is empty"));
        }
        let dodwan_config = dodwan::DodwanConfig::for_app_node(node_id)?;
        Ok(Self {
            inner: Arc::new(NetworkManagerInner {
                node_id: node_id.to_string(),
                dodwan_config,
                runtime_dir: PathBuf::from(runtime_dir),
                joined: AtomicBool::new(false),
                subscriptions: Mutex::new(HashSet::new()),
                offsets: Mutex::new(HashMap::new()),
                dodwan_ws: Mutex::new(None),
                pending_payloads: Mutex::new(VecDeque::new()),
            }),
        })
    }

    #[allow(dead_code)]
    pub fn node_id(&self) -> String {
        self.inner.node_id.clone()
    }

    pub fn join(&self) -> Result<()> {
        let needs_dodwan_connection = self
            .inner
            .dodwan_ws
            .lock()
            .map_err(|_| anyhow!("lock poisoned"))?
            .is_none();

        if needs_dodwan_connection {
            if !dodwan_is_external() {
                let home = dodwan::default_home()?;
                dodwan::run_dodwan(&home, &self.inner.dodwan_config, "start")?;
            }
            let mut ws = dodwan::connect(&self.inner.dodwan_config)?;
            dodwan::ping(&mut ws)?;

            let mut slot = self
                .inner
                .dodwan_ws
                .lock()
                .map_err(|_| anyhow!("lock poisoned"))?;
            *slot = Some(ws);
        }

        fs::create_dir_all(self.inner.runtime_dir.join("topics"))?;
        fs::create_dir_all(self.inner.runtime_dir.join("nodes"))?;
        let presence = self
            .inner
            .runtime_dir
            .join("nodes")
            .join(format!("{}.presence", self.inner.node_id));
        self.write_line(&presence, "JOIN")?;
        self.inner.joined.store(true, Ordering::SeqCst);
        self.reset_offsets_to_end()?;
        Ok(())
    }

    pub fn subscribe(&self, topic: &str) -> Result<()> {
        if topic.trim().is_empty() {
            return Err(anyhow!("topic is empty"));
        }
        if !self.inner.joined.load(Ordering::SeqCst) {
            self.join()?;
        }
        let is_new_subscription = {
            let mut subs = self
                .inner
                .subscriptions
                .lock()
                .map_err(|_| anyhow!("lock poisoned"))?;
            subs.insert(topic.to_string())
        };
        if is_new_subscription {
            let mut slot = self
                .inner
                .dodwan_ws
                .lock()
                .map_err(|_| anyhow!("lock poisoned"))?;
            let ws = slot
                .as_mut()
                .ok_or_else(|| anyhow!("DoDWAN websocket unavailable"))?;
            let payloads = dodwan::subscribe(ws, topic)?;
            self.enqueue_payloads(payloads)?;
        }

        let path = self.topic_path(topic);
        if !path.exists() {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            OpenOptions::new().create(true).append(true).open(&path)?;
        }
        let len = file_len_or_zero(&path)?;
        let mut offsets = self
            .inner
            .offsets
            .lock()
            .map_err(|_| anyhow!("lock poisoned"))?;
        offsets.insert(topic.to_string(), len);
        Ok(())
    }

    #[allow(dead_code)]
    pub fn send(&self, dst: &str, request: D3csRequest, args: Vec<String>) -> Result<()> {
        let frame = D3csFrame::new(&self.inner.node_id, dst, request, args);
        self.publish(&frame)
    }

    #[allow(dead_code)]
    pub fn send_secured(&self, dst: &str, request: D3csRequest, args: Vec<String>) -> Result<()> {
        let frame = D3csFrame::new(&self.inner.node_id, dst, request, args).with_secured(true);
        self.publish_secured(&frame)
    }

    pub fn publish(&self, frame: &D3csFrame) -> Result<()> {
        self.publish_frame(frame)
    }

    pub fn publish_secured(&self, frame: &D3csFrame) -> Result<()> {
        let secured = frame.clone().with_secured(true);
        self.publish_frame(&secured)
    }

    pub fn on_rcv(&self, raw: &str) -> Result<D3csFrame> {
        D3csFrame::from_wire(raw)
    }

    pub fn poll(&self) -> Result<Vec<D3csFrame>> {
        if !self.inner.joined.load(Ordering::SeqCst) {
            return Ok(Vec::new());
        }

        let mut payloads = self.drain_pending_payloads()?;
        let live_payloads = {
            let mut slot = self
                .inner
                .dodwan_ws
                .lock()
                .map_err(|_| anyhow!("lock poisoned"))?;
            let ws = slot
                .as_mut()
                .ok_or_else(|| anyhow!("DoDWAN websocket unavailable"))?;
            dodwan::poll_payloads(ws)?
        };
        payloads.extend(live_payloads);

        let mut out = Vec::new();
        for payload in payloads {
            let trimmed = payload.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(frame) = self.on_rcv(trimmed) {
                out.push(frame);
            }
        }

        Ok(out)
    }

    pub fn is_joined(&self) -> bool {
        self.inner.joined.load(Ordering::SeqCst)
    }

    pub fn subscriptions(&self) -> Vec<String> {
        let subs = self.inner.subscriptions.lock();
        match subs {
            Ok(v) => v.iter().cloned().collect::<Vec<_>>(),
            Err(_) => Vec::new(),
        }
    }

    pub fn is_node_present(&self, node_id: &str) -> Result<bool> {
        let path = self
            .inner
            .runtime_dir
            .join("nodes")
            .join(format!("{}.presence", node_id));
        Ok(path.exists())
    }

    fn publish_frame(&self, frame: &D3csFrame) -> Result<()> {
        if !self.inner.joined.load(Ordering::SeqCst) {
            self.join()?;
        }
        let topics = target_topics(&frame.dst);
        let wire = frame.to_transport_wire();

        {
            let mut slot = self
                .inner
                .dodwan_ws
                .lock()
                .map_err(|_| anyhow!("lock poisoned"))?;
            let ws = slot
                .as_mut()
                .ok_or_else(|| anyhow!("DoDWAN websocket unavailable"))?;
            for topic in &topics {
                let payloads = dodwan::publish(ws, topic, &frame.src, &wire)?;
                self.enqueue_payloads(payloads)?;
            }
        }

        for topic in topics {
            let path = self.topic_path(topic);
            self.write_line(&path, &wire)?;
        }

        Ok(())
    }

    fn write_line(&self, path: &Path, line: &str) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut f = OpenOptions::new().create(true).append(true).open(path)?;
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")?;
        f.flush()?;
        Ok(())
    }

    fn reset_offsets_to_end(&self) -> Result<()> {
        let subs = {
            let s = self
                .inner
                .subscriptions
                .lock()
                .map_err(|_| anyhow!("lock poisoned"))?;
            s.iter().cloned().collect::<Vec<_>>()
        };

        let mut offsets = self
            .inner
            .offsets
            .lock()
            .map_err(|_| anyhow!("lock poisoned"))?;
        for topic in subs {
            let path = self.topic_path(&topic);
            let len = file_len_or_zero(&path)?;
            offsets.insert(topic, len);
        }

        Ok(())
    }

    fn topic_path(&self, topic: &str) -> PathBuf {
        self.inner
            .runtime_dir
            .join("topics")
            .join(format!("{}.log", sanitize_topic(topic)))
    }

    fn enqueue_payloads(&self, payloads: Vec<String>) -> Result<()> {
        if payloads.is_empty() {
            return Ok(());
        }
        let mut pending = self
            .inner
            .pending_payloads
            .lock()
            .map_err(|_| anyhow!("lock poisoned"))?;
        pending.extend(payloads);
        Ok(())
    }

    fn drain_pending_payloads(&self) -> Result<Vec<String>> {
        let mut pending = self
            .inner
            .pending_payloads
            .lock()
            .map_err(|_| anyhow!("lock poisoned"))?;
        Ok(pending.drain(..).collect())
    }
}

fn dodwan_is_external() -> bool {
    std::env::var("D3CS_DODWAN_EXTERNAL")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn sanitize_topic(topic: &str) -> String {
    topic
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>()
}

fn target_topics(dst: &str) -> Vec<&str> {
    if dst == "TM" {
        vec!["TM"]
    } else {
        vec![dst]
    }
}

fn file_len_or_zero(path: &Path) -> Result<u64> {
    if !path.exists() {
        return Ok(0);
    }
    Ok(fs::metadata(path)?.len())
}
