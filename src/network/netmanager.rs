use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};

use super::dodwan::{self, DodwanEvents, DodwanWs, PeerEvent};
use super::packets::{D3csFrame, D3csRequest};

const PEER_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone)]
pub struct NetworkManager {
    inner: Arc<NetworkManagerInner>,
}

struct NetworkManagerInner {
    node_id: String,
    dodwan_config: dodwan::DodwanConfig,
    joined: AtomicBool,
    subscriptions: Mutex<HashSet<String>>,
    dodwan_ws: Mutex<Option<DodwanWs>>,
    peers: Mutex<HashSet<String>>,
    last_peer_refresh: Mutex<Instant>,
    pending_payloads: Mutex<VecDeque<String>>,
}

impl NetworkManager {
    pub fn new(node_id: &str, _runtime_dir: &str) -> Result<Self> {
        if node_id.trim().is_empty() {
            return Err(anyhow!("node_id is empty"));
        }
        let dodwan_config = dodwan::DodwanConfig::for_app_node(node_id)?;
        Ok(Self {
            inner: Arc::new(NetworkManagerInner {
                node_id: node_id.to_string(),
                dodwan_config,
                joined: AtomicBool::new(false),
                subscriptions: Mutex::new(HashSet::new()),
                dodwan_ws: Mutex::new(None),
                peers: Mutex::new(HashSet::new()),
                last_peer_refresh: Mutex::new(Instant::now()),
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
            let events = dodwan::get_peers(&mut ws)?;
            self.handle_dodwan_events(events)?;
            self.mark_peer_refresh()?;

            let mut slot = self
                .inner
                .dodwan_ws
                .lock()
                .map_err(|_| anyhow!("lock poisoned"))?;
            *slot = Some(ws);
        }

        self.inner.joined.store(true, Ordering::SeqCst);
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
            let events = dodwan::subscribe(ws, topic)?;
            self.handle_dodwan_events(events)?;
        }

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

    pub fn publish_on_topic(&self, topic: &str, frame: &D3csFrame) -> Result<()> {
        self.publish_frame_on_topics(frame, &[topic])
    }

    pub fn publish_secured_on_topic(&self, topic: &str, frame: &D3csFrame) -> Result<()> {
        let secured = frame.clone().with_secured(true);
        self.publish_frame_on_topics(&secured, &[topic])
    }

    pub fn on_rcv(&self, raw: &str) -> Result<D3csFrame> {
        D3csFrame::from_wire(raw)
    }

    pub fn poll(&self) -> Result<Vec<D3csFrame>> {
        if !self.inner.joined.load(Ordering::SeqCst) {
            return Ok(Vec::new());
        }

        let mut payloads = self.drain_pending_payloads()?;
        let (live_events, refresh_events) = {
            let mut slot = self
                .inner
                .dodwan_ws
                .lock()
                .map_err(|_| anyhow!("lock poisoned"))?;
            let ws = slot
                .as_mut()
                .ok_or_else(|| anyhow!("DoDWAN websocket unavailable"))?;
            let live_events = dodwan::poll_payloads(ws)?;
            let refresh_events = if self.should_refresh_peers()? {
                Some(dodwan::get_peers(ws)?)
            } else {
                None
            };
            (live_events, refresh_events)
        };
        self.handle_dodwan_events(live_events)?;
        if let Some(events) = refresh_events {
            self.handle_dodwan_events(events)?;
        }
        payloads.extend(self.drain_pending_payloads()?);

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

    pub fn peers(&self) -> Vec<String> {
        let peers = self.inner.peers.lock();
        match peers {
            Ok(v) => {
                let mut out = v.iter().cloned().collect::<Vec<_>>();
                out.sort();
                out
            }
            Err(_) => Vec::new(),
        }
    }

    fn publish_frame(&self, frame: &D3csFrame) -> Result<()> {
        let topics = target_topics(&frame.dst);
        self.publish_frame_on_topics(frame, &topics)
    }

    fn publish_frame_on_topics(&self, frame: &D3csFrame, topics: &[&str]) -> Result<()> {
        if !self.inner.joined.load(Ordering::SeqCst) {
            self.join()?;
        }
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
            for topic in topics {
                let events = dodwan::publish(ws, topic, &frame.src, &wire)?;
                self.handle_dodwan_events(events)?;
            }
        }

        Ok(())
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

    fn handle_dodwan_events(&self, events: DodwanEvents) -> Result<()> {
        self.apply_peer_events(events.peer_events)?;
        self.enqueue_payloads(events.payloads)
    }

    fn apply_peer_events(&self, events: Vec<PeerEvent>) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }

        let mut peers = self
            .inner
            .peers
            .lock()
            .map_err(|_| anyhow!("lock poisoned"))?;
        for event in events {
            match event {
                PeerEvent::Snapshot(items) => {
                    peers.clear();
                    peers.extend(items.into_iter().filter(|pid| !pid.trim().is_empty()));
                }
                PeerEvent::Add(pid) => {
                    if !pid.trim().is_empty() {
                        peers.insert(pid);
                    }
                }
                PeerEvent::Remove(pid) => {
                    peers.remove(&pid);
                }
                PeerEvent::Clear => peers.clear(),
            }
        }

        Ok(())
    }

    fn should_refresh_peers(&self) -> Result<bool> {
        let mut last_refresh = self
            .inner
            .last_peer_refresh
            .lock()
            .map_err(|_| anyhow!("lock poisoned"))?;
        if last_refresh.elapsed() < PEER_REFRESH_INTERVAL {
            return Ok(false);
        }
        *last_refresh = Instant::now();
        Ok(true)
    }

    fn mark_peer_refresh(&self) -> Result<()> {
        let mut last_refresh = self
            .inner
            .last_peer_refresh
            .lock()
            .map_err(|_| anyhow!("lock poisoned"))?;
        *last_refresh = Instant::now();
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

fn target_topics(dst: &str) -> Vec<&str> {
    if dst == "TM" {
        vec!["TM"]
    } else {
        vec![dst]
    }
}
