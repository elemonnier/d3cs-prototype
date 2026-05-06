// définit le contexte du network manager

use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};

use super::packets::{D3csFrame, D3csRequest};

#[derive(Clone)]
pub struct NetworkManager {
    inner: Arc<NetworkManagerInner>,
}

struct NetworkManagerInner {
    node_id: String,
    runtime_dir: PathBuf,
    group: Mutex<String>,
    joined: AtomicBool,
    subscriptions: Mutex<HashSet<String>>,
    offsets: Mutex<HashMap<String, u64>>,
}

// comprend l'ensemble des méthodes permettant de faire fonctionner le network manager
// on trouve dans src/network/logs/runtime/nodes et topics les logs de chaque noeud ou TM

impl NetworkManager {
    // constructeur du NetworkManager
    pub fn new(node_id: &str, runtime_dir: &str, initial_group: &str) -> Result<Self> {
        if node_id.trim().is_empty() {
            return Err(anyhow!("node_id is empty"));
        }
        if initial_group.trim().is_empty() {
            return Err(anyhow!("group is empty"));
        }
        Ok(Self {
            inner: Arc::new(NetworkManagerInner {
                node_id: node_id.to_string(),
                runtime_dir: PathBuf::from(runtime_dir),
                group: Mutex::new(initial_group.to_string()),
                joined: AtomicBool::new(false),
                subscriptions: Mutex::new(HashSet::new()),
                offsets: Mutex::new(HashMap::new()),
            }),
        })
    }

    // getter associé au node_id
    #[allow(dead_code)]
    pub fn node_id(&self) -> String {
        self.inner.node_id.clone()
    }

    // création des dossiers de log (nodes et topics) et fait rejoindre l'utilisateur au groupe réseau
    pub fn join(&self) -> Result<()> {
        let group = self.group()?;
        let group_dir = self.group_dir(&group);
        fs::create_dir_all(group_dir.join("topics"))?;
        fs::create_dir_all(group_dir.join("nodes"))?;
        let presence = group_dir
            .join("nodes")
            .join(format!("{}.presence", self.inner.node_id));
        self.write_line(&presence, "JOIN")?;
        self.write_current_group_marker(&group)?;
        self.inner.joined.store(true, Ordering::SeqCst);
        self.reset_offsets_to_end()?;
        Ok(())
    }

    // permet de s'abonner à un topic
    pub fn subscribe(&self, topic: &str) -> Result<()> {
        if topic.trim().is_empty() {
            return Err(anyhow!("topic is empty"));
        }
        if !self.inner.joined.load(Ordering::SeqCst) {
            self.join()?;
        }
        {
            let mut subs = self
                .inner
                .subscriptions
                .lock()
                .map_err(|_| anyhow!("lock poisoned"))?;
            subs.insert(topic.to_string());
        }
        let path = self.topic_path(&self.group()?, topic);
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

    // permet d'envoyer la trame
    #[allow(dead_code)]
    pub fn send(&self, dst: &str, request: D3csRequest, args: Vec<String>) -> Result<()> {
        let frame = D3csFrame::new(&self.inner.node_id, dst, request, args);
        self.publish(&frame)
    }

    // permet d'envoyer la trame, encapsulée dans du TLS (sécurisée)
    #[allow(dead_code)]
    pub fn send_secured(&self, dst: &str, request: D3csRequest, args: Vec<String>) -> Result<()> {
        let frame = D3csFrame::new(&self.inner.node_id, dst, request, args).with_secured(true);
        self.publish_secured(&frame)
    }

    // permet de publier une trame sur un topic
    pub fn publish(&self, frame: &D3csFrame) -> Result<()> {
        self.publish_frame(frame)
    }

    // permet de publier la trame de manière sécurisée
    pub fn publish_secured(&self, frame: &D3csFrame) -> Result<()> {
        let secured = frame.clone().with_secured(true);
        self.publish_frame(&secured)
    }

    // transforme une ligne brute reçue depuis un .log en trame réseau
    pub fn on_rcv(&self, raw: &str) -> Result<D3csFrame> {
        D3csFrame::from_wire(raw)
    }

    // permet de lire tous les messages reçus sur tous les topics auquel le NM s'est abonné
    pub fn poll(&self) -> Result<Vec<D3csFrame>> {
        if !self.inner.joined.load(Ordering::SeqCst) {
            return Ok(Vec::new());
        }

        let group = self.group()?;
        let topics = {
            let subs = self
                .inner
                .subscriptions
                .lock()
                .map_err(|_| anyhow!("lock poisoned"))?;
            subs.iter().cloned().collect::<Vec<_>>()
        };

        let mut out = Vec::new();
        for topic in topics {
            let path = self.topic_path(&group, &topic);
            if !path.exists() {
                continue;
            }

            let mut offsets = self
                .inner
                .offsets
                .lock()
                .map_err(|_| anyhow!("lock poisoned"))?;
            let offset = offsets.entry(topic.clone()).or_insert(0);

            let mut file = OpenOptions::new().read(true).open(&path)?;
            file.seek(SeekFrom::Start(*offset))?;
            let mut reader = BufReader::new(file);
            let mut cursor = *offset;

            loop {
                let mut line = String::new();
                let n = reader.read_line(&mut line)?;
                if n == 0 {
                    break;
                }
                cursor += n as u64;
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if let Ok(frame) = self.on_rcv(trimmed) {
                    out.push(frame);
                }
            }

            *offset = cursor;
        }

        Ok(out)
    }

    // sert à passer d'un groupe réseau à un autre (Net1<->Net2)
    pub fn set_group(&self, group: &str) -> Result<()> {
        if group.trim().is_empty() {
            return Err(anyhow!("group is empty"));
        }
        {
            let mut g = self
                .inner
                .group
                .lock()
                .map_err(|_| anyhow!("lock poisoned"))?;
            *g = group.to_string();
        }
        self.join()?;
        Ok(())
    }

    // permet de récupérer le nom du groupe réseau (Net1 ou Net2)
    pub fn group(&self) -> Result<String> {
        let g = self
            .inner
            .group
            .lock()
            .map_err(|_| anyhow!("lock poisoned"))?;
        Ok(g.clone())
    }

    // retourne si le NM a déjà rejoint le réseau
    pub fn is_joined(&self) -> bool {
        self.inner.joined.load(Ordering::SeqCst)
    }

    // récupère la liste des topics auquel le NM est abonné
    pub fn subscriptions(&self) -> Vec<String> {
        let subs = self.inner.subscriptions.lock();
        match subs {
            Ok(v) => v.iter().cloned().collect::<Vec<_>>(),
            Err(_) => Vec::new(),
        }
    }

    // permet de vérifier si un noeud est présent dans le groupe réseau courant
    pub fn is_node_present(&self, node_id: &str) -> Result<bool> {
        let group = self.group()?;
        let path = self
            .group_dir(&group)
            .join("nodes")
            .join(format!("{}.presence", node_id));
        Ok(path.exists())
    }

    // renvoie le groupe courant déclaré par un autre noeud
    pub fn current_group_of(&self, node_id: &str) -> Result<Option<String>> {
        let path = self.current_group_path(node_id);
        if !path.exists() {
            return Ok(None);
        }
        let raw = fs::read_to_string(path)?;
        let group = raw.trim().to_string();
        if group.is_empty() {
            return Ok(None);
        }
        Ok(Some(group))
    }

    // envoi du message réseau
    fn publish_frame(&self, frame: &D3csFrame) -> Result<()> {
        if !self.inner.joined.load(Ordering::SeqCst) {
            self.join()?;
        }
        let group = self.group()?;
        let topics = target_topics(&frame.dst);
        let wire = frame.to_transport_wire();

        for topic in topics {
            let path = self.topic_path(&group, topic);
            self.write_line(&path, &wire)?;
        }

        Ok(())
    }

    // permet d'écrire dans les fichiers de log
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

    // place l'offset à la fin des fichiers de log pour ignorer les logs précédents
    fn reset_offsets_to_end(&self) -> Result<()> {
        let group = self.group()?;
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
            let path = self.topic_path(&group, &topic);
            let len = file_len_or_zero(&path)?;
            offsets.insert(topic, len);
        }

        Ok(())
    }

    // renvoie le chemin du dossier appartenant au groupe réseau (Net1 ou Net2)
    fn group_dir(&self, group: &str) -> PathBuf {
        self.inner.runtime_dir.join(group)
    }

    // permet de construire le chemin du fichier log selon un topic
    fn topic_path(&self, group: &str, topic: &str) -> PathBuf {
        self.group_dir(group)
            .join("topics")
            .join(format!("{}.log", sanitize_topic(topic)))
    }

    // fichier partagé indiquant dans quel groupe un noeud se trouve actuellement
    fn current_group_path(&self, node_id: &str) -> PathBuf {
        self.inner
            .runtime_dir
            .join("current_groups")
            .join(format!("{}.group", sanitize_topic(node_id)))
    }

    // persiste le groupe courant pour éviter les faux positifs après un switch Net1/Net2
    fn write_current_group_marker(&self, group: &str) -> Result<()> {
        let path = self.current_group_path(&self.inner.node_id);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, format!("{group}\n"))?;
        Ok(())
    }
}

// ajoute une sécurité si des topics ont un / dans leur nom
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

// précise dans quels topics écrire la trame
fn target_topics(dst: &str) -> Vec<&str> {
    if dst == "TM" {
        vec!["TM"]
    } else {
        vec![dst]
    }
}

// récupère la taille d'un fichier, et renvoie zéro si le fichier n'existe pas
fn file_len_or_zero(path: &Path) -> Result<u64> {
    if !path.exists() {
        return Ok(0);
    }
    Ok(fs::metadata(path)?.len())
}
