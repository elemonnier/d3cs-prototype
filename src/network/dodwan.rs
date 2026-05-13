use std::env;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use serde_json::Value;
use tungstenite::{
    connect as ws_connect, error::Error as WsError, stream::MaybeTlsStream, Message, WebSocket,
};

const WS_RESPONSE_TIMEOUT: Duration = Duration::from_secs(3);
const WS_IDLE_TIMEOUT: Duration = Duration::from_millis(500);
pub(crate) type DodwanWs = WebSocket<MaybeTlsStream<TcpStream>>;

#[derive(Clone, Debug)]
pub(crate) struct DodwanConfig {
    pub(crate) node_id: String,
    pub(crate) ws_port: u16,
}

impl DodwanConfig {
    pub(crate) fn for_app_node(app_node_id: &str) -> Result<Self> {
        let node_id =
            env::var("D3CS_DODWAN_NODE_ID").unwrap_or_else(|_| default_dodwan_node_id(app_node_id));
        if node_id.trim().is_empty() {
            anyhow::bail!("D3CS_DODWAN_NODE_ID is empty");
        }

        let ws_port = match env::var("D3CS_DODWAN_WS_PORT") {
            Ok(raw) => raw
                .parse::<u16>()
                .with_context(|| format!("D3CS_DODWAN_WS_PORT invalide: {raw}"))?,
            Err(_) => default_dodwan_ws_port(app_node_id),
        };

        Ok(Self { node_id, ws_port })
    }

    fn ws_url(&self) -> String {
        format!("ws://127.0.0.1:{}/dodwan-tests", self.ws_port)
    }
}

fn default_dodwan_node_id(app_node_id: &str) -> String {
    if app_node_id.eq_ignore_ascii_case("Authority") {
        "TM0".to_string()
    } else if let Some(rest) = app_node_id.to_ascii_uppercase().strip_prefix('U') {
        if rest.chars().all(|c| c.is_ascii_digit()) {
            return format!("TM{rest}");
        }
        app_node_id.to_string()
    } else {
        app_node_id.to_string()
    }
}

fn default_dodwan_ws_port(app_node_id: &str) -> u16 {
    if app_node_id.eq_ignore_ascii_case("Authority") {
        18090
    } else if let Some(rest) = app_node_id.to_ascii_uppercase().strip_prefix('U') {
        if let Ok(i) = rest.parse::<u16>() {
            return 18090 + i;
        }
        18090
    } else {
        18090
    }
}

// fonction permettant soit de lancer (start), soit de stopper (stop) dodwan-napi
pub(crate) fn default_home() -> Result<PathBuf> {
    Ok(Path::new("src/network/tools/dodwan").canonicalize()?)
}

pub(crate) fn run_dodwan(home: &Path, config: &DodwanConfig, action: &str) -> Result<()> {
    let jvm_opts = format!(
        "-Ddodwan_napi_ws.port={} -Ddodwan_napi_ws.serial_method=json",
        config.ws_port
    );

    let status = Command::new("./bin/dodwan.sh")
        .arg(action)
        .current_dir(home)
        .env("DODWAN_HOME", home)
        .env("node_id", &config.node_id)
        .env("dodwan_plugins", "dodwan-napi,dodwan-napi-ws")
        .env("jvm_opts", jvm_opts)
        .status()?;

    anyhow::ensure!(status.success(), "dodwan.sh {action} a echoue: {status}");
    Ok(())
}

// fonction permettant de se connecter au serveur websocket DoDWAN-NAPI
pub(crate) fn connect(config: &DodwanConfig) -> Result<DodwanWs> {
    let url = config.ws_url();
    let deadline = Instant::now() + Duration::from_secs(10);

    // loop : tentative de connexion websocket
    // si ça marche, on retourne l'objet ws
    // si ça ne fonctionne pas, attendre 100ms puis réessayer
    // si on atteint 10 secondes, renvoyer l'erreur
    loop {
        match ws_connect(&url) {
            Ok((ws, _response)) => return Ok(ws),
            Err(err) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(100));
                let _ = err;
            }
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("impossible de se connecter au websocket DoDWAN sur {url}")
                })
            }
        }
    }
}

// fonction permettant d'envoyer un ping puis de lire la réponse websocket
pub(crate) fn ping(ws: &mut DodwanWs) -> Result<()> {
    ws.send(Message::Binary(br#"{"name":"ping","tkn":"t1"}"#.to_vec()))
        .context("impossible d'envoyer le ping DoDWAN")?;

    // lecture de la réponse {"tkn":"t1","name":"pong"}, initialement des bytes
    let message = ws
        .read()
        .context("impossible de lire la reponse websocket DoDWAN")?;
    print_message(&message);

    Ok(())
}

// fonction permettant d'envoyer une souscription puis de lire la réponse websocket
pub(crate) fn subscribe(ws: &mut DodwanWs, topic: &str) -> Result<Vec<String>> {
    let request = serde_json::json!({
        "name": "add_sub",
        "tkn": "t2",
        "key": format!("sub-{topic}"),
        "desc": {
            "topic": topic,
        },
    });

    ws.send(Message::Binary(serde_json::to_vec(&request)?))
        .context("impossible d'envoyer la souscription DoDWAN")?;

    read_ws_responses(ws, "souscription")
}

// fonction permettant de publier un message puis de lire la réponse websocket
pub(crate) fn publish(
    ws: &mut DodwanWs,
    topic: &str,
    src: &str,
    payload: &str,
) -> Result<Vec<String>> {
    let data = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());

    let request = serde_json::json!({
        "name": "publish",
        "tkn": "t3",
        "desc": {
            "topic": topic,
            "src": src,
        },
        "data": data,
    });

    ws.send(Message::Binary(serde_json::to_vec(&request)?))
        .context("impossible d'envoyer la publication DoDWAN")?;

    read_ws_responses(ws, "publication")
}

// lit et affiche toutes les reponses websocket déjà produites par DoDWAN
// prend en paramètre "action", permettant de savoir si c'est au moment d'une souscription ou publication
// lit les notifications DoDWAN disponibles et renvoie les payloads applicatifs D3CS
pub(crate) fn poll_payloads(ws: &mut DodwanWs) -> Result<Vec<String>> {
    let previous_timeout = set_ws_read_timeout(ws, Some(WS_IDLE_TIMEOUT))?;
    let mut payloads = Vec::new();

    loop {
        match ws.read() {
            Ok(message) => {
                let Some(value) = message_to_json(&message)? else {
                    continue;
                };
                handle_poll_pdu(ws, value, &mut payloads)?;
            }
            Err(WsError::Io(err))
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(err) => {
                let _ = set_ws_read_timeout(ws, previous_timeout);
                return Err(err).context("impossible de lire les messages DoDWAN");
            }
        }
    }

    set_ws_read_timeout(ws, previous_timeout)?;
    Ok(payloads)
}

// prend la valeur d'une trame (value) sous la forme {...} et récupère sa valeur
// en cas de recv_desc ou de recv_msg, on appelle request_payload pour demander la valeur de la trame à DoDWAN
// en cas de recv_payload on appelle payload_from_value pour retourner la trame
fn handle_poll_pdu(ws: &mut DodwanWs, value: Value, payloads: &mut Vec<String>) -> Result<()> {
    let name = value
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    match name {
        "recv_desc" | "recv_msg" => {
            if let Some(mid) = message_id(&value) {
                request_payload(ws, &mid)?;
            }
        }
        "recv_payload" => {
            if let Some(payload) = payload_from_value(&value)? {
                payloads.push(payload);
            }
        }
        _ => {}
    }
    Ok(())
}

// envoi d'une requête de payload, suite à un recv_desc/recv_msg
fn request_payload(ws: &mut DodwanWs, mid: &str) -> Result<()> {
    let request = serde_json::json!({
        "name": "get_payload",
        "tkn": format!("payload-{mid}"),
        "mid": mid,
    });

    ws.send(Message::Binary(serde_json::to_vec(&request)?))
        .context("impossible de demander le payload DoDWAN")?;
    Ok(())
}

// renvoie un mid en fonction d'une valeur de message
fn message_id(value: &Value) -> Option<String> {
    value
        .get("mid")
        .and_then(Value::as_str)
        .or_else(|| {
            value
                .get("desc")
                .and_then(|desc| desc.get("_docid"))
                .and_then(Value::as_str)
        })
        .map(ToString::to_string)
}

// retourne la trame en fonction du message dodwan
fn payload_from_value(value: &Value) -> Result<Option<String>> {
    let Some(data) = value.get("data").and_then(Value::as_str) else {
        return Ok(None);
    };
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(data.as_bytes())
        .map_err(|_| anyhow!("payload DoDWAN base64 invalide"))?;
    let payload = String::from_utf8(bytes).map_err(|_| anyhow!("payload DoDWAN UTF-8 invalide"))?;
    Ok(Some(payload))
}

// renvoie le json d'un message binaire ou texte
fn message_to_json(message: &Message) -> Result<Option<Value>> {
    match message {
        Message::Binary(bytes) => Ok(Some(serde_json::from_slice(bytes)?)),
        Message::Text(text) => Ok(Some(serde_json::from_str(&text)?)),
        _ => Ok(None),
    }
}

// permet de lire les réponses du websocket
fn read_ws_responses(ws: &mut DodwanWs, action: &str) -> Result<Vec<String>> {
    let previous_timeout = set_ws_read_timeout(ws, Some(WS_IDLE_TIMEOUT))?;
    let deadline = Instant::now() + WS_RESPONSE_TIMEOUT;
    let mut response_seen = false;
    let mut payloads = Vec::new();

    loop {
        match ws.read() {
            Ok(message) => {
                print_message(&message);
                let Some(value) = message_to_json(&message)? else {
                    continue;
                };
                match value
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                {
                    "ok" | "pong" => response_seen = true,
                    "error" => {
                        let _ = set_ws_read_timeout(ws, previous_timeout);
                        let reason = value
                            .get("reason")
                            .and_then(Value::as_str)
                            .unwrap_or("erreur DoDWAN sans raison");
                        return Err(anyhow!("{action} refusee par DoDWAN: {reason}"));
                    }
                    _ => handle_poll_pdu(ws, value, &mut payloads)?,
                }
            }
            Err(WsError::Io(err))
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if response_seen || Instant::now() >= deadline {
                    break;
                }
            }
            Err(err) => {
                let _ = set_ws_read_timeout(ws, previous_timeout);
                return Err(err).with_context(|| {
                    format!("impossible de lire les reponses websocket DoDWAN pour {action}")
                });
            }
        }
    }

    set_ws_read_timeout(ws, previous_timeout)?;

    anyhow::ensure!(
        response_seen,
        "aucune reponse websocket DoDWAN recue pour {action}"
    );
    Ok(payloads)
}

fn set_ws_read_timeout(ws: &mut DodwanWs, timeout: Option<Duration>) -> Result<Option<Duration>> {
    match ws.get_mut() {
        MaybeTlsStream::Plain(stream) => {
            let previous_timeout = stream.read_timeout()?;
            stream.set_read_timeout(timeout)?;
            Ok(previous_timeout)
        }
        _ => anyhow::bail!("le timeout websocket n'est gere que pour les connexions ws://"),
    }
}

// permet d'afficher un message présent dans la boucle
fn print_message(message: &Message) {
    match message {
        Message::Binary(bytes) => println!("{}", String::from_utf8_lossy(bytes)),
        _ => println!("{message:?}"),
    }
}

// fonction permettant de fermer la connexion websocket lancée juste avant
#[allow(dead_code)]
fn disconnect(mut ws: DodwanWs) -> Result<()> {
    ws.close(None)
        .context("impossible de fermer la connexion websocket DoDWAN")?;
    Ok(())
}
