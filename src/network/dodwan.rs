use std::collections::{HashMap, HashSet};
use std::env;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};
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
static TOPICS_BY_MID: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
static DESTS_BY_MID: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();

#[derive(Clone, Debug, Default)]
pub(crate) struct DodwanEvents {
    pub(crate) payloads: Vec<String>,
    pub(crate) peer_events: Vec<PeerEvent>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PeerEvent {
    Snapshot(Vec<String>),
    Add(String),
    Remove(String),
    Clear,
}

#[derive(Clone, Debug)]
pub(crate) struct DodwanConfig {
    pub(crate) node_id: String,
    pub(crate) ws_port: u16,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct DodwanReceiveFilter {
    destinations: HashSet<String>,
}

impl DodwanReceiveFilter {
    pub(crate) fn from_subscriptions<'a>(subscriptions: impl IntoIterator<Item = &'a str>) -> Self {
        let destinations = subscriptions
            .into_iter()
            .filter(|subscription| !subscription.trim().is_empty())
            .map(ToOwned::to_owned)
            .collect();
        Self { destinations }
    }

    fn accepts_dest(&self, dest: &str) -> bool {
        dest.eq_ignore_ascii_case("TM")
            || self
                .destinations
                .iter()
                .any(|item| item.eq_ignore_ascii_case(dest))
    }
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

// fonction permettant de demander a DoDWAN la liste des peers directs.
pub(crate) fn get_peers(
    ws: &mut DodwanWs,
    receive_filter: &DodwanReceiveFilter,
) -> Result<DodwanEvents> {
    let request = serde_json::json!({
        "name": "get_peers",
        "tkn": "peers",
    });

    ws.send(Message::Binary(serde_json::to_vec(&request)?))
        .context("impossible de demander les voisins DoDWAN")?;

    read_ws_responses(
        ws,
        "lecture des voisins DoDWAN",
        ResponseKind::Peers,
        receive_filter,
    )
}

pub(crate) fn subscribe(
    ws: &mut DodwanWs,
    topic: &str,
    receive_filter: &DodwanReceiveFilter,
) -> Result<DodwanEvents> {
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

    read_ws_responses(ws, "souscription", ResponseKind::Ack, receive_filter)
}

// fonction permettant de publier un message puis de lire la réponse websocket
pub(crate) fn publish(
    ws: &mut DodwanWs,
    topic: &str,
    src: &str,
    dest: &str,
    payload: &str,
    receive_filter: &DodwanReceiveFilter,
) -> Result<DodwanEvents> {
    let data = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());

    let request = serde_json::json!({
        "name": "publish",
        "tkn": "t3",
        "desc": {
            "topic": topic,
            "src": src,
            "dest": dest,
        },
        "data": data,
    });

    ws.send(Message::Binary(serde_json::to_vec(&request)?))
        .context("impossible d'envoyer la publication DoDWAN")?;

    read_ws_responses(ws, "publication", ResponseKind::Ack, receive_filter)
}

// lit et affiche toutes les reponses websocket déjà produites par DoDWAN
// prend en paramètre "action", permettant de savoir si c'est au moment d'une souscription ou publication
// lit les notifications DoDWAN disponibles et renvoie les payloads applicatifs D3CS
pub(crate) fn poll_payloads(
    ws: &mut DodwanWs,
    receive_filter: &DodwanReceiveFilter,
) -> Result<DodwanEvents> {
    let previous_timeout = set_ws_read_timeout(ws, Some(WS_IDLE_TIMEOUT))?;
    let mut events = DodwanEvents::default();

    loop {
        match ws.read() {
            Ok(message) => {
                let Some(value) = message_to_json(&message)? else {
                    continue;
                };
                if !accepts_value_dest(&value, receive_filter) {
                    continue;
                }
                print_value_with_decoded_data(&value);
                handle_poll_pdu(ws, value, &mut events)?;
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
    Ok(events)
}

// prend la valeur d'une trame (value) sous la forme {...} et récupère sa valeur
// en cas de recv_desc ou de recv_msg, on appelle request_payload pour demander la valeur de la trame à DoDWAN
// en cas de recv_payload on appelle payload_from_value pour retourner la trame
fn handle_poll_pdu(ws: &mut DodwanWs, value: Value, events: &mut DodwanEvents) -> Result<()> {
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
                events.payloads.push(payload);
            }
        }
        "recv_pids" => events
            .peer_events
            .push(PeerEvent::Snapshot(peer_ids_from_value(&value))),
        "add_peer" => {
            if let Some(pid) = peer_id_from_value(&value) {
                events.peer_events.push(PeerEvent::Add(pid));
            }
        }
        "remove_peer" => {
            if let Some(pid) = peer_id_from_value(&value) {
                events.peer_events.push(PeerEvent::Remove(pid));
            }
        }
        "clear_peers" => events.peer_events.push(PeerEvent::Clear),
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
    Ok(Some(decode_dodwan_data(data)?))
}

fn peer_ids_from_value(value: &Value) -> Vec<String> {
    if let Some(items) = value.get("pids").and_then(Value::as_array) {
        return items
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|pid| !pid.is_empty())
            .map(ToOwned::to_owned)
            .collect();
    }

    value
        .get("pids")
        .and_then(Value::as_str)
        .map(parse_peer_list)
        .unwrap_or_default()
}

fn peer_id_from_value(value: &Value) -> Option<String> {
    value
        .get("pid")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|pid| !pid.is_empty())
        .map(ToOwned::to_owned)
}

fn parse_peer_list(raw: &str) -> Vec<String> {
    raw.trim()
        .trim_start_matches('[')
        .trim_start_matches('{')
        .trim_end_matches(']')
        .trim_end_matches('}')
        .split(',')
        .map(str::trim)
        .filter(|pid| !pid.is_empty())
        .map(ToOwned::to_owned)
        .collect()
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
#[derive(Clone, Copy)]
enum ResponseKind {
    Ack,
    Peers,
}

fn read_ws_responses(
    ws: &mut DodwanWs,
    action: &str,
    response_kind: ResponseKind,
    receive_filter: &DodwanReceiveFilter,
) -> Result<DodwanEvents> {
    let previous_timeout = set_ws_read_timeout(ws, Some(WS_IDLE_TIMEOUT))?;
    let deadline = Instant::now() + WS_RESPONSE_TIMEOUT;
    let mut response_seen = false;
    let mut events = DodwanEvents::default();

    loop {
        match ws.read() {
            Ok(message) => {
                let Some(value) = message_to_json(&message)? else {
                    print_message(&message);
                    continue;
                };
                let accepted = accepts_value_dest(&value, receive_filter);
                if accepted && should_log_dodwan_response(&value) {
                    print_message(&message);
                }
                match value
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                {
                    "ok" | "pong" => {
                        if matches!(response_kind, ResponseKind::Ack) {
                            response_seen = true;
                        }
                    }
                    "recv_pids" => {
                        handle_poll_pdu(ws, value, &mut events)?;
                        if matches!(response_kind, ResponseKind::Peers) {
                            response_seen = true;
                        }
                    }
                    "error" => {
                        let reason = value
                            .get("reason")
                            .and_then(Value::as_str)
                            .unwrap_or("erreur DoDWAN sans raison");
                        if matches!(response_kind, ResponseKind::Ack)
                            && is_duplicate_subscription_error(reason)
                        {
                            response_seen = true;
                            continue;
                        }
                        let _ = set_ws_read_timeout(ws, previous_timeout);
                        return Err(anyhow!("{action} refusee par DoDWAN: {reason}"));
                    }
                    _ if accepted => handle_poll_pdu(ws, value, &mut events)?,
                    _ => {}
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
    Ok(events)
}

fn should_log_dodwan_response(value: &Value) -> bool {
    let name = value
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let token = value.get("tkn").and_then(Value::as_str).unwrap_or_default();
    if name == "error"
        && value
            .get("reason")
            .and_then(Value::as_str)
            .map(is_duplicate_subscription_error)
            .unwrap_or(false)
    {
        return false;
    }
    !(name == "recv_pids" && token == "peers")
}

fn is_duplicate_subscription_error(reason: &str) -> bool {
    let reason = reason.to_ascii_lowercase();
    reason.contains("subscription") && reason.contains("already exists")
}

fn accepts_value_dest(value: &Value, receive_filter: &DodwanReceiveFilter) -> bool {
    remember_dest_from_value(value);
    let Some(dest) = dest_from_value(value) else {
        return true;
    };
    receive_filter.accepts_dest(&dest)
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
        Message::Binary(bytes) => match std::str::from_utf8(bytes) {
            Ok(text) => {
                if let Some(decoded) = decoded_data_console_json(text) {
                    crate::console_log(decoded);
                } else {
                    crate::console_log(text);
                }
            }
            Err(_) => crate::console_log(String::from_utf8_lossy(bytes)),
        },
        Message::Text(text) => {
            if let Some(decoded) = decoded_data_console_json(text) {
                crate::console_log(decoded);
            } else {
                crate::console_log(text);
            }
        }
        _ => crate::console_log(format!("{message:?}")),
    }
}

fn print_value_with_decoded_data(value: &Value) {
    remember_topic_from_value(value);
    remember_dest_from_value(value);
    if value.get("data").and_then(Value::as_str).is_none() {
        return;
    }
    let Ok(text) = serde_json::to_string(value) else {
        return;
    };
    if let Some(decoded) = decoded_data_console_json(&text) {
        crate::console_log(decoded);
    } else {
        crate::console_log(text);
    }
}

fn decoded_data_console_json(raw: &str) -> Option<String> {
    let value = serde_json::from_str::<Value>(raw).ok()?;
    remember_topic_from_value(&value);
    remember_dest_from_value(&value);
    let data = value.get("data").and_then(Value::as_str)?;
    let decoded = decode_dodwan_data(data).ok()?;
    let (data_start, data_end) = find_json_string_field_value_span(raw, "data")?;
    let decoded_json_string = serde_json::to_string(&decoded).ok()?;
    let mut decoded_json = format!(
        "{}{}{}",
        &raw[..data_start],
        decoded_json_string,
        &raw[data_end..]
    );
    if value.get("topic").is_none() {
        if let Some(topic) = topic_from_value(&value) {
            decoded_json = append_json_string_field(&decoded_json, "topic", &topic)?;
        }
    }
    if value.get("dest").is_none() {
        if let Some(dest) = dest_from_value(&value) {
            decoded_json = append_json_string_field(&decoded_json, "dest", &dest)?;
        }
    }
    Some(decoded_json)
}

fn decode_dodwan_data(data: &str) -> Result<String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(data.as_bytes())
        .map_err(|_| anyhow!("payload DoDWAN base64 invalide"))?;
    String::from_utf8(bytes).map_err(|_| anyhow!("payload DoDWAN UTF-8 invalide"))
}

fn topic_cache() -> &'static Mutex<HashMap<String, String>> {
    TOPICS_BY_MID.get_or_init(|| Mutex::new(HashMap::new()))
}

fn dest_cache() -> &'static Mutex<HashMap<String, String>> {
    DESTS_BY_MID.get_or_init(|| Mutex::new(HashMap::new()))
}

fn remember_topic_from_value(value: &Value) {
    let Some(mid) = message_id(value) else {
        return;
    };
    let Some(topic) = value
        .get("topic")
        .and_then(Value::as_str)
        .or_else(|| value.get("desc")?.get("topic")?.as_str())
    else {
        return;
    };
    if let Ok(mut topics) = topic_cache().lock() {
        topics.insert(mid, topic.to_string());
    }
}

fn remember_dest_from_value(value: &Value) {
    let Some(mid) = message_id(value) else {
        return;
    };
    let Some(dest) = value
        .get("dest")
        .and_then(Value::as_str)
        .or_else(|| value.get("desc")?.get("dest")?.as_str())
    else {
        return;
    };
    if let Ok(mut dests) = dest_cache().lock() {
        dests.insert(mid, dest.to_string());
    }
}

fn topic_from_value(value: &Value) -> Option<String> {
    if let Some(topic) = value.get("topic").and_then(Value::as_str) {
        return Some(topic.to_string());
    }
    if let Some(topic) = value
        .get("desc")
        .and_then(|desc| desc.get("topic"))
        .and_then(Value::as_str)
    {
        return Some(topic.to_string());
    }
    let mid = message_id(value)?;
    topic_cache().lock().ok()?.get(&mid).cloned()
}

fn dest_from_value(value: &Value) -> Option<String> {
    if let Some(dest) = value.get("dest").and_then(Value::as_str) {
        return Some(dest.to_string());
    }
    if let Some(dest) = value
        .get("desc")
        .and_then(|desc| desc.get("dest"))
        .and_then(Value::as_str)
    {
        return Some(dest.to_string());
    }
    let mid = message_id(value)?;
    dest_cache().lock().ok()?.get(&mid).cloned()
}

fn append_json_string_field(raw: &str, field: &str, value: &str) -> Option<String> {
    let insert_at = raw.rfind('}')?;
    let field_json = serde_json::to_string(field).ok()?;
    let value_json = serde_json::to_string(value).ok()?;
    let separator = if raw[..insert_at].trim_end().ends_with('{') {
        ""
    } else {
        ","
    };
    Some(format!(
        "{}{}{}:{}{}",
        &raw[..insert_at],
        separator,
        field_json,
        value_json,
        &raw[insert_at..]
    ))
}

fn find_json_string_field_value_span(raw: &str, field: &str) -> Option<(usize, usize)> {
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'"' {
            i += 1;
            continue;
        }

        let key_end = json_string_end(raw, i)?;
        let after_key = skip_json_ws(raw, key_end);
        if bytes.get(after_key) == Some(&b':') && json_string_equals(raw, i, key_end, field) {
            let value_start = skip_json_ws(raw, after_key + 1);
            if bytes.get(value_start) != Some(&b'"') {
                return None;
            }
            let value_end = json_string_end(raw, value_start)?;
            return Some((value_start, value_end));
        }

        i = key_end;
    }
    None
}

fn json_string_end(raw: &str, start: usize) -> Option<usize> {
    let bytes = raw.as_bytes();
    if bytes.get(start) != Some(&b'"') {
        return None;
    }

    let mut escaped = false;
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if !escaped => escaped = true,
            b'"' if !escaped => return Some(i + 1),
            _ => escaped = false,
        }
        i += 1;
    }
    None
}

fn skip_json_ws(raw: &str, start: usize) -> usize {
    let bytes = raw.as_bytes();
    let mut i = start;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\n' | b'\r' | b'\t') {
        i += 1;
    }
    i
}

fn json_string_equals(raw: &str, start: usize, end: usize, expected: &str) -> bool {
    let token = &raw[start..end];
    if let Some(inner) = token.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        if !inner.contains('\\') {
            return inner == expected;
        }
    }
    serde_json::from_str::<String>(token)
        .map(|s| s == expected)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoded_data_console_json_replaces_base64_data() {
        let raw = r#"{"data":"VExTKEQzQ1N8VE0xfFRNfEtFWV9SRVFVRVNUfHUxfHsiY2xhc3NpZmljYXRpb24iOiJGUi1EUiIsIm1pc3Npb24iOiJNMSJ9fFUxfFRNMSk=","tkn":"payload-N01_12","name":"recv_payload","mid":"N01_12"}"#;

        let decoded = decoded_data_console_json(raw).unwrap();

        assert_eq!(
            decoded,
            r#"{"data":"TLS(D3CS|TM1|TM|KEY_REQUEST|u1|{\"classification\":\"FR-DR\",\"mission\":\"M1\"}|U1|TM1)","tkn":"payload-N01_12","name":"recv_payload","mid":"N01_12"}"#
        );
    }

    #[test]
    fn decoded_data_console_json_adds_topic_from_desc() {
        let desc = serde_json::json!({
            "name": "recv_desc",
            "mid": "N99_1",
            "desc": {
                "topic": "TM"
            }
        });
        remember_topic_from_value(&desc);

        let raw = r#"{"data":"VExTKEQzQ1N8VE0xfFRNfEtFWV9SRVFVRVNUfHUxfHsiY2xhc3NpZmljYXRpb24iOiJGUi1EUiIsIm1pc3Npb24iOiJNMSJ9fFUxfFRNMSk=","tkn":"payload-N99_1","name":"recv_payload","mid":"N99_1"}"#;
        let decoded = decoded_data_console_json(raw).unwrap();

        assert_eq!(
            decoded,
            r#"{"data":"TLS(D3CS|TM1|TM|KEY_REQUEST|u1|{\"classification\":\"FR-DR\",\"mission\":\"M1\"}|U1|TM1)","tkn":"payload-N99_1","name":"recv_payload","mid":"N99_1","topic":"TM"}"#
        );
    }

    #[test]
    fn periodic_peer_snapshots_are_not_logged() {
        let refresh = serde_json::json!({
            "tkn": "peers",
            "name": "recv_pids",
            "pids": ["N00"],
        });
        let other_peer_message = serde_json::json!({
            "tkn": "manual",
            "name": "recv_pids",
            "pids": ["N00"],
        });

        assert!(!should_log_dodwan_response(&refresh));
        assert!(should_log_dodwan_response(&other_peer_message));
    }
}

// fonction permettant de fermer la connexion websocket lancée juste avant
#[allow(dead_code)]
fn disconnect(mut ws: DodwanWs) -> Result<()> {
    ws.close(None)
        .context("impossible de fermer la connexion websocket DoDWAN")?;
    Ok(())
}
