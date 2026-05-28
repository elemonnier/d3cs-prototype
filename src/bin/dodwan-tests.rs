// fichier permettant de tester les messages DoDWAN de base (ping, add_sub, publish)

use std::net::TcpStream;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use base64::Engine;
use chrono::Local;
use tungstenite::{
    connect as ws_connect, error::Error as WsError, stream::MaybeTlsStream, Message, WebSocket,
};

const NODE_ID: &str = "DODWAN_NAPI";
const WS_PORT: u16 = 18090;
const WS_RESPONSE_TIMEOUT: Duration = Duration::from_secs(3);
const WS_IDLE_TIMEOUT: Duration = Duration::from_millis(500);
type DodwanWs = WebSocket<MaybeTlsStream<TcpStream>>;

fn main() -> Result<()> {
    let home = Path::new("src/network/tools/dodwan").canonicalize()?;

    run_dodwan(&home, "start")?;

    let mut ws = connect()?;
    ping(&mut ws)?;
    subscribe(&mut ws, "d3cs")?;
    publish(&mut ws, "d3cs", "TM0", "TM1", "KEY_REQUEST", "true")?;

    disconnect(ws)?;

    run_dodwan(&home, "stop")?;
    Ok(())
}

// fonction permettant soit de lancer (start), soit de stopper (stop) dodwan-napi
fn run_dodwan(home: &Path, action: &str) -> Result<()> {
    let status = Command::new("./bin/dodwan.sh")
        .arg(action)
        .current_dir(home)
        .env("DODWAN_HOME", home)
        .env("node_id", NODE_ID)
        .env("dodwan_plugins", "dodwan-napi,dodwan-napi-ws")
        .env(
            "jvm_opts",
            "-Ddodwan_napi_ws.port=18090 -Ddodwan_napi_ws.serial_method=json",
        )
        .status()?;

    anyhow::ensure!(status.success(), "dodwan.sh {action} a echoue: {status}");
    Ok(())
}

// fonction permettant de se connecter au serveur websocket DoDWAN-NAPI
fn connect() -> Result<DodwanWs> {
    let url = format!("ws://127.0.0.1:{WS_PORT}/dodwan-tests");
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
fn ping(ws: &mut DodwanWs) -> Result<()> {
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
fn subscribe(ws: &mut DodwanWs, topic: &str) -> Result<()> {
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

    read_ws_responses(ws, "souscription")?;

    Ok(())
}

// fonction permettant de publier un message puis de lire la réponse websocket
fn publish(
    ws: &mut DodwanWs,
    topic: &str,
    sender: &str,
    receiver: &str,
    request_name: &str,
    secured: &str,
) -> Result<()> {
    let payload = serde_json::json!({
        "sender": sender,
        "receiver": receiver,
        "request": request_name,
        "secured": secured,
    });
    let data = base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&payload)?);

    let request = serde_json::json!({
        "name": "publish",
        "tkn": "t3",
        "desc": {
            "topic": topic,
            "src": "cli",
        },
        "data": data,
    });

    ws.send(Message::Binary(serde_json::to_vec(&request)?))
        .context("impossible d'envoyer la publication DoDWAN")?;

    read_ws_responses(ws, "publication")?;

    Ok(())
}

// lit et affiche toutes les reponses websocket déjà produites par DoDWAN
// prend en paramètre "action", permettant de savoir si c'est au moment d'une souscription ou publication
fn read_ws_responses(ws: &mut DodwanWs, action: &str) -> Result<()> {
    let previous_timeout = set_ws_read_timeout(ws, Some(WS_IDLE_TIMEOUT))?;
    let deadline = Instant::now() + WS_RESPONSE_TIMEOUT;
    let mut read_count = 0;

    loop {
        match ws.read() {
            Ok(message) => {
                read_count += 1;
                print_message(&message);
            }
            Err(WsError::Io(err))
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if read_count > 0 || Instant::now() >= deadline {
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
        read_count > 0,
        "aucune reponse websocket DoDWAN recue pour {action}"
    );
    Ok(())
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
        Message::Binary(bytes) => console_log(String::from_utf8_lossy(bytes)),
        _ => console_log(format!("{message:?}")),
    }
}

fn console_log(message: impl AsRef<str>) {
    println!(
        "{} {}",
        Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
        message.as_ref()
    );
}

// fonction permettant de fermer la connexion websocket lancée juste avant
fn disconnect(mut ws: DodwanWs) -> Result<()> {
    ws.close(None)
        .context("impossible de fermer la connexion websocket DoDWAN")?;
    Ok(())
}
