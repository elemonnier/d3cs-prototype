use std::net::TcpStream;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tungstenite::{connect as ws_connect, stream::MaybeTlsStream, Message, WebSocket};

const NODE_ID: &str = "DODWAN_NAPI";
const WS_PORT: u16 = 18090;
type DodwanWs = WebSocket<MaybeTlsStream<TcpStream>>;

fn main() -> Result<()> {
    let home = Path::new("src/network/tools/dodwan").canonicalize()?;

    run_dodwan(&home, "start")?;

    let mut ws = connect()?;
    ping(&mut ws)?;
    subscribe(&mut ws)?;
    publish(&mut ws)?;

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
fn subscribe(ws: &mut DodwanWs) -> Result<()> {
    ws.send(Message::Binary(
        br#"{"name":"add_sub","tkn":"t2","key":"sub-d3cs","desc":{"topic":"d3cs"}}"#.to_vec(),
    ))
    .context("impossible d'envoyer la souscription DoDWAN")?;

    let message = ws
        .read()
        .context("impossible de lire la reponse websocket DoDWAN")?;
    print_message(&message);

    Ok(())
}

// fonction permettant de publier un message puis de lire la réponse websocket
fn publish(ws: &mut DodwanWs) -> Result<()> {
    ws.send(Message::Binary(
        br#"{"name":"publish","tkn":"t3","desc":{"topic":"d3cs","src":"cli"},"dummy":1}"#.to_vec(),
    ))
    .context("impossible d'envoyer la publication DoDWAN")?;

    for i in 1..=2 {
        let message = ws.read().with_context(|| {
            format!("impossible de lire la reponse websocket DoDWAN numero {i}")
        })?;
        print_message(&message);
    }

    Ok(())
}

// permet d'afficher un message présent dans la boucle
fn print_message(message: &Message) {
    match message {
        Message::Binary(bytes) => println!("{}", String::from_utf8_lossy(bytes)),
        _ => println!("{message:?}"),
    }
}

// fonction permettant de fermer la connexion websocket lancée juste avant
fn disconnect(mut ws: DodwanWs) -> Result<()> {
    ws.close(None)
        .context("impossible de fermer la connexion websocket DoDWAN")?;
    Ok(())
}
