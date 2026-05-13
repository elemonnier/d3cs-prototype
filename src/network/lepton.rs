// lecture des connexions dans le réseau opportuniste

use std::collections::{HashSet, VecDeque};
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};

const DEFAULT_CONSOLE_HOST: &str = "127.0.0.1";
const DEFAULT_CONSOLE_PORT: u16 = 5000;
const CONSOLE_TIMEOUT: Duration = Duration::from_millis(750);

// Renvoie toute la composante joignable par multi-sauts depuis le noeud courant.
pub(crate) fn connected_neighbors(app_node_id: &str) -> Result<Vec<String>> {
    let lepton_node = app_node_to_lepton_node(app_node_id)?;
    connected_neighbors_from(app_node_id, &lepton_node, direct_lepton_neighbors)
}

// Renvoie uniquement les voisins directs du noeud courant.
#[allow(dead_code)]
pub(crate) fn direct_neighbors(app_node_id: &str) -> Result<Vec<String>> {
    let lepton_node = app_node_to_lepton_node(app_node_id)?;
    direct_neighbors_from(app_node_id, &lepton_node, direct_lepton_neighbors)
}

#[allow(dead_code)]
fn direct_neighbors_from<F>(
    app_node_id: &str,
    lepton_node: &str,
    mut direct_neighbors: F,
) -> Result<Vec<String>>
where
    F: FnMut(&str) -> Result<Vec<String>>,
{
    let mut out = direct_neighbors(lepton_node)?
        .into_iter()
        .filter_map(|neighbor| lepton_node_to_app_node(&neighbor))
        .filter(|node| !node.eq_ignore_ascii_case(app_node_id))
        .collect::<Vec<_>>();

    out.sort_by(|a, b| app_node_sort_key(a).cmp(&app_node_sort_key(b)));
    out.dedup();
    Ok(out)
}

fn connected_neighbors_from<F>(
    app_node_id: &str,
    lepton_node: &str,
    mut direct_neighbors: F,
) -> Result<Vec<String>>
where
    F: FnMut(&str) -> Result<Vec<String>>,
{
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    let mut out = Vec::new();

    visited.insert(lepton_node.to_string());
    queue.push_back(lepton_node.to_string());

    while let Some(current) = queue.pop_front() {
        for neighbor in direct_neighbors(&current)? {
            if !visited.insert(neighbor.clone()) {
                continue;
            }
            if let Some(app_node) = lepton_node_to_app_node(&neighbor) {
                if !app_node.eq_ignore_ascii_case(app_node_id) {
                    out.push(app_node);
                }
                queue.push_back(neighbor);
            }
        }
    }

    out.sort_by(|a, b| app_node_sort_key(a).cmp(&app_node_sort_key(b)));
    Ok(out)
}

fn direct_lepton_neighbors(lepton_node: &str) -> Result<Vec<String>> {
    let reply = console_command(&format!("gne {lepton_node}"))?;
    Ok(parse_neighbors(&reply))
}

fn console_command(command: &str) -> Result<String> {
    let port = std::env::var("D3CS_LEPTON_CONSOLE_PORT")
        .ok()
        .and_then(|raw| raw.parse::<u16>().ok())
        .unwrap_or(DEFAULT_CONSOLE_PORT);
    let addr: SocketAddr = format!("{DEFAULT_CONSOLE_HOST}:{port}").parse()?;
    let mut stream = TcpStream::connect_timeout(&addr, CONSOLE_TIMEOUT)
        .with_context(|| format!("impossible de joindre la console Lepton sur {addr}"))?;
    stream.set_read_timeout(Some(CONSOLE_TIMEOUT))?;
    stream.set_write_timeout(Some(CONSOLE_TIMEOUT))?;
    writeln!(stream, "{command}")?;

    let mut reply = String::new();
    BufReader::new(stream).read_line(&mut reply)?;
    if reply.starts_with("ERR ") {
        return Err(anyhow!(reply.trim().to_string()));
    }
    Ok(reply.trim().trim_end_matches('.').to_string())
}

fn parse_neighbors(reply: &str) -> Vec<String> {
    let trimmed = reply
        .trim()
        .trim_start_matches('[')
        .trim_start_matches('{')
        .trim_end_matches(']')
        .trim_end_matches('}');
    if trimmed.is_empty() || trimmed == "null" {
        return Vec::new();
    }
    trimmed
        .split(',')
        .map(str::trim)
        .filter(|node| !node.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn app_node_to_lepton_node(app_node_id: &str) -> Result<String> {
    if app_node_id.eq_ignore_ascii_case("Authority") {
        return Ok("N00".to_string());
    }
    if let Some(rest) = app_node_id.to_ascii_uppercase().strip_prefix('U') {
        let idx = rest
            .parse::<u16>()
            .with_context(|| format!("identifiant de noeud invalide pour Lepton: {app_node_id}"))?;
        return Ok(format!("N{idx:02}"));
    }
    Err(anyhow!(
        "identifiant de noeud inconnu pour Lepton: {app_node_id}"
    ))
}

fn lepton_node_to_app_node(lepton_node: &str) -> Option<String> {
    if lepton_node.eq_ignore_ascii_case("N00") {
        return Some("Authority".to_string());
    }
    let rest = lepton_node.strip_prefix('N')?;
    let idx = rest.parse::<u16>().ok()?;
    if (1..=9).contains(&idx) {
        return Some(format!("U{idx}"));
    }
    None
}

fn app_node_sort_key(node: &str) -> (u8, u16, String) {
    if node.eq_ignore_ascii_case("Authority") {
        return (0, 0, String::new());
    }
    let suffix = node
        .to_ascii_uppercase()
        .strip_prefix('U')
        .and_then(|rest| rest.parse::<u16>().ok())
        .unwrap_or(u16::MAX);
    (1, suffix, node.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connected_neighbors_walks_multi_hop_component() {
        let neighbors = connected_neighbors_from("U1", "N01", |node| {
            Ok(match node {
                "N01" => vec!["N05".to_string()],
                "N05" => vec!["N01".to_string(), "N09".to_string()],
                "N09" => vec!["N05".to_string(), "N00".to_string()],
                "N00" => vec!["N09".to_string()],
                _ => Vec::new(),
            })
        })
        .unwrap();

        assert_eq!(
            neighbors,
            vec!["Authority".to_string(), "U5".to_string(), "U9".to_string()]
        );
    }

    #[test]
    fn direct_neighbors_keeps_only_first_hop() {
        let neighbors = direct_neighbors_from("U1", "N01", |node| {
            Ok(match node {
                "N01" => vec!["N05".to_string()],
                "N05" => vec!["N01".to_string(), "N09".to_string()],
                _ => Vec::new(),
            })
        })
        .unwrap();

        assert_eq!(neighbors, vec!["U5".to_string()]);
    }
}
