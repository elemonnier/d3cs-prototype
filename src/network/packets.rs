// définition de tous les messages réseau, définis dans specs/

use anyhow::{anyhow, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};

pub const D3CS_PROTOCOL: &str = "D3CS";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum D3csRequest {
    KeyRequest,
    DelegateAccept,
    AskDelegation,
    AskRevocation,
    KeyResponse,
    CtShare,
    Revoke,
    ArlUpdate,
    Synchronize,
    PskaSync,
    Unknown(String),
}

// définition des messages réseau

impl D3csRequest {
    pub fn as_str(&self) -> &str {
        match self {
            D3csRequest::KeyRequest => "KEY_REQUEST",
            D3csRequest::DelegateAccept => "DELEGATE_ACCEPT",
            D3csRequest::AskDelegation => "ASK_DELEGATION",
            D3csRequest::AskRevocation => "ASK_REVOCATION",
            D3csRequest::KeyResponse => "KEY_RESPONSE",
            D3csRequest::CtShare => "CT_SHARE",
            D3csRequest::Revoke => "REVOKE",
            D3csRequest::ArlUpdate => "ARL_UPDATE",
            D3csRequest::Synchronize => "SYNCHRONIZE",
            D3csRequest::PskaSync => "PSKA_SYNC",
            D3csRequest::Unknown(s) => s.as_str(),
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "KEY_REQUEST" => D3csRequest::KeyRequest,
            "DELEGATE_ACCEPT" => D3csRequest::DelegateAccept,
            "ASK_DELEGATION" => D3csRequest::AskDelegation,
            "ASK_REVOCATION" => D3csRequest::AskRevocation,
            "KEY_RESPONSE" => D3csRequest::KeyResponse,
            "CT_SHARE" => D3csRequest::CtShare,
            "REVOKE" => D3csRequest::Revoke,
            "ARL_UPDATE" => D3csRequest::ArlUpdate,
            "SYNCHRONIZE" => D3csRequest::Synchronize,
            "PSKA_SYNC" => D3csRequest::PskaSync,
            other => D3csRequest::Unknown(other.to_string()),
        }
    }
}

// définition du contenu d'une trame réseau

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct D3csFrame {
    pub protocol: String,
    pub src: String,
    pub dst: String,
    pub request: D3csRequest,
    pub args: Vec<String>,
    pub secured: bool,
}

// méthodes associées à une trame
// new -> création de trame
// with_secured -> ajout d'une sécurisation supplémentaire (factice) lors de la création de clés (support TLS)
// to_wire -> permet de convertir une trame en texte de la forme : D3CS|U1|authority...
// to_transport_wire -> forme finale de la trame avant de la transférer sur le réseau (ajout TLS ou non)
// from_wire -> permet de désencapsuler la trame selon son contenu

impl D3csFrame {
    pub fn new(src: &str, dst: &str, request: D3csRequest, args: Vec<String>) -> Self {
        Self {
            protocol: D3CS_PROTOCOL.to_string(),
            src: src.to_string(),
            dst: dst.to_string(),
            request,
            args,
            secured: false,
        }
    }

    pub fn with_secured(mut self, secured: bool) -> Self {
        self.secured = secured;
        self
    }

    pub fn to_wire(&self) -> String {
        let mut parts = vec![
            self.protocol.clone(),
            self.src.clone(),
            self.dst.clone(),
            self.request.as_str().to_string(),
        ];
        parts.extend(self.args.iter().map(|a| encode_arg(a)));
        parts.join("|")
    }

    pub fn to_transport_wire(&self) -> String {
        let wire = self.to_wire();
        if self.secured {
            format!("TLS({wire})")
        } else {
            wire
        }
    }

    pub fn from_wire(raw: &str) -> Result<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(anyhow!("Empty frame"));
        }

        let (secured, inner) = if trimmed.starts_with("TLS(") && trimmed.ends_with(')') {
            (true, &trimmed[4..trimmed.len() - 1])
        } else {
            (false, trimmed)
        };

        let parts: Vec<&str> = inner.split('|').collect();
        if parts.len() < 4 {
            return Err(anyhow!("Invalid frame format"));
        }
        if parts[0] != D3CS_PROTOCOL {
            return Err(anyhow!("Invalid protocol"));
        }

        let args = parts[4..]
            .iter()
            .map(|a| decode_arg(a))
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            protocol: parts[0].to_string(),
            src: parts[1].to_string(),
            dst: parts[2].to_string(),
            request: D3csRequest::from_str(parts[3]),
            args,
            secured,
        })
    }
}

// permet d'encoder en base 64 les arguments en fin de trame pour ne pas qu'ils soient considérés
// comme des arguments supplémentaires (e.g. mission|M1 correspond au dernier argument)

fn encode_arg(value: &str) -> String {
    if value.contains('|') || value.contains('\n') || value.contains('\r') {
        let encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(value.as_bytes());
        format!("b64:{encoded}")
    } else {
        value.to_string()
    }
}

// même chose mais pour le décodage

fn decode_arg(value: &str) -> Result<String> {
    if let Some(rest) = value.strip_prefix("b64:") {
        let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(rest)
            .map_err(|_| anyhow!("Invalid frame argument encoding"))?;
        String::from_utf8(bytes).map_err(|_| anyhow!("Invalid UTF-8 frame argument"))
    } else {
        Ok(value.to_string())
    }
}
