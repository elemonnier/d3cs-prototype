use std::{collections::HashMap,fs,path::Path,sync::{Arc,Mutex}};
use anyhow::{Context,Result};
use serde::{Deserialize,Serialize};

#[derive(Clone,Serialize,Deserialize)]
pub struct Clearance{pub classification:String,pub mission:String}
#[derive(Clone)]
pub struct UserRecord{pub password:String,pub clearance:Clearance,pub is_authority_user:bool}
#[derive(Clone,Serialize,Deserialize)]
pub struct PendingRevocation{pub id:u64,pub requester:String,pub missions:Vec<String>}
pub struct UserDb{pub users:HashMap<String,UserRecord>}
#[derive(Clone,Copy,PartialEq,Eq)]
pub enum RunMode{Local,Network}
pub const AUTHORITY_LOGIN:&str="authority";
pub mod network{#[derive(Clone)]pub struct NetworkRuntime;}
pub struct AppState{
 pub host:String,pub port:u16,pub config_dir:String,pub users_dir:String,pub tm_dir:String,pub authority_dir:String,pub ihm_dir:String,pub mode:RunMode,pub user_db:Mutex<UserDb>,pub sessions:Mutex<HashMap<String,String>>,pub pending_revocations:Mutex<Vec<PendingRevocation>>,pub network_runtime:Mutex<Option<Arc<network::NetworkRuntime>>>
}

#[path="../crypto/mod.rs"]
mod crypto;
#[path="../network/packets.rs"]
mod packets;

use packets::{D3csFrame,D3csRequest};

fn frame_size(src:&str,dst:&str,request:D3csRequest,args:Vec<String>,secured:bool)->Result<usize>{
 let frame=D3csFrame::new(src,dst,request,args).with_secured(secured);
 let wire=frame.to_transport_wire();
 let parsed=D3csFrame::from_wire(&wire).context("generated frame did not round-trip")?;
 anyhow::ensure!(parsed.request==frame.request&&parsed.args==frame.args&&parsed.secured==frame.secured,"generated frame changed during serialization");
 Ok(wire.as_bytes().len())
}

fn json_bytes<T:serde::Serialize>(value:&T)->Result<Vec<u8>>{Ok(serde_json::to_vec(value)?)}

fn arl(entries:usize)->crypto::RevocationList{
 crypto::RevocationList{version:1,items:(0..entries).map(|i|crypto::RevocationEntry{attribute_type:"mission".to_string(),attribute_value:format!("M{i}")}).collect()}
}

fn revocation_request_key(requester:&str,missions:&[String],request_id:&str)->String{
 format!("{request_id}|{requester}|{}",missions.join(","))
}

fn main()->Result<()>{
 let results=Path::new("results");
 fs::create_dir_all(results)?;

 let clearance=Clearance{classification:"FR-DR".to_string(),mission:"M1".to_string()};
 let clearance_s=serde_json::to_string(&clearance)?;
 let attrs=vec!["FR-DR".to_string(),"M1".to_string()];
 let label=crypto::DocumentLabel{classification:"FR-DR".to_string(),mission:"M1".to_string()};

 let(abs_params,abs_msk)=crypto::abs::setup()?;
 let abs_user_key=crypto::abs::extract(&abs_params,&abs_msk,"FR-DR")?;
 let(cpabe_params,cpabe_msk)=crypto::cpabe::setup()?;
 let(cpabe_pska,cpabe_psks)=crypto::cpabe::keygen(&cpabe_params,&cpabe_msk,&attrs)?;
 let ciphertext=crypto::cpabe::encrypt(&cpabe_params,&label,"test")?;
 let ciphertext_s=serde_json::to_string(&ciphertext)?;
 let signature=crypto::abs::sign(&abs_params,&abs_user_key,ciphertext_s.as_bytes())?;
 anyhow::ensure!(crypto::abs::verify_with_attr(&abs_params,&signature,ciphertext_s.as_bytes(),"FR-DR")?,"CT_SHARE signature invalid");

 let pp_s=serde_json::to_string(&cpabe_params)?;
 let psks_s=serde_json::to_string(&cpabe_psks)?;
 let pska_s=serde_json::to_string(&cpabe_pska)?;
 let abs_params_s=serde_json::to_string(&abs_params)?;
 let abs_user_key_s=serde_json::to_string(&abs_user_key)?;
 let signature_s=serde_json::to_string(&signature)?;

 let mut message_rows=String::from("message_type,payload_description,serialized_size_bytes\n");
 let mut add=|name:&str,description:&str,size:usize|{message_rows.push_str(&format!("{name},{description},{size}\n"));};

 add("KEY_REQUEST","login+clearance+user_topic+tm_topic",frame_size("TM1","TM",D3csRequest::KeyRequest,vec!["u1".into(),clearance_s.clone(),"U1".into(),"TM1".into()],true)?);
 add("KEY_RESPONSE_USER_KEYGEN","login+PP+PSKS+ABS_user_key",frame_size("Authority","U1",D3csRequest::KeyResponse,vec!["USER_KEYGEN".into(),"u1".into(),pp_s.clone(),psks_s.clone(),abs_user_key_s.clone()],true)?);
 add("KEY_RESPONSE_TM_KEY","login+ABS_params+PSKA",frame_size("Authority","TM1",D3csRequest::KeyResponse,vec!["TM_KEY".into(),"u1".into(),abs_params_s.clone(),pska_s.clone()],true)?);
 add("DELEGATE_OFFER","login+clearance+user_topic+tm_topic",frame_size("TM1","TM2",D3csRequest::DelegateAccept,vec!["u2".into(),clearance_s.clone(),"U2".into(),"TM2".into()],true)?);
 add("DELEGATE_ACCEPT","login+clearance+user_topic+tm_topic",frame_size("TM2","TM1",D3csRequest::AskDelegation,vec!["u2".into(),clearance_s.clone(),"U2".into(),"TM2".into()],true)?);
 let missions=vec!["M1".to_string()];
 add("ASK_REVOCATION","requester+missions+request_key",frame_size("TM1","TM",D3csRequest::AskRevocation,vec!["u1".into(),serde_json::to_string(&missions)?,revocation_request_key("u1",&missions,"1")],true)?);
 add("CT_SHARE","document_id+ciphertext+ABS_signature",frame_size("TM1","TM",D3csRequest::CtShare,vec!["1".into(),ciphertext_s.clone(),signature_s.clone()],false)?);
 let arl_one=arl(1);
 add("ARL_UPDATE","serialized_revocation_list",frame_size("Authority","TM",D3csRequest::ArlUpdate,vec![serde_json::to_string(&arl_one)?],true)?);
 fs::write(results.join("network_message_sizes.csv"),message_rows)?;

 let mut arl_csv=String::from("arl_entries,arl_serialized_size_bytes,arl_update_serialized_size_bytes\n");
 for count in [0usize,1,10,50,100,500,1000]{
  let value=arl(count);
  let serialized=serde_json::to_vec(&value)?;
  let update=frame_size("Authority","TM",D3csRequest::ArlUpdate,vec![String::from_utf8(serialized.clone())?],true)?;
  arl_csv.push_str(&format!("{count},{},{}\n",serialized.len(),update));
 }
 fs::write(results.join("arl_scalability.csv"),arl_csv)?;

 let mut ct_csv=String::from("plaintext_size_bytes,ciphertext_size_bytes,ct_share_serialized_size_bytes\n");
 for plaintext_size in [4usize,1024,10240,102400,1048576]{
  let message="A".repeat(plaintext_size);
  let ct=crypto::cpabe::encrypt(&cpabe_params,&label,&message)?;
  let ct_s=serde_json::to_string(&ct)?;
  let sig=crypto::abs::sign(&abs_params,&abs_user_key,ct_s.as_bytes())?;
  let sig_s=serde_json::to_string(&sig)?;
  anyhow::ensure!(crypto::abs::verify_with_attr(&abs_params,&sig,ct_s.as_bytes(),"FR-DR")?,"scalability CT_SHARE signature invalid");
  let size=frame_size("TM1","TM",D3csRequest::CtShare,vec!["1".into(),ct_s.clone(),sig_s],false)?;
  ct_csv.push_str(&format!("{plaintext_size},{},{}\n",ct_s.as_bytes().len(),size));
 }
 fs::write(results.join("ct_share_scalability.csv"),ct_csv)?;

 let _=json_bytes(&abs_msk)?;
 Ok(())
}
