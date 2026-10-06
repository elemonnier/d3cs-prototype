use std::{collections::HashMap,fs,path::Path,sync::{Arc,Mutex}};
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

fn serialized_size<T:serde::Serialize>(value:&T)->anyhow::Result<usize>{Ok(serde_json::to_string(value)?.as_bytes().len())}

fn build_arl(entries:usize)->crypto::RevocationList{
 crypto::RevocationList{version:1,items:(0..entries).map(|i|crypto::RevocationEntry{attribute_type:"mission".to_string(),attribute_value:format!("M{i}")}).collect()}
}

fn main()->anyhow::Result<()>{
 let results=Path::new("results");
 fs::create_dir_all(results)?;

 let(attrs_pp,attrs_msk)=crypto::cpabe::setup()?;
 let(abs_params,abs_msk)=crypto::abs::setup()?;
 let attrs=vec!["FR-DR".to_string(),"M1".to_string()];
 let(pska,_psks)=crypto::cpabe::keygen(&attrs_pp,&attrs_msk,&attrs)?;
 let arl_reference=build_arl(1);

 let cpabe_size=serialized_size(&attrs_pp)?;
 let abs_size=serialized_size(&abs_params)?;
 let pska_size=serialized_size(&pska)?;
 let arl_size=serialized_size(&arl_reference)?;
 let fixed_state=cpabe_size+abs_size+pska_size;

 let mut components=String::from("component,description,serialized_size_bytes\n");
 components.push_str(&format!("CPABE_PUBLIC_PARAMETERS,tm_dir/pp.bin,{cpabe_size}\n"));
 components.push_str(&format!("ABS_PUBLIC_PARAMETERS,tm_dir/params.bin,{abs_size}\n"));
 components.push_str(&format!("PSKA_u1,tm_dir/nodes/u1/pskau1.bin,{pska_size}\n"));
 components.push_str(&format!("ARL_REFERENCE_1_ENTRY,tm_dir/nodes/<tm>/arl.json,{arl_size}\n"));
 fs::write(results.join("tm_storage_components.csv"),components)?;

 let mut scalability=String::from("arl_entries,fixed_state_size_bytes,arl_size_bytes,total_tm_state_size_bytes\n");
 let mut summary=String::from("configuration,total_tm_state_size_bytes,arl_share_percent\n");
 for entries in [0usize,1,10,50,100,500,1000]{
  let value=build_arl(entries);
  let arl_size=serialized_size(&value)?;
  let total=fixed_state+arl_size;
  scalability.push_str(&format!("{entries},{fixed_state},{arl_size},{total}\n"));
  let share=100.0*arl_size as f64/total as f64;
  summary.push_str(&format!("ARL_{entries},{total},{share:.6}\n"));
 }
 fs::write(results.join("tm_storage_scalability.csv"),scalability)?;
 fs::write(results.join("tm_storage_summary.csv"),summary)?;
 let _=abs_msk;
 Ok(())
}
