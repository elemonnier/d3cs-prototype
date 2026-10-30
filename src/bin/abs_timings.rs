use std::{fs,path::Path,time::Instant};
use anyhow::{Context,Result};
use serde::{Deserialize,Serialize};

#[derive(Clone,Serialize,Deserialize)]
pub struct DocumentLabel{pub classification:String,pub mission:String}

#[path="../crypto/abs.rs"]
mod abs;
#[path="../crypto/cpabe.rs"]
mod cpabe;

const DEFAULT_WARMUPS:usize=100;
const DEFAULT_MEASUREMENTS:usize=500;

struct Samples{operation:&'static str,times_us:Vec<u128>}

fn reps(kind:&str,default:usize)->Result<usize>{
 let key=match kind{"warmup"=>"D3CS_ABS_WARMUPS","measure"=>"D3CS_ABS_MEASUREMENTS",_=>unreachable!()};
 Ok(std::env::var(key).map(|v|v.parse()).unwrap_or(Ok(default))?)
}

fn record<F:FnMut()->Result<()>>(operation:&'static str,warmups:usize,measurements:usize,mut f:F)->Result<Samples>{
 for _ in 0..warmups{f()?}
 let mut times_us=Vec::with_capacity(measurements);
 for _ in 0..measurements{let started=Instant::now();f()?;times_us.push(started.elapsed().as_micros())}
 Ok(Samples{operation,times_us})
}

fn mean(values:&[u128])->f64{values.iter().map(|x|*x as f64).sum::<f64>()/values.len()as f64}
fn stddev(values:&[u128],average:f64)->f64{(values.iter().map(|x|{let d=*x as f64-average;d*d}).sum::<f64>()/values.len()as f64).sqrt()}
fn median(values:&[u128])->f64{let mut sorted=values.to_vec();sorted.sort_unstable();let middle=sorted.len()/2;if sorted.len()%2==0{(sorted[middle-1]+sorted[middle])as f64/2.0}else{sorted[middle]as f64}}
fn json_size<T:serde::Serialize>(value:&T)->Result<usize>{Ok(serde_json::to_vec(value)?.len())}

fn main()->Result<()>{
 let warmups=reps("warmup",DEFAULT_WARMUPS)?;
 let measurements=reps("measure",DEFAULT_MEASUREMENTS)?;
 anyhow::ensure!(measurements>0,"D3CS_ABS_MEASUREMENTS must be positive");

 let attr="FR-DR";
 let short_message=b"test";
 let label=DocumentLabel{classification:"FR-DR".to_string(),mission:"M1".to_string()};

 let setup=record("setup",warmups,measurements,||{abs::setup()?;Ok(())})?;
 let(params,msk)=abs::setup().context("ABS setup preparation")?;

 let extract=record("extract",warmups,measurements,||{abs::extract(&params,&msk,attr)?;Ok(())})?;
 let user_key=abs::extract(&params,&msk,attr).context("ABS extract preparation")?;

 let sign=record("sign",warmups,measurements,||{abs::sign(&params,&user_key,short_message)?;Ok(())})?;
 let signature=abs::sign(&params,&user_key,short_message).context("short-message signature preparation")?;
 anyhow::ensure!(abs::verify_with_attr(&params,&signature,short_message,attr)?,"short-message signature failed verification");
 let verify=record("verify",warmups,measurements,||{abs::verify_with_attr(&params,&signature,short_message,attr)?;Ok(())})?;

 let(cpabe_params,_cpabe_msk)=cpabe::setup().context("CP-ABE setup for ciphertext scenario")?;
 let ciphertext=cpabe::encrypt(&cpabe_params,&label,"test").context("CP-ABE ciphertext generation")?;
 let ciphertext_message=serde_json::to_string(&ciphertext).context("CP-ABE ciphertext serialization")?.into_bytes();
 anyhow::ensure!(ciphertext_message.len()>1000,"unexpectedly small serialized CP-ABE ciphertext");
 let ciphertext_signature=abs::sign(&params,&user_key,&ciphertext_message).context("ciphertext signature preparation")?;
 anyhow::ensure!(abs::verify_with_attr(&params,&ciphertext_signature,&ciphertext_message,attr)?,"ciphertext signature failed verification");

 let ciphertext_sign=record("sign",warmups,measurements,||{abs::sign(&params,&user_key,&ciphertext_message)?;Ok(())})?;
 let ciphertext_verify=record("verify",warmups,measurements,||{abs::verify_with_attr(&params,&ciphertext_signature,&ciphertext_message,attr)?;Ok(())})?;

 let samples=vec![setup,extract,sign,verify];
 let results=Path::new("results");
 fs::create_dir_all(results)?;

 let mut raw=String::from("operation,iteration,time_us
");
 for sample in &samples{for(index,time)in sample.times_us.iter().enumerate(){raw.push_str(&format!("{},{},{}\n",sample.operation,index+1,time));}}
 fs::write(results.join("abs_timings.csv"),raw)?;

 let mut summary=String::from("operation,n,mean_us,stddev_us,median_us,min_us,max_us
");
 println!("operation,n,mean_us,stddev_us,median_us,min_us,max_us");
 for sample in &samples{
  let average=mean(&sample.times_us);
  let line=format!("{},{},{:.3},{:.3},{:.3},{},{}\n",sample.operation,sample.times_us.len(),average,stddev(&sample.times_us,average),median(&sample.times_us),sample.times_us.iter().min().unwrap(),sample.times_us.iter().max().unwrap());
  print!("{line}");
  summary.push_str(&line);
 }
 fs::write(results.join("abs_timings_summary.csv"),summary)?;

 let sizes=[
  ("public_parameters",json_size(&params)?),
  ("master_secret_key",json_size(&msk)?),
  ("user_private_key",json_size(&user_key)?),
  ("signature",json_size(&signature)?),
 ];
 let mut sizes_csv=String::from("object,size_bytes
");
 for(object,size)in sizes{sizes_csv.push_str(&format!("{object},{size}
"));}
 fs::write(results.join("abs_sizes.csv"),sizes_csv)?;

 let mut ciphertext_raw=String::from("operation,iteration,time_us
");
 for sample in [&ciphertext_sign,&ciphertext_verify]{for(index,time)in sample.times_us.iter().enumerate(){ciphertext_raw.push_str(&format!("{},{},{}\n",sample.operation,index+1,time));}}
 fs::write(results.join("abs_ciphertext_timings.csv"),ciphertext_raw)?;

 let mut ciphertext_summary=String::from("operation,n,mean_us,stddev_us,median_us,min_us,max_us
");
 println!("ciphertext_input_size_bytes={}",ciphertext_message.len());
 println!("signature_size_bytes={}",json_size(&ciphertext_signature)?);
 println!("operation,n,mean_us,stddev_us,median_us,min_us,max_us");
 for sample in [&ciphertext_sign,&ciphertext_verify]{
  let average=mean(&sample.times_us);
  let line=format!("{},{},{:.3},{:.3},{:.3},{},{}\n",sample.operation,sample.times_us.len(),average,stddev(&sample.times_us,average),median(&sample.times_us),sample.times_us.iter().min().unwrap(),sample.times_us.iter().max().unwrap());
  print!("{line}");
  ciphertext_summary.push_str(&line);
 }
 fs::write(results.join("abs_ciphertext_timings_summary.csv"),ciphertext_summary)?;

 let ciphertext_size=ciphertext_message.len();
 let signature_size=json_size(&ciphertext_signature)?;
 let mut ciphertext_sizes=String::from("object,size_bytes
");
 ciphertext_sizes.push_str(&format!("ciphertext_input_size_bytes,{ciphertext_size}
"));
 ciphertext_sizes.push_str(&format!("signature_size_bytes,{signature_size}
"));
 ciphertext_sizes.push_str(&format!("ciphertext_plus_signature_size_bytes,{}
",ciphertext_size+signature_size));
 fs::write(results.join("abs_ciphertext_sizes.csv"),ciphertext_sizes)?;

 Ok(())
}
