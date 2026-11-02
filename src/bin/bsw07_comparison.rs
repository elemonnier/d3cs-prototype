//! Comparative local benchmark for the D3CS PM23/LK10 workflow and BSW07.
//!
//! The benchmark is intentionally independent from the application workflows.
//! It prepares valid cryptographic objects before timing and never measures
//! network communication, file I/O, or setup of the other operation.

use std::collections::BTreeMap;
use std::fs;
use std::hint::black_box;
use std::path::Path;
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct DocumentLabel {
    pub classification: String,
    pub mission: String,
}

#[path = "../crypto/abs.rs"]
mod abs;
#[path = "../crypto/bsw07.rs"]
mod bsw07;
#[path = "../crypto/cpabe.rs"]
mod cpabe;

const OUTPUT_DIR: &str = "results/bsw07_comparison";
const CONTROLLED_OUTPUT_DIR: &str = "results/bsw07_comparison_controlled";
const DEFAULT_WARMUPS: usize = 100;
const DEFAULT_MEASUREMENTS: usize = 500;
const DEFAULT_ORDER_BLOCK_SIZE: usize = 25;
const DEFAULT_MESSAGE_SIZES: &[usize] = &[4, 1024 * 1024];
const POLICY_LEAVES: usize = 2;
const ABS_ATTRIBUTE: &str = "FR-DR";
const CLASSIFICATION: &str = "FR-DR";
const MISSION: &str = "M1";

const D3CS_SCHEMA: &str = "D3CS_PM23_LK10";
const BSW07_SCHEMA: &str = "BSW07";

#[derive(Clone)]
struct BenchmarkConfig {
    warmups: usize,
    measurements: usize,
    message_sizes: Vec<usize>,
    order_seed: u64,
    order_block_size: usize,
    controlled: bool,
    campaign_id: usize,
}

#[derive(Clone)]
struct PreparedD3cs {
    pp: cpabe::PublicParamsV1,
    pska: cpabe::PskaV1,
    psks: cpabe::PsksV1,
    delegated_pska: cpabe::PskaV1,
    delegated_psks: cpabe::PsksV1,
    ciphertext: cpabe::CiphertextV1,
    intermediate: cpabe::IntermediateCiphertextV1,
    abs_params: abs::AbsParamsV1,
    abs_user_key: abs::AbsUserKeyV1,
    signed_message: Vec<u8>,
    signature: abs::AbsSignatureV1,
    message: String,
    label: DocumentLabel,
}

#[derive(Clone)]
struct PreparedBsw07 {
    pp: bsw07::Bsw07PublicParams,
    sk: bsw07::Bsw07SecretKey,
    delegated_sk: bsw07::Bsw07SecretKey,
    ciphertext: bsw07::Bsw07Ciphertext,
    message: String,
    label: bsw07::Bsw07Label,
}

#[derive(Clone)]
struct Sample {
    schema: String,
    operation: String,
    message_size: usize,
    user_attributes: usize,
    delegated_attributes: usize,
    policy_leaves: usize,
    durations_ns: Vec<u128>,
}

#[derive(Clone)]
struct ErrorRow {
    schema: String,
    operation: String,
    message_size: usize,
    iteration: usize,
    phase: String,
    error: String,
}

struct Campaign {
    samples: Vec<Sample>,
    errors: Vec<ErrorRow>,
}

#[derive(Serialize)]
struct Metadata {
    benchmark: &'static str,
    timestamp_unix_seconds: u64,
    git_commit: String,
    git_worktree_state: String,
    git_status_porcelain: String,
    rustc: String,
    dependencies: String,
    operating_system: &'static str,
    architecture: &'static str,
    processor: String,
    build_mode: &'static str,
    execution_mode: &'static str,
    campaign_id: usize,
    order_seed: u64,
    order_block_size: usize,
    order_strategy: &'static str,
    warmups: usize,
    measurements: usize,
    duration_unit: &'static str,
    policy: &'static str,
    policy_leaves: usize,
    user_attributes: Vec<String>,
    delegated_attributes: Vec<String>,
    message_sizes_bytes: Vec<usize>,
    hybrid_cipher: &'static str,
    d3cs_cpabe_version: &'static str,
    d3cs_hash_to_curve: &'static str,
    d3cs_hash_domain: &'static str,
    bsw07_format_version: &'static str,
    bsw07_hash_to_curve: &'static str,
    bsw07_hash_domain: &'static str,
    abs_hash_domains: [&'static str; 2],
    d3cs_system_ids: BTreeMap<String, String>,
    bsw07_system_ids: BTreeMap<String, String>,
    note: &'static str,
}

#[derive(Clone)]
struct SizeRow {
    schema: String,
    object: String,
    representation: String,
    message_size: usize,
    user_attributes: usize,
    delegated_attributes: usize,
    policy_leaves: usize,
    bytes: usize,
}

fn env_usize(name: &str, default: usize) -> Result<usize> {
    match std::env::var(name) {
        Ok(value) => value
            .parse::<usize>()
            .with_context(|| format!("invalid {name} value {value}")),
        Err(_) => Ok(default),
    }
}

fn env_u64(name: &str, default: u64) -> Result<u64> {
    match std::env::var(name) {
        Ok(value) => value
            .parse::<u64>()
            .with_context(|| format!("invalid {name} value {value}")),
        Err(_) => Ok(default),
    }
}

fn env_bool(name: &str, default: bool) -> Result<bool> {
    match std::env::var(name) {
        Ok(value) => match value.as_str() {
            "1" | "true" | "TRUE" | "yes" => Ok(true),
            "0" | "false" | "FALSE" | "no" => Ok(false),
            _ => Err(anyhow!("invalid {name} value {value}")),
        },
        Err(_) => Ok(default),
    }
}

fn config_from_environment() -> Result<BenchmarkConfig> {
    let warmups = env_usize("BSW07_COMPARISON_WARMUPS", DEFAULT_WARMUPS)?;
    let measurements = env_usize("BSW07_COMPARISON_MEASUREMENTS", DEFAULT_MEASUREMENTS)?;
    let order_block_size = env_usize(
        "BSW07_COMPARISON_ORDER_BLOCK_SIZE",
        DEFAULT_ORDER_BLOCK_SIZE,
    )?;
    anyhow::ensure!(order_block_size > 0, "order block size must be positive");
    anyhow::ensure!(measurements > 0, "measurements must be positive");
    let message_sizes = match std::env::var("BSW07_COMPARISON_MESSAGE_SIZES") {
        Ok(value) => value
            .split(',')
            .map(|item| {
                item.trim()
                    .parse::<usize>()
                    .with_context(|| format!("invalid message size {item}"))
            })
            .collect::<Result<Vec<_>>>()?,
        Err(_) => DEFAULT_MESSAGE_SIZES.to_vec(),
    };
    anyhow::ensure!(
        !message_sizes.is_empty(),
        "at least one message size is required"
    );
    Ok(BenchmarkConfig {
        warmups,
        measurements,
        message_sizes,
        order_seed: env_u64("BSW07_COMPARISON_ORDER_SEED", 0x6d_65_74_68_6f_64_31)?,
        order_block_size,
        controlled: env_bool("BSW07_COMPARISON_CONTROLLED", false)?,
        campaign_id: env_usize("BSW07_COMPARISON_CAMPAIGN_ID", 0)?,
    })
}

fn output_dir() -> String {
    std::env::var("BSW07_COMPARISON_OUTPUT_DIR").unwrap_or_else(|_| {
        if std::env::var_os("BSW07_COMPARISON_CONTROLLED").is_some() {
            CONTROLLED_OUTPUT_DIR.to_string()
        } else {
            OUTPUT_DIR.to_string()
        }
    })
}

fn csv_message_size(size: usize) -> String {
    if size == 0 {
        "NA".to_string()
    } else {
        size.to_string()
    }
}

fn csv_escape(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn command_output(command: &str, args: &[&str]) -> String {
    Command::new(command)
        .args(args)
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unavailable".to_string())
}

fn git_status() -> String {
    command_output("git", &["status", "--porcelain"])
}

fn message_for_size(size: usize) -> String {
    if size == 4 {
        "test".to_string()
    } else {
        "A".repeat(size)
    }
}

fn label() -> DocumentLabel {
    DocumentLabel {
        classification: CLASSIFICATION.to_string(),
        mission: MISSION.to_string(),
    }
}

fn bsw_label() -> bsw07::Bsw07Label {
    bsw07::Bsw07Label {
        classification: CLASSIFICATION.to_string(),
        mission: MISSION.to_string(),
    }
}

fn user_attributes() -> Vec<String> {
    vec![
        CLASSIFICATION.to_string(),
        MISSION.to_string(),
        "EXTRA".to_string(),
    ]
}

fn delegated_attributes() -> Vec<String> {
    vec![CLASSIFICATION.to_string(), MISSION.to_string()]
}

fn decoded_size(value: &str) -> usize {
    STANDARD_NO_PAD
        .decode(value)
        .map(|bytes| bytes.len())
        .unwrap_or(0)
}

fn json_size<T: Serialize>(value: &T) -> Result<usize> {
    Ok(serde_json::to_vec(value)?.len())
}

fn d3cs_pp_raw_size(pp: &cpabe::PublicParamsV1) -> usize {
    [&pp.g, &pp.g2, &pp.h, &pp.f, &pp.f2, &pp.y]
        .into_iter()
        .map(|value| decoded_size(value))
        .sum()
}

fn d3cs_msk_raw_size(msk: &cpabe::MasterKeyV1) -> usize {
    decoded_size(&msk.alpha) + decoded_size(&msk.beta)
}

fn d3cs_pska_raw_size(pska: &cpabe::PskaV1) -> usize {
    decoded_size(&pska.d)
}

fn d3cs_psks_raw_size(psks: &cpabe::PsksV1) -> usize {
    psks.attrs
        .iter()
        .map(|item| decoded_size(&item.d) + decoded_size(&item.d_prime))
        .sum()
}

fn d3cs_tk_raw_size(tk: &cpabe::TkV1) -> usize {
    decoded_size(&tk.t)
}

fn d3cs_ct_raw_size(ct: &cpabe::CiphertextV1) -> usize {
    decoded_size(&ct.abe.c_tilde)
        + decoded_size(&ct.abe.c)
        + ct.abe
            .leafs
            .iter()
            .map(|leaf| decoded_size(&leaf.c_i) + decoded_size(&leaf.c_i_prime))
            .sum::<usize>()
        + decoded_size(&ct.sym.nonce)
        + decoded_size(&ct.sym.ciphertext)
}

fn d3cs_intermediate_raw_size(ct: &cpabe::IntermediateCiphertextV1) -> usize {
    decoded_size(&ct.abe.c_tilde)
        + decoded_size(&ct.abe.f)
        + ct.abe
            .leafs
            .iter()
            .map(|leaf| decoded_size(&leaf.c_i) + decoded_size(&leaf.c_i_prime))
            .sum::<usize>()
        + decoded_size(&ct.sym.nonce)
        + decoded_size(&ct.sym.ciphertext)
}

fn d3cs_signature_raw_size(signature: &abs::AbsSignatureV1) -> usize {
    decoded_size(&signature.r1) + decoded_size(&signature.r2) + decoded_size(&signature.r3)
}

fn bsw_pp_raw_size(pp: &bsw07::Bsw07PublicParams) -> usize {
    [&pp.g, &pp.g2, &pp.h, &pp.f2, &pp.y]
        .into_iter()
        .map(|value| decoded_size(value))
        .sum()
}

fn bsw_msk_raw_size(msk: &bsw07::Bsw07MasterKey) -> usize {
    decoded_size(&msk.beta) + decoded_size(&msk.g2_alpha)
}

fn bsw_sk_raw_size(sk: &bsw07::Bsw07SecretKey) -> usize {
    decoded_size(&sk.d)
        + sk.components
            .iter()
            .map(|component| decoded_size(&component.d_i) + decoded_size(&component.d_i_prime))
            .sum::<usize>()
}

fn bsw_ct_raw_size(ct: &bsw07::Bsw07Ciphertext) -> usize {
    decoded_size(&ct.c_tilde)
        + decoded_size(&ct.c)
        + ct.leaves
            .iter()
            .map(|leaf| decoded_size(&leaf.c_i) + decoded_size(&leaf.c_i_prime))
            .sum::<usize>()
        + decoded_size(&ct.nonce)
        + decoded_size(&ct.ciphertext)
}

#[allow(clippy::too_many_arguments)]
fn add_size(
    rows: &mut Vec<SizeRow>,
    schema: &str,
    object: &str,
    representation: &str,
    message_size: usize,
    user_attributes: usize,
    delegated_attributes: usize,
    bytes: usize,
) {
    rows.push(SizeRow {
        schema: schema.to_string(),
        object: object.to_string(),
        representation: representation.to_string(),
        message_size,
        user_attributes,
        delegated_attributes,
        policy_leaves: POLICY_LEAVES,
        bytes,
    });
}

fn prepare_d3cs(message: String) -> Result<(PreparedD3cs, cpabe::MasterKeyV1, cpabe::TkV1)> {
    let attrs = user_attributes();
    let delegated = delegated_attributes();
    let label = label();
    let (pp, msk) = cpabe::setup().context("D3CS setup preparation")?;
    let (pska, psks) = cpabe::keygen(&pp, &msk, &attrs).context("D3CS KeyGen preparation")?;
    let (delegated_psks, tk) =
        cpabe::delegate(&pp, &psks, &delegated).context("D3CS Delegate preparation")?;
    let delegated_pska = cpabe::tm_delegate(&pska, &tk).context("D3CS TM_Delegate preparation")?;
    let ciphertext = cpabe::encrypt(&pp, &label, &message).context("D3CS Encrypt preparation")?;
    let intermediate = cpabe::tm_decrypt(&pp, &ciphertext, &delegated_pska)
        .context("D3CS TM_Decrypt preparation")?;
    let plaintext =
        cpabe::decrypt(&pp, &intermediate, &delegated_psks).context("D3CS Decrypt preparation")?;
    anyhow::ensure!(
        plaintext == message,
        "D3CS preparation did not decrypt correctly"
    );

    let (abs_params, abs_msk) = abs::setup().context("ABS setup preparation")?;
    let abs_user_key =
        abs::extract(&abs_params, &abs_msk, ABS_ATTRIBUTE).context("ABS user-key preparation")?;
    let signed_message = serde_json::to_string(&ciphertext)
        .context("D3CS ciphertext serialization")?
        .into_bytes();
    let signature = abs::sign(&abs_params, &abs_user_key, &signed_message)
        .context("ABS signature preparation")?;
    anyhow::ensure!(
        abs::verify_with_attr(&abs_params, &signature, &signed_message, ABS_ATTRIBUTE)?,
        "ABS preparation verification failed"
    );

    Ok((
        PreparedD3cs {
            pp,
            pska,
            psks,
            delegated_pska,
            delegated_psks,
            ciphertext,
            intermediate,
            abs_params,
            abs_user_key,
            signed_message,
            signature,
            message,
            label,
        },
        msk,
        tk,
    ))
}

fn prepare_bsw07(message: String) -> Result<(PreparedBsw07, bsw07::Bsw07MasterKey)> {
    let attrs = user_attributes();
    let delegated = delegated_attributes();
    let label = bsw_label();
    let (pp, msk) = bsw07::setup().context("BSW07 setup preparation")?;
    let sk = bsw07::keygen(&pp, &msk, &attrs).context("BSW07 KeyGen preparation")?;
    let delegated_sk =
        bsw07::delegate(&pp, &sk, &delegated).context("BSW07 Delegate preparation")?;
    let ciphertext = bsw07::encrypt(&pp, &label, &message).context("BSW07 Encrypt preparation")?;
    let plaintext =
        bsw07::decrypt(&pp, &ciphertext, &delegated_sk).context("BSW07 Decrypt preparation")?;
    anyhow::ensure!(
        plaintext == message,
        "BSW07 preparation did not decrypt correctly"
    );
    Ok((
        PreparedBsw07 {
            pp,
            sk,
            delegated_sk,
            ciphertext,
            message,
            label,
        },
        msk,
    ))
}

#[allow(clippy::too_many_arguments)]
fn measure<F>(
    campaign: &mut Campaign,
    schema: &str,
    operation: &str,
    message_size: usize,
    user_attributes: usize,
    delegated_attributes: usize,
    warmups: usize,
    measurements: usize,
    mut operation_fn: F,
) where
    F: FnMut() -> Result<()>,
{
    for warmup in 1..=warmups {
        if let Err(error) = operation_fn() {
            campaign.errors.push(ErrorRow {
                schema: schema.to_string(),
                operation: operation.to_string(),
                message_size,
                iteration: warmup,
                phase: "warmup".to_string(),
                error: format!("{error:#}"),
            });
        }
    }

    let mut durations_ns = Vec::with_capacity(measurements);
    for iteration in 1..=measurements {
        let started = Instant::now();
        match operation_fn() {
            Ok(()) => durations_ns.push(started.elapsed().as_nanos()),
            Err(error) => campaign.errors.push(ErrorRow {
                schema: schema.to_string(),
                operation: operation.to_string(),
                message_size,
                iteration,
                phase: "measurement".to_string(),
                error: format!("{error:#}"),
            }),
        }
    }

    campaign.samples.push(Sample {
        schema: schema.to_string(),
        operation: operation.to_string(),
        message_size,
        user_attributes,
        delegated_attributes,
        policy_leaves: POLICY_LEAVES,
        durations_ns,
    });
}

fn shuffled_block_order(seed: u64, pair_id: u64, block_count: usize) -> Vec<bool> {
    let mut order = (0..block_count)
        .map(|index| index < block_count / 2)
        .collect::<Vec<_>>();
    let mut state = seed ^ pair_id.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    for index in (1..order.len()).rev() {
        state ^= state << 7;
        state ^= state >> 9;
        state ^= state << 8;
        let swap_index = (state as usize) % (index + 1);
        order.swap(index, swap_index);
    }
    order
}

fn run_timed_sample<F>(
    operation_fn: &mut F,
    sample: &mut Sample,
    errors: &mut Vec<ErrorRow>,
    iteration: usize,
) where
    F: FnMut() -> Result<()>,
{
    let started = Instant::now();
    match operation_fn() {
        Ok(()) => sample.durations_ns.push(started.elapsed().as_nanos()),
        Err(error) => errors.push(ErrorRow {
            schema: sample.schema.clone(),
            operation: sample.operation.clone(),
            message_size: sample.message_size,
            iteration,
            phase: "measurement".to_string(),
            error: format!("{error:#}"),
        }),
    }
}

#[allow(clippy::too_many_arguments)]
fn measure_pair<FD, FB>(
    campaign: &mut Campaign,
    d3cs_operation: &str,
    bsw_operation: &str,
    message_size: usize,
    user_attributes: usize,
    delegated_attributes: usize,
    warmups: usize,
    measurements: usize,
    block_size: usize,
    order_seed: u64,
    pair_id: u64,
    mut d3cs_fn: FD,
    mut bsw_fn: FB,
) where
    FD: FnMut() -> Result<()>,
    FB: FnMut() -> Result<()>,
{
    let mut d3cs_sample = Sample {
        schema: D3CS_SCHEMA.to_string(),
        operation: d3cs_operation.to_string(),
        message_size,
        user_attributes,
        delegated_attributes,
        policy_leaves: POLICY_LEAVES,
        durations_ns: Vec::with_capacity(measurements),
    };
    let mut bsw_sample = Sample {
        schema: BSW07_SCHEMA.to_string(),
        operation: bsw_operation.to_string(),
        message_size,
        user_attributes,
        delegated_attributes,
        policy_leaves: POLICY_LEAVES,
        durations_ns: Vec::with_capacity(measurements),
    };

    for warmup in 1..=warmups {
        if let Err(error) = d3cs_fn() {
            campaign.errors.push(ErrorRow {
                schema: D3CS_SCHEMA.to_string(),
                operation: d3cs_operation.to_string(),
                message_size,
                iteration: warmup,
                phase: "warmup".to_string(),
                error: format!("{error:#}"),
            });
        }
        if let Err(error) = bsw_fn() {
            campaign.errors.push(ErrorRow {
                schema: BSW07_SCHEMA.to_string(),
                operation: bsw_operation.to_string(),
                message_size,
                iteration: warmup,
                phase: "warmup".to_string(),
                error: format!("{error:#}"),
            });
        }
    }

    let block_count = measurements.div_ceil(block_size);
    let order = shuffled_block_order(order_seed, pair_id, block_count);
    for (block, d3cs_first) in order.into_iter().enumerate() {
        let start = block * block_size;
        let count = (measurements - start).min(block_size);
        for iteration in 0..count {
            if d3cs_first {
                run_timed_sample(
                    &mut d3cs_fn,
                    &mut d3cs_sample,
                    &mut campaign.errors,
                    start + iteration + 1,
                );
                run_timed_sample(
                    &mut bsw_fn,
                    &mut bsw_sample,
                    &mut campaign.errors,
                    start + iteration + 1,
                );
            } else {
                run_timed_sample(
                    &mut bsw_fn,
                    &mut bsw_sample,
                    &mut campaign.errors,
                    start + iteration + 1,
                );
                run_timed_sample(
                    &mut d3cs_fn,
                    &mut d3cs_sample,
                    &mut campaign.errors,
                    start + iteration + 1,
                );
            }
        }
    }
    campaign.samples.push(d3cs_sample);
    campaign.samples.push(bsw_sample);
}

fn mean(values: &[u128]) -> f64 {
    values.iter().map(|value| *value as f64).sum::<f64>() / values.len() as f64
}

fn sample_stddev(values: &[u128], average: f64) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }
    let sum = values
        .iter()
        .map(|value| {
            let difference = *value as f64 - average;
            difference * difference
        })
        .sum::<f64>();
    (sum / (values.len() - 1) as f64).sqrt()
}

fn median(values: &[u128]) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let middle = sorted.len() / 2;
    if sorted.len().is_multiple_of(2) {
        (sorted[middle - 1] as f64 + sorted[middle] as f64) / 2.0
    } else {
        sorted[middle] as f64
    }
}

fn percentile(values: &[u128], numerator: usize, denominator: usize) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let rank = (sorted.len() * numerator).div_ceil(denominator).max(1);
    sorted[rank - 1] as f64
}

fn sample_key(sample: &Sample) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}",
        sample.schema,
        sample.operation,
        sample.message_size,
        sample.user_attributes,
        sample.delegated_attributes,
        sample.policy_leaves
    )
}

fn comparable_operation(schema: &str, operation: &str) -> Option<&'static str> {
    if schema != BSW07_SCHEMA {
        return None;
    }
    match operation {
        "Setup" => Some("Setup"),
        "KeyGen" => Some("KeyGen"),
        "Encrypt" => Some("Encrypt"),
        "Decrypt" => Some("TM_Decrypt+Decrypt"),
        "Delegate" => Some("Delegate+TM_Delegate"),
        _ => None,
    }
}

fn write_outputs(
    config: &BenchmarkConfig,
    campaign: &Campaign,
    sizes: &[SizeRow],
    metadata: &Metadata,
) -> Result<()> {
    let output_dir = output_dir();
    let output = Path::new(&output_dir);
    fs::create_dir_all(output)?;

    let mut raw = String::from(
        "schema,operation,iteration,message_size_bytes,user_attributes,delegated_attributes,policy_leaves,unit,duration,success\n",
    );
    for sample in &campaign.samples {
        for (index, duration) in sample.durations_ns.iter().enumerate() {
            raw.push_str(&format!(
                "{},{},{},{},{},{},{},nanoseconds,{},true\n",
                sample.schema,
                sample.operation,
                index + 1,
                csv_message_size(sample.message_size),
                sample.user_attributes,
                sample.delegated_attributes,
                sample.policy_leaves,
                duration
            ));
        }
    }
    for error in &campaign.errors {
        raw.push_str(&format!(
            "{},{},{},{},{},{},{},nanoseconds,,false\n",
            csv_escape(&error.schema),
            csv_escape(&error.operation),
            error.iteration,
            csv_message_size(error.message_size),
            user_attributes().len(),
            delegated_attributes().len(),
            POLICY_LEAVES
        ));
    }
    fs::write(output.join("timings_raw.csv"), raw)?;

    let mut medians: BTreeMap<String, f64> = BTreeMap::new();
    for sample in &campaign.samples {
        if !sample.durations_ns.is_empty() {
            medians.insert(sample_key(sample), median(&sample.durations_ns));
        }
    }

    let mut summary = String::from(
        "schema,operation,message_size_bytes,user_attributes,delegated_attributes,policy_leaves,valid_samples,failed_samples,mean_ns,median_ns,stddev_ns,min_ns,max_ns,p95_ns,stddev_convention,percentile_convention,bsw07_over_d3cs_median_ratio\n",
    );
    for sample in &campaign.samples {
        let ratio = comparable_operation(&sample.schema, &sample.operation).and_then(|operation| {
            let d3cs = Sample {
                schema: D3CS_SCHEMA.to_string(),
                operation: operation.to_string(),
                message_size: sample.message_size,
                user_attributes: sample.user_attributes,
                delegated_attributes: sample.delegated_attributes,
                policy_leaves: sample.policy_leaves,
                durations_ns: Vec::new(),
            };
            medians
                .get(&sample_key(&d3cs))
                .map(|value| median(&sample.durations_ns) / value)
        });
        if sample.durations_ns.is_empty() {
            summary.push_str(&format!(
                "{},{},{},{},{},{},0,{},,,,,,,sample (n-1),nearest-rank ceil(0.95*n),\n",
                sample.schema,
                sample.operation,
                csv_message_size(sample.message_size),
                sample.user_attributes,
                sample.delegated_attributes,
                sample.policy_leaves,
                config.measurements
            ));
            continue;
        }
        let average = mean(&sample.durations_ns);
        let line = format!(
            "{},{},{},{},{},{},{},{},{:.3},{:.3},{:.3},{},{},{:.3},sample (n-1),nearest-rank ceil(0.95*n),{}\n",
            sample.schema,
            sample.operation,
            csv_message_size(sample.message_size),
            sample.user_attributes,
            sample.delegated_attributes,
            sample.policy_leaves,
            sample.durations_ns.len(),
            config.measurements.saturating_sub(sample.durations_ns.len()),
            average,
            median(&sample.durations_ns),
            sample_stddev(&sample.durations_ns, average),
            sample.durations_ns.iter().min().unwrap(),
            sample.durations_ns.iter().max().unwrap(),
            percentile(&sample.durations_ns, 95, 100),
            ratio.map(|value| format!("{value:.6}")).unwrap_or_default()
        );
        summary.push_str(&line);
    }
    fs::write(output.join("timings_summary.csv"), summary)?;

    let mut sizes_csv = String::from(
        "schema,object,representation,message_size_bytes,user_attributes,delegated_attributes,policy_leaves,bytes\n",
    );
    for row in sizes {
        sizes_csv.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            csv_escape(&row.schema),
            csv_escape(&row.object),
            csv_escape(&row.representation),
            csv_message_size(row.message_size),
            row.user_attributes,
            row.delegated_attributes,
            row.policy_leaves,
            row.bytes
        ));
    }
    fs::write(output.join("sizes.csv"), sizes_csv)?;

    let mut errors_csv =
        String::from("schema,operation,message_size_bytes,iteration,phase,error\n");
    for error in &campaign.errors {
        errors_csv.push_str(&format!(
            "{},{},{},{},{},{}\n",
            csv_escape(&error.schema),
            csv_escape(&error.operation),
            csv_message_size(error.message_size),
            error.iteration,
            error.phase,
            csv_escape(&error.error)
        ));
    }
    fs::write(output.join("errors.csv"), errors_csv)?;
    fs::write(
        output.join("metadata.json"),
        serde_json::to_vec_pretty(metadata)?,
    )?;
    Ok(())
}

fn add_d3cs_sizes(
    rows: &mut Vec<SizeRow>,
    prepared: &PreparedD3cs,
    msk: &cpabe::MasterKeyV1,
    tk: &cpabe::TkV1,
    message_size: usize,
) -> Result<()> {
    let user_count = user_attributes().len();
    let delegated_count = delegated_attributes().len();
    add_size(
        rows,
        D3CS_SCHEMA,
        "PP",
        "raw_crypto_elements",
        message_size,
        user_count,
        delegated_count,
        d3cs_pp_raw_size(&prepared.pp),
    );
    add_size(
        rows,
        D3CS_SCHEMA,
        "PP",
        "json_utf8",
        message_size,
        user_count,
        delegated_count,
        json_size(&prepared.pp)?,
    );
    add_size(
        rows,
        D3CS_SCHEMA,
        "MSK",
        "raw_crypto_elements",
        message_size,
        user_count,
        delegated_count,
        d3cs_msk_raw_size(msk),
    );
    add_size(
        rows,
        D3CS_SCHEMA,
        "MSK",
        "json_utf8",
        message_size,
        user_count,
        delegated_count,
        json_size(msk)?,
    );
    add_size(
        rows,
        D3CS_SCHEMA,
        "PSKA",
        "raw_crypto_elements",
        message_size,
        user_count,
        delegated_count,
        d3cs_pska_raw_size(&prepared.pska),
    );
    add_size(
        rows,
        D3CS_SCHEMA,
        "PSKA",
        "json_utf8",
        message_size,
        user_count,
        delegated_count,
        json_size(&prepared.pska)?,
    );
    add_size(
        rows,
        D3CS_SCHEMA,
        "PSKS",
        "raw_crypto_elements",
        message_size,
        user_count,
        delegated_count,
        d3cs_psks_raw_size(&prepared.psks),
    );
    add_size(
        rows,
        D3CS_SCHEMA,
        "PSKS",
        "json_utf8",
        message_size,
        user_count,
        delegated_count,
        json_size(&prepared.psks)?,
    );
    add_size(
        rows,
        D3CS_SCHEMA,
        "PSKA+PSKS",
        "raw_crypto_elements",
        message_size,
        user_count,
        delegated_count,
        d3cs_pska_raw_size(&prepared.pska) + d3cs_psks_raw_size(&prepared.psks),
    );
    add_size(
        rows,
        D3CS_SCHEMA,
        "PSKA+PSKS",
        "json_utf8_combined_tuple",
        message_size,
        user_count,
        delegated_count,
        json_size(&(&prepared.pska, &prepared.psks))?,
    );
    add_size(
        rows,
        D3CS_SCHEMA,
        "TK",
        "raw_crypto_elements",
        message_size,
        user_count,
        delegated_count,
        d3cs_tk_raw_size(tk),
    );
    add_size(
        rows,
        D3CS_SCHEMA,
        "TK",
        "json_utf8",
        message_size,
        user_count,
        delegated_count,
        json_size(tk)?,
    );
    add_size(
        rows,
        D3CS_SCHEMA,
        "ciphertext",
        "raw_crypto_elements_and_payload",
        message_size,
        user_count,
        delegated_count,
        d3cs_ct_raw_size(&prepared.ciphertext),
    );
    add_size(
        rows,
        D3CS_SCHEMA,
        "ciphertext",
        "json_utf8",
        message_size,
        user_count,
        delegated_count,
        json_size(&prepared.ciphertext)?,
    );
    add_size(
        rows,
        D3CS_SCHEMA,
        "signature_abs",
        "raw_crypto_elements",
        message_size,
        user_count,
        delegated_count,
        d3cs_signature_raw_size(&prepared.signature),
    );
    add_size(
        rows,
        D3CS_SCHEMA,
        "signature_abs",
        "json_utf8",
        message_size,
        user_count,
        delegated_count,
        json_size(&prepared.signature)?,
    );
    add_size(
        rows,
        D3CS_SCHEMA,
        "ciphertext+signature",
        "raw_crypto_elements_and_payload",
        message_size,
        user_count,
        delegated_count,
        d3cs_ct_raw_size(&prepared.ciphertext) + d3cs_signature_raw_size(&prepared.signature),
    );
    add_size(
        rows,
        D3CS_SCHEMA,
        "ciphertext+signature",
        "json_utf8_combined_tuple",
        message_size,
        user_count,
        delegated_count,
        json_size(&(&prepared.ciphertext, &prepared.signature))?,
    );
    add_size(
        rows,
        D3CS_SCHEMA,
        "ciphertext_intermediate",
        "raw_crypto_elements_and_payload",
        message_size,
        user_count,
        delegated_count,
        d3cs_intermediate_raw_size(&prepared.intermediate),
    );
    add_size(
        rows,
        D3CS_SCHEMA,
        "ciphertext_intermediate",
        "json_utf8",
        message_size,
        user_count,
        delegated_count,
        json_size(&prepared.intermediate)?,
    );
    Ok(())
}

fn add_bsw_sizes(
    rows: &mut Vec<SizeRow>,
    prepared: &PreparedBsw07,
    msk: &bsw07::Bsw07MasterKey,
    message_size: usize,
) -> Result<()> {
    let user_count = user_attributes().len();
    let delegated_count = delegated_attributes().len();
    add_size(
        rows,
        BSW07_SCHEMA,
        "PP",
        "raw_crypto_elements",
        message_size,
        user_count,
        delegated_count,
        bsw_pp_raw_size(&prepared.pp),
    );
    add_size(
        rows,
        BSW07_SCHEMA,
        "PP",
        "json_utf8",
        message_size,
        user_count,
        delegated_count,
        json_size(&prepared.pp)?,
    );
    add_size(
        rows,
        BSW07_SCHEMA,
        "MSK",
        "raw_crypto_elements",
        message_size,
        user_count,
        delegated_count,
        bsw_msk_raw_size(msk),
    );
    add_size(
        rows,
        BSW07_SCHEMA,
        "MSK",
        "json_utf8",
        message_size,
        user_count,
        delegated_count,
        json_size(msk)?,
    );
    add_size(
        rows,
        BSW07_SCHEMA,
        "user_key_complete",
        "raw_crypto_elements",
        message_size,
        user_count,
        delegated_count,
        bsw_sk_raw_size(&prepared.sk),
    );
    add_size(
        rows,
        BSW07_SCHEMA,
        "user_key_complete",
        "json_utf8",
        message_size,
        user_count,
        delegated_count,
        json_size(&prepared.sk)?,
    );
    add_size(
        rows,
        BSW07_SCHEMA,
        "delegated_key",
        "raw_crypto_elements",
        message_size,
        user_count,
        delegated_count,
        bsw_sk_raw_size(&prepared.delegated_sk),
    );
    add_size(
        rows,
        BSW07_SCHEMA,
        "delegated_key",
        "json_utf8",
        message_size,
        user_count,
        delegated_count,
        json_size(&prepared.delegated_sk)?,
    );
    add_size(
        rows,
        BSW07_SCHEMA,
        "ciphertext",
        "raw_crypto_elements_and_payload",
        message_size,
        user_count,
        delegated_count,
        bsw_ct_raw_size(&prepared.ciphertext),
    );
    add_size(
        rows,
        BSW07_SCHEMA,
        "ciphertext",
        "json_utf8",
        message_size,
        user_count,
        delegated_count,
        json_size(&prepared.ciphertext)?,
    );
    Ok(())
}

fn run_core_measurements(
    campaign: &mut Campaign,
    config: &BenchmarkConfig,
    d3cs: &PreparedD3cs,
    d3cs_msk: &cpabe::MasterKeyV1,
    bsw: &PreparedBsw07,
    bsw_msk: &bsw07::Bsw07MasterKey,
) {
    let user_count = user_attributes().len();
    let delegated_count = delegated_attributes().len();
    let size = 4;
    measure(
        campaign,
        D3CS_SCHEMA,
        "Setup",
        size,
        user_count,
        delegated_count,
        config.warmups,
        config.measurements,
        || {
            black_box(cpabe::setup()?);
            Ok(())
        },
    );
    measure(
        campaign,
        BSW07_SCHEMA,
        "Setup",
        size,
        user_count,
        delegated_count,
        config.warmups,
        config.measurements,
        || {
            black_box(bsw07::setup()?);
            Ok(())
        },
    );
    measure(
        campaign,
        D3CS_SCHEMA,
        "KeyGen",
        size,
        user_count,
        delegated_count,
        config.warmups,
        config.measurements,
        || {
            black_box(cpabe::keygen(&d3cs.pp, d3cs_msk, &user_attributes())?);
            Ok(())
        },
    );
    measure(
        campaign,
        BSW07_SCHEMA,
        "KeyGen",
        size,
        user_count,
        delegated_count,
        config.warmups,
        config.measurements,
        || {
            black_box(bsw07::keygen(&bsw.pp, bsw_msk, &user_attributes())?);
            Ok(())
        },
    );
}

fn run_d3cs_measurements(
    campaign: &mut Campaign,
    config: &BenchmarkConfig,
    prepared: &PreparedD3cs,
    size: usize,
) {
    let user_count = user_attributes().len();
    let delegated_count = delegated_attributes().len();
    measure(
        campaign,
        D3CS_SCHEMA,
        "Encrypt",
        size,
        user_count,
        delegated_count,
        config.warmups,
        config.measurements,
        || {
            black_box(cpabe::encrypt(
                &prepared.pp,
                &prepared.label,
                &prepared.message,
            )?);
            Ok(())
        },
    );
    measure(
        campaign,
        D3CS_SCHEMA,
        "Sign",
        size,
        user_count,
        delegated_count,
        config.warmups,
        config.measurements,
        || {
            black_box(abs::sign(
                &prepared.abs_params,
                &prepared.abs_user_key,
                &prepared.signed_message,
            )?);
            Ok(())
        },
    );
    measure(
        campaign,
        D3CS_SCHEMA,
        "Verify",
        size,
        user_count,
        delegated_count,
        config.warmups,
        config.measurements,
        || {
            anyhow::ensure!(
                abs::verify_with_attr(
                    &prepared.abs_params,
                    &prepared.signature,
                    &prepared.signed_message,
                    ABS_ATTRIBUTE
                )?,
                "ABS verification failed"
            );
            Ok(())
        },
    );
    measure(
        campaign,
        D3CS_SCHEMA,
        "Encrypt+Sign+Verify",
        size,
        user_count,
        delegated_count,
        config.warmups,
        config.measurements,
        || {
            let ct = cpabe::encrypt(&prepared.pp, &prepared.label, &prepared.message)?;
            let signed_message = serde_json::to_string(&ct)?.into_bytes();
            let signature = abs::sign(
                &prepared.abs_params,
                &prepared.abs_user_key,
                &signed_message,
            )?;
            anyhow::ensure!(
                abs::verify_with_attr(
                    &prepared.abs_params,
                    &signature,
                    &signed_message,
                    ABS_ATTRIBUTE
                )?,
                "ABS verification failed"
            );
            black_box((ct, signature));
            Ok(())
        },
    );
    measure(
        campaign,
        D3CS_SCHEMA,
        "TM_Decrypt",
        size,
        user_count,
        delegated_count,
        config.warmups,
        config.measurements,
        || {
            black_box(cpabe::tm_decrypt(
                &prepared.pp,
                &prepared.ciphertext,
                &prepared.delegated_pska,
            )?);
            Ok(())
        },
    );
    measure(
        campaign,
        D3CS_SCHEMA,
        "Decrypt",
        size,
        user_count,
        delegated_count,
        config.warmups,
        config.measurements,
        || {
            black_box(cpabe::decrypt(
                &prepared.pp,
                &prepared.intermediate,
                &prepared.delegated_psks,
            )?);
            Ok(())
        },
    );
    measure(
        campaign,
        D3CS_SCHEMA,
        "TM_Decrypt+Decrypt",
        size,
        user_count,
        delegated_count,
        config.warmups,
        config.measurements,
        || {
            let intermediate =
                cpabe::tm_decrypt(&prepared.pp, &prepared.ciphertext, &prepared.delegated_pska)?;
            black_box(cpabe::decrypt(
                &prepared.pp,
                &intermediate,
                &prepared.delegated_psks,
            )?);
            Ok(())
        },
    );
    measure(
        campaign,
        D3CS_SCHEMA,
        "Delegate",
        size,
        user_count,
        delegated_count,
        config.warmups,
        config.measurements,
        || {
            black_box(cpabe::delegate(
                &prepared.pp,
                &prepared.psks,
                &delegated_attributes(),
            )?);
            Ok(())
        },
    );
    let (_, tk) = cpabe::delegate(&prepared.pp, &prepared.psks, &delegated_attributes())
        .expect("prepared D3CS TK");
    measure(
        campaign,
        D3CS_SCHEMA,
        "TM_Delegate",
        size,
        user_count,
        delegated_count,
        config.warmups,
        config.measurements,
        || {
            black_box(cpabe::tm_delegate(&prepared.pska, &tk)?);
            Ok(())
        },
    );
    measure(
        campaign,
        D3CS_SCHEMA,
        "Delegate+TM_Delegate",
        size,
        user_count,
        delegated_count,
        config.warmups,
        config.measurements,
        || {
            let (delegated_psks, tk) =
                cpabe::delegate(&prepared.pp, &prepared.psks, &delegated_attributes())?;
            let delegated_pska = cpabe::tm_delegate(&prepared.pska, &tk)?;
            black_box((delegated_pska, delegated_psks));
            Ok(())
        },
    );
}

fn run_bsw_measurements(
    campaign: &mut Campaign,
    config: &BenchmarkConfig,
    prepared: &PreparedBsw07,
    size: usize,
) {
    let user_count = user_attributes().len();
    let delegated_count = delegated_attributes().len();
    measure(
        campaign,
        BSW07_SCHEMA,
        "Encrypt",
        size,
        user_count,
        delegated_count,
        config.warmups,
        config.measurements,
        || {
            black_box(bsw07::encrypt(
                &prepared.pp,
                &prepared.label,
                &prepared.message,
            )?);
            Ok(())
        },
    );
    measure(
        campaign,
        BSW07_SCHEMA,
        "Decrypt",
        size,
        user_count,
        delegated_count,
        config.warmups,
        config.measurements,
        || {
            black_box(bsw07::decrypt(
                &prepared.pp,
                &prepared.ciphertext,
                &prepared.delegated_sk,
            )?);
            Ok(())
        },
    );
    measure(
        campaign,
        BSW07_SCHEMA,
        "Delegate",
        size,
        user_count,
        delegated_count,
        config.warmups,
        config.measurements,
        || {
            black_box(bsw07::delegate(
                &prepared.pp,
                &prepared.sk,
                &delegated_attributes(),
            )?);
            Ok(())
        },
    );
}

#[allow(clippy::too_many_arguments)]
fn run_controlled_core_measurements(
    campaign: &mut Campaign,
    config: &BenchmarkConfig,
    d3cs: &PreparedD3cs,
    d3cs_msk: &cpabe::MasterKeyV1,
    bsw: &PreparedBsw07,
    bsw_msk: &bsw07::Bsw07MasterKey,
) {
    let user_count = user_attributes().len();
    let delegated_count = delegated_attributes().len();
    measure_pair(
        campaign,
        "Setup",
        "Setup",
        0,
        user_count,
        delegated_count,
        config.warmups,
        config.measurements,
        config.order_block_size,
        config.order_seed,
        1,
        || {
            black_box(cpabe::setup()?);
            Ok(())
        },
        || {
            black_box(bsw07::setup()?);
            Ok(())
        },
    );
    measure_pair(
        campaign,
        "KeyGen",
        "KeyGen",
        0,
        user_count,
        delegated_count,
        config.warmups,
        config.measurements,
        config.order_block_size,
        config.order_seed,
        2,
        || {
            black_box(cpabe::keygen(&d3cs.pp, d3cs_msk, &user_attributes())?);
            Ok(())
        },
        || {
            black_box(bsw07::keygen(&bsw.pp, bsw_msk, &user_attributes())?);
            Ok(())
        },
    );
}

fn run_controlled_delegation_measurements(
    campaign: &mut Campaign,
    config: &BenchmarkConfig,
    d3cs: &PreparedD3cs,
    bsw: &PreparedBsw07,
) {
    let user_count = user_attributes().len();
    let delegated_count = delegated_attributes().len();
    let size = 0;
    let (_, tk) = cpabe::delegate(&d3cs.pp, &d3cs.psks, &delegated_attributes())
        .expect("prepared D3CS transformation key");

    measure(
        campaign,
        D3CS_SCHEMA,
        "Delegate",
        size,
        user_count,
        delegated_count,
        config.warmups,
        config.measurements,
        || {
            black_box(cpabe::delegate(
                &d3cs.pp,
                &d3cs.psks,
                &delegated_attributes(),
            )?);
            Ok(())
        },
    );
    measure(
        campaign,
        D3CS_SCHEMA,
        "TM_Delegate",
        size,
        user_count,
        delegated_count,
        config.warmups,
        config.measurements,
        || {
            black_box(cpabe::tm_delegate(&d3cs.pska, &tk)?);
            Ok(())
        },
    );
    measure_pair(
        campaign,
        "Delegate+TM_Delegate",
        "Delegate",
        size,
        user_count,
        delegated_count,
        config.warmups,
        config.measurements,
        config.order_block_size,
        config.order_seed,
        3,
        || {
            let (delegated_psks, tk) =
                cpabe::delegate(&d3cs.pp, &d3cs.psks, &delegated_attributes())?;
            let delegated_pska = cpabe::tm_delegate(&d3cs.pska, &tk)?;
            black_box((delegated_pska, delegated_psks));
            Ok(())
        },
        || {
            black_box(bsw07::delegate(&bsw.pp, &bsw.sk, &delegated_attributes())?);
            Ok(())
        },
    );
}

fn run_controlled_data_measurements(
    campaign: &mut Campaign,
    config: &BenchmarkConfig,
    d3cs: &PreparedD3cs,
    bsw: &PreparedBsw07,
    size: usize,
) {
    let user_count = user_attributes().len();
    let delegated_count = delegated_attributes().len();
    measure_pair(
        campaign,
        "Encrypt",
        "Encrypt",
        size,
        user_count,
        delegated_count,
        config.warmups,
        config.measurements,
        config.order_block_size,
        config.order_seed,
        10 + size as u64,
        || {
            black_box(cpabe::encrypt(&d3cs.pp, &d3cs.label, &d3cs.message)?);
            Ok(())
        },
        || {
            black_box(bsw07::encrypt(&bsw.pp, &bsw.label, &bsw.message)?);
            Ok(())
        },
    );
    measure(
        campaign,
        D3CS_SCHEMA,
        "Sign",
        size,
        user_count,
        delegated_count,
        config.warmups,
        config.measurements,
        || {
            black_box(abs::sign(
                &d3cs.abs_params,
                &d3cs.abs_user_key,
                &d3cs.signed_message,
            )?);
            Ok(())
        },
    );
    measure(
        campaign,
        D3CS_SCHEMA,
        "Verify",
        size,
        user_count,
        delegated_count,
        config.warmups,
        config.measurements,
        || {
            anyhow::ensure!(
                abs::verify_with_attr(
                    &d3cs.abs_params,
                    &d3cs.signature,
                    &d3cs.signed_message,
                    ABS_ATTRIBUTE,
                )?,
                "ABS verification failed"
            );
            Ok(())
        },
    );
    measure(
        campaign,
        D3CS_SCHEMA,
        "Encrypt+Sign+Verify",
        size,
        user_count,
        delegated_count,
        config.warmups,
        config.measurements,
        || {
            let ct = cpabe::encrypt(&d3cs.pp, &d3cs.label, &d3cs.message)?;
            let signed_message = serde_json::to_string(&ct)?.into_bytes();
            let signature = abs::sign(&d3cs.abs_params, &d3cs.abs_user_key, &signed_message)?;
            anyhow::ensure!(
                abs::verify_with_attr(
                    &d3cs.abs_params,
                    &signature,
                    &signed_message,
                    ABS_ATTRIBUTE,
                )?,
                "ABS verification failed"
            );
            black_box((ct, signature));
            Ok(())
        },
    );
    measure(
        campaign,
        D3CS_SCHEMA,
        "TM_Decrypt",
        size,
        user_count,
        delegated_count,
        config.warmups,
        config.measurements,
        || {
            black_box(cpabe::tm_decrypt(
                &d3cs.pp,
                &d3cs.ciphertext,
                &d3cs.delegated_pska,
            )?);
            Ok(())
        },
    );
    measure(
        campaign,
        D3CS_SCHEMA,
        "Decrypt",
        size,
        user_count,
        delegated_count,
        config.warmups,
        config.measurements,
        || {
            let plaintext = cpabe::decrypt(&d3cs.pp, &d3cs.intermediate, &d3cs.delegated_psks)?;
            anyhow::ensure!(
                plaintext == d3cs.message,
                "D3CS decryption returned an unexpected plaintext"
            );
            Ok(())
        },
    );
    measure_pair(
        campaign,
        "TM_Decrypt+Decrypt",
        "Decrypt",
        size,
        user_count,
        delegated_count,
        config.warmups,
        config.measurements,
        config.order_block_size,
        config.order_seed,
        20 + size as u64,
        || {
            let intermediate = cpabe::tm_decrypt(&d3cs.pp, &d3cs.ciphertext, &d3cs.delegated_pska)?;
            black_box(cpabe::decrypt(
                &d3cs.pp,
                &intermediate,
                &d3cs.delegated_psks,
            )?);
            Ok(())
        },
        || {
            anyhow::ensure!(
                bsw07::decrypt(&bsw.pp, &bsw.ciphertext, &bsw.delegated_sk)? == bsw.message,
                "BSW07 decryption returned an unexpected plaintext"
            );
            Ok(())
        },
    );
}

fn main() -> Result<()> {
    let config = config_from_environment()?;
    let attrs = user_attributes();
    let delegated = delegated_attributes();
    let (d3cs_prepared, d3cs_msk, _d3cs_tk) = prepare_d3cs(message_for_size(4))?;
    let (bsw_prepared, bsw_msk) = prepare_bsw07(message_for_size(4))?;
    anyhow::ensure!(
        d3cs_prepared.pp.system_id == d3cs_msk.system_id,
        "D3CS system identity mismatch"
    );
    anyhow::ensure!(
        bsw_prepared.pp.system_id == bsw_msk.system_id,
        "BSW07 system identity mismatch"
    );
    bsw07::validate_public_params(&bsw_prepared.pp)?;
    bsw07::validate_master_key(&bsw_msk)?;
    bsw07::validate_secret_key(&bsw_prepared.delegated_sk)?;
    bsw07::validate_ciphertext(&bsw_prepared.ciphertext)?;
    cpabe::validate_key_material(
        &d3cs_prepared.pp,
        &d3cs_prepared.delegated_pska,
        &d3cs_prepared.delegated_psks,
    )?;
    cpabe::validate_ciphertext_for_pp(&d3cs_prepared.pp, &d3cs_prepared.ciphertext)?;

    let mut campaign = Campaign {
        samples: Vec::new(),
        errors: Vec::new(),
    };
    if config.controlled {
        run_controlled_core_measurements(
            &mut campaign,
            &config,
            &d3cs_prepared,
            &d3cs_msk,
            &bsw_prepared,
            &bsw_msk,
        );
        run_controlled_delegation_measurements(
            &mut campaign,
            &config,
            &d3cs_prepared,
            &bsw_prepared,
        );
    } else {
        run_core_measurements(
            &mut campaign,
            &config,
            &d3cs_prepared,
            &d3cs_msk,
            &bsw_prepared,
            &bsw_msk,
        );
    }
    let mut sizes = Vec::new();
    let mut d3cs_system_ids = BTreeMap::new();
    let mut bsw07_system_ids = BTreeMap::new();
    for (campaign_index, message_size) in config.message_sizes.iter().enumerate() {
        let message = message_for_size(*message_size);
        let (d3cs, d3cs_msk_for_size, tk) = prepare_d3cs(message.clone())?;
        let (bsw, bsw_msk_for_size) = prepare_bsw07(message)?;
        d3cs_system_ids.insert(message_size.to_string(), d3cs.pp.system_id.clone());
        bsw07_system_ids.insert(message_size.to_string(), bsw.pp.system_id.clone());
        if config.controlled {
            run_controlled_data_measurements(&mut campaign, &config, &d3cs, &bsw, *message_size);
        } else if campaign_index.is_multiple_of(2) {
            run_d3cs_measurements(&mut campaign, &config, &d3cs, *message_size);
            run_bsw_measurements(&mut campaign, &config, &bsw, *message_size);
        } else {
            run_bsw_measurements(&mut campaign, &config, &bsw, *message_size);
            run_d3cs_measurements(&mut campaign, &config, &d3cs, *message_size);
        }
        add_d3cs_sizes(&mut sizes, &d3cs, &d3cs_msk_for_size, &tk, *message_size)?;
        add_bsw_sizes(&mut sizes, &bsw, &bsw_msk_for_size, *message_size)?;
    }

    let status = git_status();
    let metadata = Metadata {
        benchmark: "D3CS PM23/LK10 versus standalone BSW07 local cryptographic comparison",
        timestamp_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        git_commit: command_output("git", &["rev-parse", "HEAD"]),
        git_worktree_state: if status == "unavailable" { "unavailable".to_string() } else if status.is_empty() { "clean".to_string() } else { "modified".to_string() },
        git_status_porcelain: status,
        rustc: command_output("rustc", &["--version"]),
        dependencies: command_output("cargo", &["tree", "--depth", "1"]),
        operating_system: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        processor: command_output("bash", &["-lc", "lscpu | sed -n '/Model name/ { s/^[^:]*:[[:space:]]*//; p; q; }'"]),
        build_mode: "release",
        execution_mode: if config.controlled { "controlled_campaign" } else { "historical_single_campaign" },
        campaign_id: config.campaign_id,
        order_seed: config.order_seed,
        order_block_size: config.order_block_size,
        order_strategy: if config.controlled { "reproducible_balanced_short_blocks" } else { "message_size_block_order" },
        warmups: config.warmups,
        measurements: config.measurements,
        duration_unit: "nanoseconds from std::time::Instant",
        policy: "classification AND mission",
        policy_leaves: POLICY_LEAVES,
        user_attributes: attrs,
        delegated_attributes: delegated,
        message_sizes_bytes: config.message_sizes.clone(),
        hybrid_cipher: "AES-256-GCM; no network time included",
        d3cs_cpabe_version: "CP-ABE",
        d3cs_hash_to_curve: "G2 MapToCurveBasedHasher / WBMap / SHA-256",
        d3cs_hash_domain: "D3CS-CPABE-V2-ATTR-G2",
        bsw07_format_version: "BSW07 format v1 with mandatory BSW07 scheme tag",
        bsw07_hash_to_curve: "G2 MapToCurveBasedHasher / WBMap / SHA-256",
        bsw07_hash_domain: "D3CS-BSW07-CPABE-ATTR-G2-v1",
        abs_hash_domains: ["D3CS-ABS-H1", "D3CS-ABS-H2"],
        d3cs_system_ids,
        bsw07_system_ids,
        note: "D3CS and BSW07 are not claimed to provide identical security or functionality; cumulative medians are measured sequences, not sums of medians.",
    };
    write_outputs(&config, &campaign, &sizes, &metadata)?;
    if !campaign.errors.is_empty() {
        return Err(anyhow!(
            "benchmark completed with {} failed or warmup operations; see {}/errors.csv",
            campaign.errors.len(),
            output_dir(),
        ));
    }
    println!("Benchmark completed: {}", output_dir());
    println!("timings_raw.csv, timings_summary.csv, sizes.csv, metadata.json, errors.csv");
    Ok(())
}
