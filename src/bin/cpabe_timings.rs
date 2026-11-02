use std::fs;
use std::path::Path;
use std::time::Instant;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};

#[path = "../crypto/cpabe.rs"]
mod cpabe;

#[derive(Clone, Deserialize, Serialize)]
pub struct DocumentLabel {
    pub classification: String,
    pub mission: String,
}

const WARMUPS: usize = 100;
const MEASUREMENTS: usize = 500;
const OUTPUT_DIR: &str = "results/cpabe/cpabe_timings";

struct Samples {
    operation: &'static str,
    durations_ns: Vec<u128>,
}

#[derive(Serialize)]
struct Metadata {
    benchmark: &'static str,
    cryptographic_version: &'static str,
    curve: &'static str,
    hash_to_curve: &'static str,
    build_mode: &'static str,
    warmups: usize,
    measurements: usize,
    message_size_bytes: usize,
    duration_unit_raw: &'static str,
    duration_unit_summary: &'static str,
    stddev: &'static str,
    percentile: &'static str,
    git_commit: String,
    git_worktree: String,
    rustc: String,
    dependencies: String,
    operating_system: &'static str,
    architecture: &'static str,
    processor: String,
    system_id: String,
}

struct ObjectSize {
    object: &'static str,
    serialized_json_bytes: usize,
    decoded_crypto_payload_bytes: usize,
}

fn command_output(command: &str, args: &[&str]) -> String {
    std::process::Command::new(command)
        .args(args)
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unavailable".to_string())
}

fn record<F>(operation: &'static str, mut operation_fn: F) -> Result<Samples>
where
    F: FnMut() -> Result<()>,
{
    for _ in 0..WARMUPS {
        operation_fn()?;
    }

    let mut durations_ns = Vec::with_capacity(MEASUREMENTS);
    for _ in 0..MEASUREMENTS {
        let started = Instant::now();
        operation_fn()?;
        durations_ns.push(started.elapsed().as_nanos());
    }

    Ok(Samples {
        operation,
        durations_ns,
    })
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
            let delta = *value as f64 - average;
            delta * delta
        })
        .sum::<f64>();
    (sum / (values.len() - 1) as f64).sqrt()
}

fn percentile(values: &[u128], numerator: usize, denominator: usize) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let rank = (sorted.len() * numerator).div_ceil(denominator).max(1);
    sorted[rank - 1] as f64
}

fn median(values: &[u128]) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let middle = sorted.len() / 2;
    if sorted.len() % 2 == 0 {
        (sorted[middle - 1] as f64 + sorted[middle] as f64) / 2.0
    } else {
        sorted[middle] as f64
    }
}

fn serialized_size<T: Serialize>(value: &T) -> Result<usize> {
    Ok(serde_json::to_vec(value)?.len())
}

fn decoded_size(value: &str) -> usize {
    STANDARD_NO_PAD
        .decode(value)
        .map(|bytes| bytes.len())
        .unwrap_or(0)
}

fn object_size<T: Serialize>(
    object: &'static str,
    value: &T,
    decoded_crypto_payload_bytes: usize,
) -> Result<ObjectSize> {
    Ok(ObjectSize {
        object,
        serialized_json_bytes: serialized_size(value)?,
        decoded_crypto_payload_bytes,
    })
}

fn public_params_size(value: &cpabe::PublicParamsV1) -> usize {
    [&value.g, &value.g2, &value.h, &value.f, &value.f2, &value.y]
        .into_iter()
        .map(|item| decoded_size(item))
        .sum()
}

fn master_key_size(value: &cpabe::MasterKeyV1) -> usize {
    decoded_size(&value.alpha) + decoded_size(&value.beta)
}

fn pska_size(value: &cpabe::PskaV1) -> usize {
    decoded_size(&value.d)
}

fn psks_size(value: &cpabe::PsksV1) -> usize {
    value
        .attrs
        .iter()
        .map(|item| decoded_size(&item.d) + decoded_size(&item.d_prime))
        .sum()
}

fn tk_size(value: &cpabe::TkV1) -> usize {
    decoded_size(&value.t)
}

fn ciphertext_size(value: &cpabe::CiphertextV1) -> usize {
    decoded_size(&value.abe.c_tilde)
        + decoded_size(&value.abe.c)
        + value
            .abe
            .leafs
            .iter()
            .map(|item| decoded_size(&item.c_i) + decoded_size(&item.c_i_prime))
            .sum::<usize>()
        + decoded_size(&value.sym.nonce)
        + decoded_size(&value.sym.ciphertext)
}

fn intermediate_ciphertext_size(value: &cpabe::IntermediateCiphertextV1) -> usize {
    decoded_size(&value.abe.c_tilde)
        + decoded_size(&value.abe.f)
        + value
            .abe
            .leafs
            .iter()
            .map(|item| decoded_size(&item.c_i) + decoded_size(&item.c_i_prime))
            .sum::<usize>()
        + decoded_size(&value.sym.nonce)
        + decoded_size(&value.sym.ciphertext)
}

fn main() -> Result<()> {
    let attrs = vec!["FR-DR".to_string(), "M1".to_string()];
    let label = DocumentLabel {
        classification: "FR-DR".to_string(),
        mission: "M1".to_string(),
    };
    let message = "test";

    let setup = record("Setup", || cpabe::setup().map(|_| ()))?;
    let (pp, msk) = cpabe::setup().context("reference CP-ABE setup")?;
    let keygen = record("KeyGen", || cpabe::keygen(&pp, &msk, &attrs).map(|_| ()))?;
    let (pska, psks) = cpabe::keygen(&pp, &msk, &attrs).context("reference KeyGen")?;

    let delegate = record("Delegate", || {
        cpabe::delegate(&pp, &psks, &attrs).map(|_| ())
    })?;
    let (delegated_psks, tk) = cpabe::delegate(&pp, &psks, &attrs).context("reference Delegate")?;

    let tm_delegate = record("TM_Delegate", || cpabe::tm_delegate(&pska, &tk).map(|_| ()))?;
    let delegated_pska = cpabe::tm_delegate(&pska, &tk).context("reference TM_Delegate")?;

    let encrypt = record("Encrypt", || {
        cpabe::encrypt(&pp, &label, message).map(|_| ())
    })?;
    let ciphertext = cpabe::encrypt(&pp, &label, message).context("reference Encrypt")?;

    let tm_decrypt = record("TM_Decrypt", || {
        cpabe::tm_decrypt(&pp, &ciphertext, &delegated_pska).map(|_| ())
    })?;
    let intermediate_ciphertext =
        cpabe::tm_decrypt(&pp, &ciphertext, &delegated_pska).context("reference TM_Decrypt")?;

    let decrypt = record("Decrypt", || {
        cpabe::decrypt(&pp, &intermediate_ciphertext, &delegated_psks).map(|_| ())
    })?;
    let plaintext = cpabe::decrypt(&pp, &intermediate_ciphertext, &delegated_psks)
        .context("reference Decrypt")?;
    anyhow::ensure!(
        plaintext == message,
        "CP-ABE round-trip did not recover test"
    );

    let samples = [
        setup,
        keygen,
        delegate,
        tm_delegate,
        encrypt,
        tm_decrypt,
        decrypt,
    ];
    anyhow::ensure!(
        samples
            .iter()
            .all(|sample| sample.durations_ns.len() == MEASUREMENTS),
        "unexpected number of measurements"
    );

    let output_dir = Path::new(OUTPUT_DIR);
    fs::create_dir_all(output_dir)?;

    let mut raw = String::from("operation,iteration,duration_ns\n");
    for sample in &samples {
        for (index, duration) in sample.durations_ns.iter().enumerate() {
            raw.push_str(&format!(
                "{},{},{}\n",
                sample.operation,
                index + 1,
                duration
            ));
        }
    }
    fs::write(output_dir.join("timings_raw.csv"), raw)?;

    let mut summary = String::from(
        "operation,n,mean_us,stddev_us,median_us,p95_us,min_us,max_us,stddev_convention,percentile_convention\n",
    );
    println!("operation,n,mean_us,stddev_us,median_us,p95_us,min_us,max_us");
    for sample in &samples {
        let average = mean(&sample.durations_ns);
        let to_us = |nanoseconds: f64| nanoseconds / 1_000.0;
        let line = format!(
            "{},{},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},sample (n-1),nearest-rank ceil(0.95*n)\n",
            sample.operation,
            sample.durations_ns.len(),
            to_us(average),
            to_us(sample_stddev(&sample.durations_ns, average)),
            to_us(median(&sample.durations_ns)),
            to_us(percentile(&sample.durations_ns, 95, 100)),
            to_us(*sample.durations_ns.iter().min().unwrap() as f64),
            to_us(*sample.durations_ns.iter().max().unwrap() as f64),
        );
        print!("{line}");
        summary.push_str(&line);
    }
    fs::write(output_dir.join("timings_summary.csv"), summary)?;

    let sizes = [
        object_size("public_parameters", &pp, public_params_size(&pp))?,
        object_size("master_secret_key", &msk, master_key_size(&msk))?,
        object_size("pska", &pska, pska_size(&pska))?,
        object_size("psks", &psks, psks_size(&psks))?,
        object_size("tk", &tk, tk_size(&tk))?,
        object_size("ciphertext", &ciphertext, ciphertext_size(&ciphertext))?,
        object_size(
            "intermediate_ciphertext",
            &intermediate_ciphertext,
            intermediate_ciphertext_size(&intermediate_ciphertext),
        )?,
    ];
    let mut sizes_csv =
        String::from("object,serialized_json_bytes,decoded_crypto_payload_bytes,serialization\n");
    for size in sizes {
        sizes_csv.push_str(&format!(
            "{},{},{},serde_json UTF-8 with Base64 fields\n",
            size.object, size.serialized_json_bytes, size.decoded_crypto_payload_bytes
        ));
    }
    fs::write(output_dir.join("object_sizes.csv"), sizes_csv)?;

    let status = command_output("git", &["status", "--porcelain"]);
    let metadata = Metadata {
        benchmark: "CP-ABE primitive timings",
        cryptographic_version: "2",
        curve: "BLS12-381",
        hash_to_curve: "G2, deterministic hash-to-curve",
        build_mode: "release",
        warmups: WARMUPS,
        measurements: MEASUREMENTS,
        message_size_bytes: message.len(),
        duration_unit_raw: "nanoseconds from std::time::Instant",
        duration_unit_summary: "microseconds",
        stddev: "sample standard deviation with denominator n-1",
        percentile: "nearest-rank, rank=ceil(0.95*n)",
        git_commit: command_output("git", &["rev-parse", "HEAD"]),
        git_worktree: if status == "unavailable" {
            status
        } else if status.is_empty() {
            "clean".to_string()
        } else {
            "modified".to_string()
        },
        rustc: command_output("rustc", &["--version"]),
        dependencies: command_output("cargo", &["tree", "--depth", "1"]),
        operating_system: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        processor: command_output(
            "bash",
            &[
                "-lc",
                "lscpu | sed -n '/Model name/ { s/^[^:]*:[[:space:]]*//; p; q; }'",
            ],
        ),
        system_id: pp.system_id.clone(),
    };
    fs::write(
        output_dir.join("metadata.json"),
        serde_json::to_vec_pretty(&metadata)?,
    )?;

    Ok(())
}
