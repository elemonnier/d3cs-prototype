use std::fs;
use std::path::Path;
use std::time::Instant;

use anyhow::{Context, Result};
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

struct Samples {
    operation: &'static str,
    durations_us: Vec<u128>,
}

fn record<F>(operation: &'static str, mut operation_fn: F) -> Result<Samples>
where
    F: FnMut() -> Result<()>,
{
    for _ in 0..WARMUPS {
        operation_fn()?;
    }

    let mut durations_us = Vec::with_capacity(MEASUREMENTS);
    for _ in 0..MEASUREMENTS {
        let started = Instant::now();
        operation_fn()?;
        durations_us.push(started.elapsed().as_micros());
    }

    Ok(Samples {
        operation,
        durations_us,
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

fn median(values: &[u128]) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let middle = sorted.len() / 2;
    if sorted.len() % 2 == 0 {
        (sorted[middle - 1] + sorted[middle]) as f64 / 2.0
    } else {
        sorted[middle] as f64
    }
}

fn serialized_size<T: Serialize>(value: &T) -> Result<usize> {
    Ok(serde_json::to_string(value)?.as_bytes().len())
}

fn main() -> Result<()> {
    let attrs = vec!["FR-DR".to_string(), "M1".to_string()];
    let label = DocumentLabel {
        classification: "FR-DR".to_string(),
        mission: "M1".to_string(),
    };
    let message = "test";

    let setup = record("Setup", || {
        cpabe::setup().map(|_| ())
    })?;

    // One valid reference state is prepared outside every measured region.
    let (pp, msk) = cpabe::setup().context("reference CP-ABE setup")?;
    let keygen = record("KeyGen", || {
        cpabe::keygen(&pp, &msk, &attrs).map(|_| ())
    })?;
    let (pska, psks) = cpabe::keygen(&pp, &msk, &attrs).context("reference KeyGen")?;

    let delegate = record("Delegate", || {
        cpabe::delegate(&pp, &psks, &attrs).map(|_| ())
    })?;
    let (delegated_psks, tk) =
        cpabe::delegate(&pp, &psks, &attrs).context("reference Delegate")?;

    let tm_delegate = record("TM_Delegate", || {
        cpabe::tm_delegate(&pska, &tk).map(|_| ())
    })?;
    let delegated_pska =
        cpabe::tm_delegate(&pska, &tk).context("reference TM_Delegate")?;

    let encrypt = record("Encrypt", || {
        cpabe::encrypt(&pp, &label, message).map(|_| ())
    })?;
    let ciphertext = cpabe::encrypt(&pp, &label, message).context("reference Encrypt")?;

    let tm_decrypt = record("TM_Decrypt", || {
        cpabe::tm_decrypt(&pp, &ciphertext, &delegated_pska).map(|_| ())
    })?;
    let intermediate_ciphertext = cpabe::tm_decrypt(&pp, &ciphertext, &delegated_pska)
        .context("reference TM_Decrypt")?;

    let decrypt = record("Decrypt", || {
        cpabe::decrypt(&pp, &intermediate_ciphertext, &delegated_psks).map(|_| ())
    })?;
    let plaintext = cpabe::decrypt(&pp, &intermediate_ciphertext, &delegated_psks)
        .context("reference Decrypt")?;
    anyhow::ensure!(plaintext == message, "CP-ABE round-trip did not recover test");

    let samples = [setup, keygen, delegate, tm_delegate, encrypt, tm_decrypt, decrypt];
    anyhow::ensure!(
        samples.iter().all(|sample| sample.durations_us.len() == MEASUREMENTS),
        "unexpected number of measurements"
    );
    anyhow::ensure!(
        samples
            .iter()
            .all(|sample| sample.durations_us.iter().all(|duration| *duration > 0)),
        "unexpected zero duration"
    );

    let results = Path::new("results");
    fs::create_dir_all(results)?;

    let mut raw = String::from("operation,iteration,duration_us\n");
    for sample in &samples {
        for (index, duration) in sample.durations_us.iter().enumerate() {
            raw.push_str(&format!(
                "{},{},{}\n",
                sample.operation,
                index + 1,
                duration
            ));
        }
    }
    fs::write(results.join("cpabe_timings.csv"), raw)?;

    let mut summary = String::from(
        "operation,n,mean_us,stddev_us,median_us,min_us,max_us\n",
    );
    println!("operation,n,mean_us,stddev_us,median_us,min_us,max_us");
    for sample in &samples {
        let average = mean(&sample.durations_us);
        let line = format!(
            "{},{},{:.3},{:.3},{:.3},{},{}\n",
            sample.operation,
            sample.durations_us.len(),
            average,
            sample_stddev(&sample.durations_us, average),
            median(&sample.durations_us),
            sample.durations_us.iter().min().unwrap(),
            sample.durations_us.iter().max().unwrap()
        );
        print!("{line}");
        summary.push_str(&line);
    }
    fs::write(results.join("cpabe_timings_summary.csv"), summary)?;

    let sizes = [
        ("public_parameters", serialized_size(&pp)?),
        ("master_secret_key", serialized_size(&msk)?),
        ("pska", serialized_size(&pska)?),
        ("psks", serialized_size(&psks)?),
        ("tk", serialized_size(&tk)?),
        ("ciphertext", serialized_size(&ciphertext)?),
        (
            "intermediate_ciphertext",
            serialized_size(&intermediate_ciphertext)?,
        ),
    ];
    let mut sizes_csv = String::from("object,size_bytes\n");
    for (object, size) in sizes {
        sizes_csv.push_str(&format!("{object},{size}\n"));
    }
    fs::write(results.join("cpabe_sizes.csv"), sizes_csv)?;

    Ok(())
}
