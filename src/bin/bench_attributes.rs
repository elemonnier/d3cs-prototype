//! Campagne Rust autonome sur l'influence du nombre d'attributs.
//!
//! Cette campagne réutilise directement les primitives du dépôt. Elle ne
//! démarre ni serveur HTTP ni composant réseau. Les configurations que les
//! APIs actuelles ne peuvent pas représenter sont exportées dans errors.csv,
//! sans être remplacées par des mesures simulées.

use std::env;
use std::fs;
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct DocumentLabel {
    pub classification: String,
    pub mission: String,
}

#[path = "../crypto/abs.rs"]
#[allow(dead_code)]
mod abs;
#[path = "../crypto/cpabe.rs"]
mod cpabe;

const ATTRIBUTE_COUNTS: [usize; 6] = [1, 2, 5, 10, 20, 50];
const DEFAULT_WARMUPS: usize = 10;
const DEFAULT_MEASUREMENTS: usize = 100;
const MESSAGE_SIZE: usize = 1024;
const ABS_ATTRIBUTE: &str = "A1";

type PlotSeries = (String, String, Vec<(usize, f64)>);

#[derive(Clone, Debug)]
struct Config {
    warmups: usize,
    measurements: usize,
    output_dir: PathBuf,
    only: Option<String>,
    plots: bool,
}

#[derive(Clone)]
struct RawSample {
    experiment: String,
    operation: String,
    attributes: usize,
    iteration: usize,
    duration_ns: u128,
}

#[derive(Clone)]
struct ErrorRow {
    experiment: String,
    operation: String,
    attributes: usize,
    iteration: usize,
    error: String,
}

#[derive(Clone)]
struct SummaryRow {
    experiment: String,
    operation: String,
    attributes: usize,
    valid_samples: usize,
    mean_ms: f64,
    median_ms: f64,
    stddev_ms: f64,
    min_ms: f64,
    max_ms: f64,
    p95_ms: f64,
}

#[derive(Clone)]
struct SizeRow {
    experiment: String,
    operation: String,
    attributes: usize,
    object_type: String,
    size_bytes: usize,
    representation: String,
}

#[derive(Serialize)]
struct Metadata {
    benchmark: &'static str,
    version: &'static str,
    cryptographic_version: &'static str,
    curve: &'static str,
    hash_to_curve: &'static str,
    attribute_counts: Vec<usize>,
    warmups: usize,
    measurements: usize,
    message_size_bytes: usize,
    duration_unit_raw: &'static str,
    duration_unit_summary: &'static str,
    stddev: &'static str,
    percentile: &'static str,
    rustc: String,
    target_os: &'static str,
    target_arch: &'static str,
    processor: String,
    build_mode: &'static str,
    git_revision: String,
    git_worktree: String,
    dependencies: String,
    system_id: String,
    policy_leaves: usize,
    limitations: Vec<&'static str>,
}

fn usage() -> &'static str {
    "Usage: cargo run --release --bin bench_attributes -- [OPTIONS]\n\
     Options:\n\
       --warmups N          échauffements (défaut: 10)\n\
       --measurements N     mesures valides (défaut: 100)\n\
       --output-dir PATH    répertoire de sortie (défaut: results/attribute_benchmark)\n\
       --only NAME          abs-user-set | abs-predicate | cpabe-policy | cpabe-keys\n\
       --quick              1 échauffement et 3 mesures\n\
       --no-plots           ne pas générer les SVG\n\
       --help"
}

fn parse_usize(value: Option<&String>, option: &str) -> Result<usize> {
    let value = value.ok_or_else(|| anyhow!("{option} attend une valeur"))?;
    let parsed = value
        .parse::<usize>()
        .with_context(|| format!("valeur invalide pour {option}: {value}"))?;
    if parsed == 0 {
        return Err(anyhow!("{option} doit être positif"));
    }
    Ok(parsed)
}

fn parse_args() -> Result<Config> {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut config = Config {
        warmups: DEFAULT_WARMUPS,
        measurements: DEFAULT_MEASUREMENTS,
        output_dir: PathBuf::from("results/cpabe/attribute_benchmark"),
        only: None,
        plots: true,
    };
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--warmups" => {
                config.warmups = parse_usize(args.get(index + 1), "--warmups")?;
                index += 2;
            }
            "--measurements" => {
                config.measurements = parse_usize(args.get(index + 1), "--measurements")?;
                index += 2;
            }
            "--output-dir" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| anyhow!("--output-dir attend une valeur"))?;
                config.output_dir = PathBuf::from(value);
                index += 2;
            }
            "--only" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| anyhow!("--only attend une valeur"))?;
                let allowed = [
                    "abs-user-set",
                    "abs-predicate",
                    "cpabe-policy",
                    "cpabe-keys",
                ];
                if !allowed.contains(&value.as_str()) {
                    return Err(anyhow!("expérience inconnue: {value}"));
                }
                config.only = Some(value.clone());
                index += 2;
            }
            "--quick" => {
                config.warmups = 1;
                config.measurements = 3;
                index += 1;
            }
            "--no-plots" => {
                config.plots = false;
                index += 1;
            }
            "--help" | "-h" => {
                println!("{}", usage());
                std::process::exit(0);
            }
            option => return Err(anyhow!("option inconnue: {option}\n\n{}", usage())),
        }
    }
    Ok(config)
}

fn attrs(count: usize) -> Vec<String> {
    (1..=count).map(|index| format!("A{index}")).collect()
}

fn fixed_two_attribute_label() -> DocumentLabel {
    DocumentLabel {
        classification: "A1".to_string(),
        mission: "A2".to_string(),
    }
}

fn one_distinct_attribute_label() -> DocumentLabel {
    // CP-ABE impose deux feuilles. Cette étiquette ne contient qu'un attribut
    // distinct, répété sur les deux feuilles, pour les expériences D.
    DocumentLabel {
        classification: ABS_ATTRIBUTE.to_string(),
        mission: ABS_ATTRIBUTE.to_string(),
    }
}

fn fixed_message() -> String {
    "D3CS benchmark message ".repeat(MESSAGE_SIZE / 23 + 1)[..MESSAGE_SIZE].to_string()
}

fn serialized_size<T: Serialize>(value: &T) -> Result<usize> {
    Ok(serde_json::to_vec(value)?.len())
}

fn csv_escape(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn record_error(
    errors: &mut Vec<ErrorRow>,
    experiment: &str,
    operation: &str,
    attributes: usize,
    iteration: usize,
    error: impl Into<String>,
) {
    errors.push(ErrorRow {
        experiment: experiment.to_string(),
        operation: operation.to_string(),
        attributes,
        iteration,
        error: error.into(),
    });
}

fn unsupported(
    errors: &mut Vec<ErrorRow>,
    experiment: &str,
    operation: &str,
    attributes: usize,
    reason: &str,
) {
    record_error(errors, experiment, operation, attributes, 0, reason);
}

#[allow(clippy::too_many_arguments)]
fn measure<T, F>(
    experiment: &str,
    operation: &str,
    attributes: usize,
    warmups: usize,
    measurements: usize,
    errors: &mut Vec<ErrorRow>,
    raw: &mut Vec<RawSample>,
    mut operation_fn: F,
) -> Vec<u128>
where
    F: FnMut() -> Result<T>,
{
    for warmup in 1..=warmups {
        if let Err(error) = operation_fn() {
            record_error(
                errors,
                experiment,
                operation,
                attributes,
                0,
                format!("warmup {warmup}: {error:#}"),
            );
        }
    }

    let mut durations = Vec::with_capacity(measurements);
    for iteration in 1..=measurements {
        let started = Instant::now();
        match operation_fn() {
            Ok(value) => {
                let duration_ns = started.elapsed().as_nanos();
                black_box(value);
                raw.push(RawSample {
                    experiment: experiment.to_string(),
                    operation: operation.to_string(),
                    attributes,
                    iteration,
                    duration_ns,
                });
                durations.push(duration_ns);
            }
            Err(error) => record_error(
                errors,
                experiment,
                operation,
                attributes,
                iteration,
                format!("{error:#}"),
            ),
        }
    }
    durations
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

fn summary(
    experiment: &str,
    operation: &str,
    attributes: usize,
    durations: &[u128],
) -> Option<SummaryRow> {
    if durations.is_empty() {
        return None;
    }
    let mut sorted = durations.to_vec();
    sorted.sort_unstable();
    let middle = sorted.len() / 2;
    let median_ns = if sorted.len().is_multiple_of(2) {
        (sorted[middle - 1] as f64 + sorted[middle] as f64) / 2.0
    } else {
        sorted[middle] as f64
    };
    let average = mean(durations);
    let to_ms = |ns: f64| ns / 1_000_000.0;
    Some(SummaryRow {
        experiment: experiment.to_string(),
        operation: operation.to_string(),
        attributes,
        valid_samples: durations.len(),
        mean_ms: to_ms(average),
        median_ms: to_ms(median_ns),
        stddev_ms: to_ms(sample_stddev(durations, average)),
        min_ms: to_ms(*sorted.first().unwrap() as f64),
        max_ms: to_ms(*sorted.last().unwrap() as f64),
        p95_ms: to_ms(percentile(durations, 95, 100)),
    })
}

fn add_size<T: Serialize>(
    sizes: &mut Vec<SizeRow>,
    experiment: &str,
    operation: &str,
    attributes: usize,
    object_type: &str,
    value: &T,
) -> Result<()> {
    sizes.push(SizeRow {
        experiment: experiment.to_string(),
        operation: operation.to_string(),
        attributes,
        object_type: object_type.to_string(),
        size_bytes: serialized_size(value)?,
        representation: "serde_json UTF-8 bytes".to_string(),
    });
    Ok(())
}

fn experiment_selected(config: &Config, name: &str) -> bool {
    match config.only.as_deref() {
        None => true,
        Some(selected) => selected == name,
    }
}

fn run_abs_user_set(
    abs_params: &abs::AbsParamsV1,
    abs_msk: &abs::AbsMasterKeyV1,
    config: &Config,
    raw: &mut Vec<RawSample>,
    summaries: &mut Vec<SummaryRow>,
    sizes: &mut Vec<SizeRow>,
    errors: &mut Vec<ErrorRow>,
) -> Result<()> {
    let experiment = "A_abs_user_attribute_set";
    for &count in &ATTRIBUTE_COUNTS {
        if count != 1 {
            let reason = "API ABS actuelle: extract accepte un seul attribut et AbsUserKeyV1 ne contient qu'un attribut; l'ensemble utilisateur de cardinalité N n'est pas représentable.";
            for operation in ["extract", "sign", "verify"] {
                unsupported(errors, experiment, operation, count, reason);
            }
            continue;
        }

        let key = abs::extract(abs_params, abs_msk, ABS_ATTRIBUTE)
            .with_context(|| format!("{experiment} extract preparation"))?;
        let signature = abs::sign(abs_params, &key, b"ABS fixed message")?;
        anyhow::ensure!(
            abs::verify_with_attr(abs_params, &signature, b"ABS fixed message", ABS_ATTRIBUTE)?,
            "ABS reference signature did not verify"
        );

        let durations = measure(
            experiment,
            "extract",
            count,
            config.warmups,
            config.measurements,
            errors,
            raw,
            || abs::extract(abs_params, abs_msk, ABS_ATTRIBUTE),
        );
        if let Some(row) = summary(experiment, "extract", count, &durations) {
            summaries.push(row);
        }
        let durations = measure(
            experiment,
            "sign",
            count,
            config.warmups,
            config.measurements,
            errors,
            raw,
            || abs::sign(abs_params, &key, b"ABS fixed message"),
        );
        if let Some(row) = summary(experiment, "sign", count, &durations) {
            summaries.push(row);
        }
        let durations = measure(
            experiment,
            "verify",
            count,
            config.warmups,
            config.measurements,
            errors,
            raw,
            || abs::verify_with_attr(abs_params, &signature, b"ABS fixed message", ABS_ATTRIBUTE),
        );
        if let Some(row) = summary(experiment, "verify", count, &durations) {
            summaries.push(row);
        }
        add_size(sizes, experiment, "extract", count, "abs_user_key", &key)?;
        add_size(
            sizes,
            experiment,
            "sign",
            count,
            "abs_signature",
            &signature,
        )?;
    }
    Ok(())
}

fn run_abs_predicate(
    abs_params: &abs::AbsParamsV1,
    abs_msk: &abs::AbsMasterKeyV1,
    config: &Config,
    raw: &mut Vec<RawSample>,
    summaries: &mut Vec<SummaryRow>,
    sizes: &mut Vec<SizeRow>,
    errors: &mut Vec<ErrorRow>,
) -> Result<()> {
    let experiment = "B_abs_mobilized_attributes";
    for &count in &ATTRIBUTE_COUNTS {
        if count != 1 {
            let reason = "API ABS actuelle: params.d=1, extract produit une clé pour un seul attribut et sign ne construit aucun prédicat multi-attribut; N attributs mobilisés n'est pas réalisable.";
            for operation in ["sign", "verify"] {
                unsupported(errors, experiment, operation, count, reason);
            }
            continue;
        }
        let key = abs::extract(abs_params, abs_msk, ABS_ATTRIBUTE)?;
        let signature = abs::sign(abs_params, &key, b"ABS fixed message")?;
        anyhow::ensure!(
            abs::verify_with_attr(abs_params, &signature, b"ABS fixed message", ABS_ATTRIBUTE)?,
            "ABS reference signature did not verify"
        );

        let durations = measure(
            experiment,
            "sign",
            count,
            config.warmups,
            config.measurements,
            errors,
            raw,
            || abs::sign(abs_params, &key, b"ABS fixed message"),
        );
        if let Some(row) = summary(experiment, "sign", count, &durations) {
            summaries.push(row);
        }
        let durations = measure(
            experiment,
            "verify",
            count,
            config.warmups,
            config.measurements,
            errors,
            raw,
            || abs::verify_with_attr(abs_params, &signature, b"ABS fixed message", ABS_ATTRIBUTE),
        );
        if let Some(row) = summary(experiment, "verify", count, &durations) {
            summaries.push(row);
        }
        add_size(
            sizes,
            experiment,
            "sign",
            count,
            "abs_signature",
            &signature,
        )?;
    }
    Ok(())
}

fn run_cpabe_policy(
    pp: &cpabe::PublicParamsV1,
    msk: &cpabe::MasterKeyV1,
    config: &Config,
    raw: &mut Vec<RawSample>,
    summaries: &mut Vec<SummaryRow>,
    sizes: &mut Vec<SizeRow>,
    errors: &mut Vec<ErrorRow>,
) -> Result<()> {
    let experiment = "C_cpabe_policy_attributes";
    let fixed_attrs = attrs(50);
    let (pska, psks) = cpabe::keygen(pp, msk, &fixed_attrs)?;
    let message = fixed_message();

    for &count in &ATTRIBUTE_COUNTS {
        if count != 2 {
            let reason = "API CP-ABE actuelle: encrypt encode toujours exactement deux feuilles et decrypt applique la reconstruction fixe à deux feuilles; une politique conjonctive de cardinalité N != 2 n'est pas représentable.";
            for operation in ["encrypt", "decrypt"] {
                unsupported(errors, experiment, operation, count, reason);
            }
            continue;
        }
        let label = fixed_two_attribute_label();
        let ciphertext = cpabe::encrypt(pp, &label, &message)?;
        let intermediate = cpabe::tm_decrypt(pp, &ciphertext, &pska)?;
        let plaintext = cpabe::decrypt(pp, &intermediate, &psks)?;
        anyhow::ensure!(
            plaintext == message,
            "CP-ABE policy reference round-trip failed"
        );

        let durations = measure(
            experiment,
            "encrypt",
            count,
            config.warmups,
            config.measurements,
            errors,
            raw,
            || cpabe::encrypt(pp, &label, &message),
        );
        if let Some(row) = summary(experiment, "encrypt", count, &durations) {
            summaries.push(row);
        }
        let durations = measure(
            experiment,
            "decrypt",
            count,
            config.warmups,
            config.measurements,
            errors,
            raw,
            || cpabe::decrypt(pp, &intermediate, &psks),
        );
        if let Some(row) = summary(experiment, "decrypt", count, &durations) {
            summaries.push(row);
        }
        add_size(
            sizes,
            experiment,
            "encrypt",
            count,
            "ciphertext",
            &ciphertext,
        )?;
        add_size(
            sizes,
            experiment,
            "decrypt",
            count,
            "intermediate_ciphertext",
            &intermediate,
        )?;
    }
    Ok(())
}

fn run_cpabe_keys(
    pp: &cpabe::PublicParamsV1,
    msk: &cpabe::MasterKeyV1,
    config: &Config,
    raw: &mut Vec<RawSample>,
    summaries: &mut Vec<SummaryRow>,
    sizes: &mut Vec<SizeRow>,
    errors: &mut Vec<ErrorRow>,
) -> Result<()> {
    let experiment = "D_cpabe_key_attributes";
    let source_attrs = attrs(50);
    let (source_pska, source_psks) = cpabe::keygen(pp, msk, &source_attrs)?;
    let message = fixed_message();
    let decrypt_ciphertext = cpabe::encrypt(pp, &one_distinct_attribute_label(), &message)?;

    for &count in &ATTRIBUTE_COUNTS {
        let current_attrs = attrs(count);
        let (reference_pska, reference_psks) = cpabe::keygen(pp, msk, &current_attrs)?;

        let durations = measure(
            experiment,
            "keygen",
            count,
            config.warmups,
            config.measurements,
            errors,
            raw,
            || cpabe::keygen(pp, msk, &current_attrs),
        );
        if let Some(row) = summary(experiment, "keygen", count, &durations) {
            summaries.push(row);
        }
        add_size(sizes, experiment, "keygen", count, "pska", &reference_pska)?;
        add_size(sizes, experiment, "keygen", count, "psks", &reference_psks)?;

        let delegated_attrs = current_attrs.clone();
        let (reference_delegated_psks, reference_tk) =
            cpabe::delegate(pp, &source_psks, &delegated_attrs)
                .with_context(|| format!("delegate preparation for N={count}"))?;
        let durations = measure(
            experiment,
            "delegate",
            count,
            config.warmups,
            config.measurements,
            errors,
            raw,
            || cpabe::delegate(pp, &source_psks, &delegated_attrs),
        );
        if let Some(row) = summary(experiment, "delegate", count, &durations) {
            summaries.push(row);
        }
        add_size(
            sizes,
            experiment,
            "delegate",
            count,
            "delegated_psks",
            &reference_delegated_psks,
        )?;
        add_size(sizes, experiment, "delegate", count, "tk", &reference_tk)?;

        let reference_delegated_pska = cpabe::tm_delegate(&source_pska, &reference_tk)?;
        let delegated_cti = cpabe::tm_decrypt(pp, &decrypt_ciphertext, &reference_delegated_pska)?;
        let delegated_plaintext = cpabe::decrypt(pp, &delegated_cti, &reference_delegated_psks)?;
        anyhow::ensure!(
            delegated_plaintext == message,
            "CP-ABE delegation round-trip failed for N={count}"
        );
        let durations = measure(
            experiment,
            "tm_delegate",
            count,
            config.warmups,
            config.measurements,
            errors,
            raw,
            || cpabe::tm_delegate(&source_pska, &reference_tk),
        );
        if let Some(row) = summary(experiment, "tm_delegate", count, &durations) {
            summaries.push(row);
        }
        add_size(
            sizes,
            experiment,
            "tm_delegate",
            count,
            "delegated_pska",
            &reference_delegated_pska,
        )?;

        // Le CP-ABE actuel encode deux feuilles. En répétant A1, on conserve
        // une politique fixe à un seul attribut distinct et on rend N=1
        // mesurable sans inventer une politique à une feuille.
        let cti = cpabe::tm_decrypt(pp, &decrypt_ciphertext, &reference_pska)?;
        let plaintext = cpabe::decrypt(pp, &cti, &reference_psks)?;
        anyhow::ensure!(
            plaintext == message,
            "CP-ABE fixed one-attribute round-trip failed"
        );
        let durations = measure(
            experiment,
            "decrypt",
            count,
            config.warmups,
            config.measurements,
            errors,
            raw,
            || cpabe::decrypt(pp, &cti, &reference_psks),
        );
        if let Some(row) = summary(experiment, "decrypt", count, &durations) {
            summaries.push(row);
        }
        add_size(sizes, experiment, "decrypt", count, "psks", &reference_psks)?;

        let tm_cti = cpabe::tm_decrypt(pp, &decrypt_ciphertext, &reference_pska)?;
        let durations = measure(
            experiment,
            "tm_decrypt",
            count,
            config.warmups,
            config.measurements,
            errors,
            raw,
            || cpabe::tm_decrypt(pp, &decrypt_ciphertext, &reference_pska),
        );
        if let Some(row) = summary(experiment, "tm_decrypt", count, &durations) {
            summaries.push(row);
        }
        add_size(
            sizes,
            experiment,
            "tm_decrypt",
            count,
            "intermediate_ciphertext",
            &tm_cti,
        )?;
    }
    Ok(())
}

fn write_csv(
    output_dir: &Path,
    raw: &[RawSample],
    summaries: &[SummaryRow],
    sizes: &[SizeRow],
    errors: &[ErrorRow],
) -> Result<()> {
    let mut raw_csv = String::from(
        "experiment,operation,attributes,user_attributes,delegated_attributes,policy_leaves,iteration,duration_ns\n",
    );
    for row in raw {
        let (user_attributes, delegated_attributes, policy_leaves) =
            scenario_dimensions(&row.experiment, &row.operation, row.attributes);
        raw_csv.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            csv_escape(&row.experiment),
            csv_escape(&row.operation),
            row.attributes,
            user_attributes,
            delegated_attributes,
            policy_leaves,
            row.iteration,
            row.duration_ns
        ));
    }
    fs::write(output_dir.join("timings_raw.csv"), raw_csv)?;

    let mut summary_csv = String::from(
        "experiment,operation,attributes,user_attributes,delegated_attributes,policy_leaves,valid_samples,mean_ms,median_ms,stddev_ms,min_ms,max_ms,p95_ms,stddev_convention,percentile_convention\n",
    );
    for row in summaries {
        let (user_attributes, delegated_attributes, policy_leaves) =
            scenario_dimensions(&row.experiment, &row.operation, row.attributes);
        summary_csv.push_str(&format!(
            "{},{},{},{},{},{},{},{:.9},{:.9},{:.9},{:.9},{:.9},{:.9},sample (n-1),nearest-rank ceil(0.95*n)\n",
            csv_escape(&row.experiment),
            csv_escape(&row.operation),
            row.attributes,
            user_attributes,
            delegated_attributes,
            policy_leaves,
            row.valid_samples,
            row.mean_ms,
            row.median_ms,
            row.stddev_ms,
            row.min_ms,
            row.max_ms,
            row.p95_ms
        ));
    }
    fs::write(output_dir.join("timings_summary.csv"), summary_csv)?;

    let mut sizes_csv = String::from(
        "experiment,operation,attributes,user_attributes,delegated_attributes,policy_leaves,object_type,size_bytes,representation\n",
    );
    for row in sizes {
        let (user_attributes, delegated_attributes, policy_leaves) =
            scenario_dimensions(&row.experiment, &row.operation, row.attributes);
        sizes_csv.push_str(&format!(
            "{},{},{},{},{},{},{},{},{}\n",
            csv_escape(&row.experiment),
            csv_escape(&row.operation),
            row.attributes,
            user_attributes,
            delegated_attributes,
            policy_leaves,
            csv_escape(&row.object_type),
            row.size_bytes,
            csv_escape(&row.representation)
        ));
    }
    fs::write(output_dir.join("sizes.csv"), sizes_csv)?;

    let mut errors_csv = String::from("experiment,operation,attributes,iteration,error\n");
    for row in errors {
        errors_csv.push_str(&format!(
            "{},{},{},{},{}\n",
            csv_escape(&row.experiment),
            csv_escape(&row.operation),
            row.attributes,
            row.iteration,
            csv_escape(&row.error)
        ));
    }
    fs::write(output_dir.join("errors.csv"), errors_csv)?;
    Ok(())
}

fn scenario_dimensions(
    experiment: &str,
    operation: &str,
    attributes: usize,
) -> (usize, usize, usize) {
    match experiment {
        "C_cpabe_policy_attributes" => {
            let user_attributes = if operation == "decrypt" { 50 } else { 0 };
            (user_attributes, 0, 2)
        }
        "D_cpabe_key_attributes" => match operation {
            "keygen" => (attributes, 0, 0),
            "delegate" | "tm_delegate" => (50, attributes, 0),
            "decrypt" | "tm_decrypt" => (attributes, 0, 2),
            _ => (attributes, 0, 0),
        },
        _ => (attributes, 0, 0),
    }
}

fn chart_color(index: usize) -> &'static str {
    [
        "#1b4f72", "#922b21", "#117864", "#7d3c98", "#b9770e", "#2c3e50", "#148f77", "#884c75",
        "#616a6b", "#ca6f1e", "#2874a6", "#943126",
    ][index % 12]
}

fn write_timing_plot(output_dir: &Path, summaries: &[SummaryRow]) -> Result<()> {
    write_line_plot(
        output_dir.join("timings_medians.svg"),
        "Médiane des temps cryptographiques",
        "Temps médian (ms)",
        summaries
            .iter()
            .map(|row| {
                (
                    row.experiment.clone(),
                    row.operation.clone(),
                    row.attributes,
                    row.median_ms,
                )
            })
            .collect(),
    )
}

fn write_size_plot(output_dir: &Path, sizes: &[SizeRow]) -> Result<()> {
    write_line_plot(
        output_dir.join("sizes.svg"),
        "Tailles sérialisées des objets cryptographiques",
        "Taille (octets)",
        sizes
            .iter()
            .map(|row| {
                (
                    row.experiment.clone(),
                    row.object_type.clone(),
                    row.attributes,
                    row.size_bytes as f64,
                )
            })
            .collect(),
    )
}

fn write_line_plot(
    path: PathBuf,
    title: &str,
    y_label: &str,
    points: Vec<(String, String, usize, f64)>,
) -> Result<()> {
    let width = 1200.0;
    let height = 700.0;
    let left = 90.0;
    let right = 40.0;
    let top = 70.0;
    let bottom = 100.0;
    let chart_width = width - left - right;
    let chart_height = height - top - bottom;
    let max_y = points
        .iter()
        .map(|(_, _, _, value)| *value)
        .fold(1.0_f64, f64::max);
    let x = |attributes: usize| {
        left + (ATTRIBUTE_COUNTS
            .iter()
            .position(|candidate| *candidate == attributes)
            .unwrap_or(0) as f64)
            * chart_width
            / (ATTRIBUTE_COUNTS.len() - 1) as f64
    };
    let y = |value: f64| top + chart_height - (value / max_y) * chart_height;

    let mut series: Vec<PlotSeries> = Vec::new();
    for (group, name, attributes, value) in points {
        if let Some(existing) = series.iter_mut().find(|(current_group, current_name, _)| {
            *current_group == group && *current_name == name
        }) {
            existing.2.push((attributes, value));
        } else {
            series.push((group, name, vec![(attributes, value)]));
        }
    }

    let mut svg = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{width}\" height=\"{height}\" viewBox=\"0 0 {width} {height}\">\n<rect width=\"100%\" height=\"100%\" fill=\"white\"/>\n<text x=\"{left}\" y=\"35\" font-family=\"sans-serif\" font-size=\"22\" font-weight=\"bold\">{title}</text>\n<text x=\"20\" y=\"{top}\" font-family=\"sans-serif\" font-size=\"14\" transform=\"rotate(-90 20 {top})\">{y_label}</text>\n<line x1=\"{left}\" y1=\"{top}\" x2=\"{left}\" y2=\"{}\" stroke=\"#333\"/>\n<line x1=\"{left}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"#333\"/>\n",
        top + chart_height,
        top + chart_height,
        left + chart_width,
        top + chart_height
    );
    for &attributes in &ATTRIBUTE_COUNTS {
        let x_value = x(attributes);
        svg.push_str(&format!(
            "<line x1=\"{x_value:.1}\" y1=\"{top}\" x2=\"{x_value:.1}\" y2=\"{}\" stroke=\"#e5e7e9\"/>\n<text x=\"{x_value:.1}\" y=\"{}\" text-anchor=\"middle\" font-family=\"sans-serif\" font-size=\"12\">{attributes}</text>\n",
            top + chart_height,
            top + chart_height + 22.0
        ));
    }
    for (index, (group, name, mut values)) in series.into_iter().enumerate() {
        values.sort_by_key(|(attributes, _)| *attributes);
        let color = chart_color(index);
        let polyline = values
            .iter()
            .map(|(attributes, value)| format!("{:.1},{:.1}", x(*attributes), y(*value)))
            .collect::<Vec<_>>()
            .join(" ");
        svg.push_str(&format!(
            "<polyline points=\"{polyline}\" fill=\"none\" stroke=\"{color}\" stroke-width=\"2\"/>\n"
        ));
        for (attributes, value) in values {
            svg.push_str(&format!(
                "<circle cx=\"{:.1}\" cy=\"{:.1}\" r=\"3\" fill=\"{color}\"/>\n",
                x(attributes),
                y(value)
            ));
        }
        let legend_y = top + 18.0 + index as f64 * 18.0;
        svg.push_str(&format!(
            "<line x1=\"{}\" y1=\"{legend_y:.1}\" x2=\"{}\" y2=\"{legend_y:.1}\" stroke=\"{color}\" stroke-width=\"3\"/><text x=\"{}\" y=\"{}\" font-family=\"sans-serif\" font-size=\"12\">{group} / {name}</text>\n",
            width - 330.0,
            width - 310.0,
            width - 300.0,
            legend_y + 4.0
        ));
    }
    svg.push_str("</svg>\n");
    fs::write(path, svg)?;
    Ok(())
}

fn command_output(command: &str, args: &[&str]) -> String {
    Command::new(command)
        .args(args)
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .unwrap_or_else(|| "unavailable".to_string())
}

fn write_metadata(output_dir: &Path, config: &Config, system_id: &str) -> Result<()> {
    let git_status = command_output("git", &["status", "--porcelain"]);
    let metadata = Metadata {
        benchmark: "D3CS cryptographic attribute-count campaign",
        version: env!("CARGO_PKG_VERSION"),
        cryptographic_version: "2",
        curve: "BLS12-381",
        hash_to_curve: "G2, deterministic hash-to-curve",
        attribute_counts: ATTRIBUTE_COUNTS.to_vec(),
        warmups: config.warmups,
        measurements: config.measurements,
        message_size_bytes: MESSAGE_SIZE,
        duration_unit_raw: "nanoseconds from std::time::Instant",
        duration_unit_summary: "milliseconds",
        stddev: "sample standard deviation with denominator n-1",
        percentile: "nearest-rank, rank=ceil(0.95*n)",
        rustc: command_output("rustc", &["--version"]),
        target_os: std::env::consts::OS,
        target_arch: std::env::consts::ARCH,
        processor: command_output(
            "bash",
            &[
                "-lc",
                "lscpu | sed -n '/Model name/ { s/^[^:]*:[[:space:]]*//; p; q; }'",
            ],
        ),
        build_mode: "release",
        git_revision: command_output("git", &["rev-parse", "HEAD"]),
        git_worktree: if git_status == "unavailable" {
            git_status
        } else if git_status.is_empty() {
            "clean".to_string()
        } else {
            "modified".to_string()
        },
        dependencies: command_output("cargo", &["tree", "--depth", "1"]),
        system_id: system_id.to_string(),
        policy_leaves: 2,
        limitations: vec![
            "ABS is implemented with d=1 and one attribute per user key; ABS multi-attribute experiments are therefore exported as unsupported.",
            "CP-ABE encrypt/decrypt currently implement exactly two leaves with fixed two-leaf reconstruction.",
            "CP-ABE tm_delegate and tm_decrypt consume PSKA/TK or ciphertext/PSKA, not an attribute list; their N labels describe preparation provenance, not an N-dependent input size.",
            "The D decrypt policy uses A1 AND A1 because the CP-ABE API cannot encode a one-leaf policy; only one distinct attribute is required.",
        ],
    };
    fs::write(
        output_dir.join("metadata.json"),
        serde_json::to_vec_pretty(&metadata)?,
    )?;
    Ok(())
}

fn main() -> Result<()> {
    let config = parse_args()?;
    fs::create_dir_all(&config.output_dir)?;
    let (abs_params, abs_msk) = abs::setup().context("ABS setup")?;
    let (cpabe_pp, cpabe_msk) = cpabe::setup().context("CP-ABE setup")?;

    let mut raw = Vec::new();
    let mut summaries = Vec::new();
    let mut sizes = Vec::new();
    let mut errors = Vec::new();

    if experiment_selected(&config, "abs-user-set") {
        run_abs_user_set(
            &abs_params,
            &abs_msk,
            &config,
            &mut raw,
            &mut summaries,
            &mut sizes,
            &mut errors,
        )?;
    }
    if experiment_selected(&config, "abs-predicate") {
        run_abs_predicate(
            &abs_params,
            &abs_msk,
            &config,
            &mut raw,
            &mut summaries,
            &mut sizes,
            &mut errors,
        )?;
    }
    if experiment_selected(&config, "cpabe-policy") {
        run_cpabe_policy(
            &cpabe_pp,
            &cpabe_msk,
            &config,
            &mut raw,
            &mut summaries,
            &mut sizes,
            &mut errors,
        )?;
    }
    if experiment_selected(&config, "cpabe-keys") {
        run_cpabe_keys(
            &cpabe_pp,
            &cpabe_msk,
            &config,
            &mut raw,
            &mut summaries,
            &mut sizes,
            &mut errors,
        )?;
    }

    write_csv(&config.output_dir, &raw, &summaries, &sizes, &errors)?;
    write_metadata(&config.output_dir, &config, &cpabe_pp.system_id)?;
    if config.plots {
        write_timing_plot(&config.output_dir, &summaries)?;
        write_size_plot(&config.output_dir, &sizes)?;
    }

    println!(
        "Campagne terminée: {} mesures valides, {} erreurs, sortie {}",
        raw.len(),
        errors.len(),
        config.output_dir.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribute_sets_have_expected_distinct_values() {
        for &count in &ATTRIBUTE_COUNTS {
            let values = attrs(count);
            assert_eq!(values.len(), count);
            assert_eq!(
                values
                    .iter()
                    .collect::<std::collections::HashSet<_>>()
                    .len(),
                count
            );
            assert_eq!(values.first().map(String::as_str), Some("A1"));
        }
    }

    #[test]
    fn fixed_message_has_constant_size() {
        assert_eq!(fixed_message().len(), MESSAGE_SIZE);
    }

    #[test]
    fn csv_escaping_is_stable() {
        assert_eq!(csv_escape("plain"), "plain");
        assert_eq!(csv_escape("a,b\"c"), "\"a,b\"\"c\"");
    }

    #[test]
    fn statistics_use_nearest_rank_p95() {
        let values: Vec<u128> = (1..=100).collect();
        assert_eq!(percentile(&values, 95, 100), 95.0);
        let row = summary("e", "op", 1, &values).unwrap();
        assert_eq!(row.valid_samples, 100);
        assert!((row.median_ms - 0.0000505).abs() < 1e-12);
    }

    #[test]
    fn one_distinct_attribute_policy_is_explicitly_repeated() {
        let label = one_distinct_attribute_label();
        assert_eq!(label.classification, ABS_ATTRIBUTE);
        assert_eq!(label.mission, ABS_ATTRIBUTE);
    }

    #[test]
    fn csv_export_writes_expected_headers() -> Result<()> {
        let output = std::env::temp_dir().join(format!(
            "d3cs-attribute-benchmark-test-{}",
            std::process::id()
        ));
        fs::create_dir_all(&output)?;
        write_csv(&output, &[], &[], &[], &[])?;
        assert_eq!(
            fs::read_to_string(output.join("timings_raw.csv"))?,
            "experiment,operation,attributes,user_attributes,delegated_attributes,policy_leaves,iteration,duration_ns\n"
        );
        assert_eq!(
            fs::read_to_string(output.join("errors.csv"))?,
            "experiment,operation,attributes,iteration,error\n"
        );
        fs::remove_dir_all(output)?;
        Ok(())
    }

    #[test]
    fn real_crypto_round_trips_in_the_benchmark_shape() -> Result<()> {
        let (pp, msk) = cpabe::setup()?;
        let (pska, psks) = cpabe::keygen(&pp, &msk, &attrs(1))?;
        let message = fixed_message();
        let ct = cpabe::encrypt(&pp, &one_distinct_attribute_label(), &message)?;
        let cti = cpabe::tm_decrypt(&pp, &ct, &pska)?;
        assert_eq!(cpabe::decrypt(&pp, &cti, &psks)?, message);

        let (params, abs_msk) = abs::setup()?;
        let key = abs::extract(&params, &abs_msk, ABS_ATTRIBUTE)?;
        let signature = abs::sign(&params, &key, b"benchmark")?;
        assert!(abs::verify_with_attr(
            &params,
            &signature,
            b"benchmark",
            ABS_ATTRIBUTE
        )?);
        Ok(())
    }
}
