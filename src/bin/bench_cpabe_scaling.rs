use std::{
    collections::BTreeMap,
    env,
    fs::{self, File},
    hint::black_box,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

use anyhow::{anyhow, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use chrono::Utc;
use serde::{Deserialize, Serialize};

#[path = "../crypto/cpabe.rs"]
mod cpabe;

#[derive(Clone, Serialize, Deserialize)]
pub struct DocumentLabel {
    pub classification: String,
    pub mission: String,
}

const CARDINALITIES: [usize; 6] = [1, 2, 5, 10, 20, 50];
const DEFAULT_WARMUPS: usize = 100;
const DEFAULT_MEASUREMENTS: usize = 500;
const DEFAULT_CAMPAIGNS: usize = 3;
const DEFAULT_SEED: u64 = 0xD3C5_5A5A_2026_050A;
const DEFAULT_OUTPUT_DIR: &str = "results/cpabe/scaling";
const PLAINTEXT: &str = "test";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Selection {
    All,
    Attributes,
    Delegation,
    Policy,
}

#[derive(Clone, Debug)]
struct Config {
    warmups: usize,
    measurements: usize,
    campaigns: usize,
    seed: u64,
    output_dir: PathBuf,
    selection: Selection,
}

#[derive(Debug)]
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self { state: seed.max(1) }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn shuffle<T>(&mut self, values: &mut [T]) {
        for index in (1..values.len()).rev() {
            let other = (self.next_u64() as usize) % (index + 1);
            values.swap(index, other);
        }
    }
}

#[derive(Serialize)]
struct RawRow {
    campaign_id: usize,
    experiment: &'static str,
    operation: &'static str,
    n: usize,
    iteration: usize,
    duration_ns: u128,
    success: bool,
}

#[derive(Serialize)]
struct ErrorRow {
    campaign_id: usize,
    experiment: &'static str,
    operation: &'static str,
    n: usize,
    phase: &'static str,
    iteration: usize,
    error: String,
}

#[derive(Serialize)]
struct SummaryRow {
    campaign_id: String,
    scope: &'static str,
    experiment: String,
    operation: String,
    n: usize,
    valid_samples: usize,
    failed_samples: usize,
    mean_ns: f64,
    median_ns: f64,
    stddev_ns: f64,
    min_ns: u128,
    max_ns: u128,
    p95_ns: u128,
}

#[derive(Serialize)]
struct SizeRow {
    campaign_id: usize,
    experiment: &'static str,
    operation: &'static str,
    n: usize,
    user_attributes: usize,
    delegated_attributes: usize,
    policy_leaves: usize,
    object_type: &'static str,
    serialized_json_bytes: usize,
    decoded_base64_bytes: usize,
    decoded_abe_bytes: usize,
}

#[derive(Default)]
struct Outputs {
    raw: Vec<RawRow>,
    errors: Vec<ErrorRow>,
    summaries: Vec<SummaryRow>,
    sizes: Vec<SizeRow>,
}

#[derive(Default)]
struct MeasurementResult {
    durations_ns: Vec<u128>,
    failed_samples: usize,
}

#[derive(Serialize)]
struct Metadata {
    benchmark: &'static str,
    format_version: &'static str,
    crypto_version: &'static str,
    curve: &'static str,
    hash_to_curve: &'static str,
    attribute_encoding: &'static str,
    cardinalities: Vec<usize>,
    experiments: Vec<&'static str>,
    warmups: usize,
    measurements: usize,
    campaigns: usize,
    seed: u64,
    selection_order: &'static str,
    raw_time_unit: &'static str,
    summary_time_unit: &'static str,
    plaintext_bytes: usize,
    build_mode: &'static str,
    generated_at_utc: String,
    rustc: String,
    operating_system: String,
    architecture: String,
    processor: String,
    git_commit: String,
    git_worktree: String,
    dependency_snapshot: String,
    system_ids: Vec<String>,
    timing_scope: Vec<&'static str>,
    limitations: Vec<&'static str>,
}

fn attributes(count: usize) -> Vec<String> {
    (1..=count).map(|index| format!("A{index:04}")).collect()
}

fn ordered_cardinalities(seed: u64, campaign_id: usize) -> Vec<usize> {
    let mut values = CARDINALITIES.to_vec();
    let mut rng = XorShift64::new(seed ^ (campaign_id as u64).wrapping_mul(0x9E37_79B9));
    rng.shuffle(&mut values);
    values
}

fn delegated_subset(seed: u64, campaign_id: usize, count: usize) -> Vec<String> {
    let mut values = attributes(50);
    let mixed_seed = seed
        ^ (campaign_id as u64).wrapping_mul(0xA5A5_5A5A)
        ^ (count as u64).wrapping_mul(0xD1B5_4A32);
    XorShift64::new(mixed_seed).shuffle(&mut values);
    values.truncate(count);
    values.sort();
    values
}

fn parse_usize(value: Option<&str>, name: &str) -> Result<usize> {
    value
        .ok_or_else(|| anyhow!("valeur manquante pour {name}"))?
        .parse()
        .with_context(|| format!("valeur invalide pour {name}"))
}

fn parse_u64(value: Option<&str>, name: &str) -> Result<u64> {
    let text = value.ok_or_else(|| anyhow!("valeur manquante pour {name}"))?;
    if let Some(hex) = text.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).with_context(|| format!("valeur invalide pour {name}"))
    } else {
        text.parse()
            .with_context(|| format!("valeur invalide pour {name}"))
    }
}

fn usage() -> &'static str {
    "bench_cpabe_scaling [options]
  --warmups N          Nombre de warmups par operation
  --measurements N     Nombre de mesures par operation
  --campaigns N        Nombre de campagnes independantes
  --seed N              Graine de l'ordre controle (decimal ou 0x...)
  --output-dir PATH     Repertoire de sortie
  --only all|A|B|C      Selectionner les experiences
  --smoke               1 warmup, 1 mesure, 1 campagne
  --help                Afficher cette aide"
}

fn parse_config() -> Result<Config> {
    let mut config = Config {
        warmups: DEFAULT_WARMUPS,
        measurements: DEFAULT_MEASUREMENTS,
        campaigns: DEFAULT_CAMPAIGNS,
        seed: DEFAULT_SEED,
        output_dir: PathBuf::from(DEFAULT_OUTPUT_DIR),
        selection: Selection::All,
    };
    let args: Vec<String> = env::args().skip(1).collect();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--warmups" => {
                config.warmups = parse_usize(args.get(index + 1).map(String::as_str), "--warmups")?;
                index += 2;
            }
            "--measurements" => {
                config.measurements =
                    parse_usize(args.get(index + 1).map(String::as_str), "--measurements")?;
                index += 2;
            }
            "--campaigns" => {
                config.campaigns =
                    parse_usize(args.get(index + 1).map(String::as_str), "--campaigns")?;
                index += 2;
            }
            "--seed" => {
                config.seed = parse_u64(args.get(index + 1).map(String::as_str), "--seed")?;
                index += 2;
            }
            "--output-dir" => {
                config.output_dir = PathBuf::from(
                    args.get(index + 1)
                        .ok_or_else(|| anyhow!("valeur manquante pour --output-dir"))?,
                );
                index += 2;
            }
            "--only" => {
                config.selection = match args
                    .get(index + 1)
                    .ok_or_else(|| anyhow!("valeur manquante pour --only"))?
                    .as_str()
                {
                    "all" => Selection::All,
                    "A" | "a" => Selection::Attributes,
                    "B" | "b" => Selection::Delegation,
                    "C" | "c" => Selection::Policy,
                    other => return Err(anyhow!("selection inconnue: {other}")),
                };
                index += 2;
            }
            "--smoke" => {
                config.warmups = 1;
                config.measurements = 1;
                config.campaigns = 1;
                index += 1;
            }
            "--help" | "-h" => {
                println!("{}", usage());
                std::process::exit(0);
            }
            other => return Err(anyhow!("option inconnue: {other}\n\n{}", usage())),
        }
    }
    ensure!(config.warmups > 0, "--warmups doit etre positif");
    ensure!(config.measurements > 0, "--measurements doit etre positif");
    ensure!(config.campaigns > 0, "--campaigns doit etre positif");
    Ok(config)
}

fn serialized_size<T: Serialize>(value: &T) -> Result<usize> {
    Ok(serde_json::to_vec(value)?.len())
}

fn decoded_field_size(value: &str) -> Result<usize> {
    Ok(STANDARD_NO_PAD.decode(value)?.len())
}

fn write_csv<T: Serialize>(path: &Path, rows: &[T]) -> Result<()> {
    let mut file = File::create(path).with_context(|| format!("creation de {}", path.display()))?;
    if rows.is_empty() {
        return Ok(());
    }
    let value = serde_json::to_value(&rows[0])?;
    let headers = value
        .as_object()
        .ok_or_else(|| anyhow!("ligne CSV non objet"))?
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    writeln!(file, "{}", headers.join(","))?;
    for row in rows {
        let object = serde_json::to_value(row)?
            .as_object()
            .cloned()
            .ok_or_else(|| anyhow!("ligne CSV non objet"))?;
        let cells = headers
            .iter()
            .map(|header| csv_cell(object.get(header)))
            .collect::<Vec<_>>();
        writeln!(file, "{}", cells.join(","))?;
    }
    Ok(())
}

fn csv_cell(value: Option<&serde_json::Value>) -> String {
    let raw = match value {
        None | Some(serde_json::Value::Null) => String::new(),
        Some(serde_json::Value::String(text)) => text.clone(),
        Some(other) => other.to_string(),
    };
    if raw.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", raw.replace('"', "\"\""))
    } else {
        raw
    }
}

fn record_error(
    outputs: &mut Outputs,
    campaign_id: usize,
    experiment: &'static str,
    operation: &'static str,
    n: usize,
    phase: &'static str,
    iteration: usize,
    error: impl std::fmt::Display,
) {
    outputs.errors.push(ErrorRow {
        campaign_id,
        experiment,
        operation,
        n,
        phase,
        iteration,
        error: error.to_string(),
    });
}

fn measure_op<T, F, V>(
    outputs: &mut Outputs,
    campaign_id: usize,
    experiment: &'static str,
    operation: &'static str,
    n: usize,
    warmups: usize,
    measurements: usize,
    mut operation_fn: F,
    mut validate: V,
) -> MeasurementResult
where
    F: FnMut() -> Result<T>,
    V: FnMut(&T) -> Result<()>,
{
    for iteration in 0..warmups {
        match operation_fn() {
            Ok(value) => {
                if let Err(error) = validate(&value) {
                    record_error(
                        outputs,
                        campaign_id,
                        experiment,
                        operation,
                        n,
                        "warmup_validation",
                        iteration,
                        error,
                    );
                }
                black_box(value);
            }
            Err(error) => record_error(
                outputs,
                campaign_id,
                experiment,
                operation,
                n,
                "warmup_operation",
                iteration,
                error,
            ),
        }
    }

    let mut result = MeasurementResult::default();
    for iteration in 0..measurements {
        let started = Instant::now();
        let value = operation_fn();
        let duration_ns = started.elapsed().as_nanos();
        match value {
            Ok(value) => {
                let valid = validate(&value);
                outputs.raw.push(RawRow {
                    campaign_id,
                    experiment,
                    operation,
                    n,
                    iteration,
                    duration_ns,
                    success: valid.is_ok(),
                });
                if let Err(error) = valid {
                    result.failed_samples += 1;
                    record_error(
                        outputs,
                        campaign_id,
                        experiment,
                        operation,
                        n,
                        "measurement_validation",
                        iteration,
                        error,
                    );
                } else {
                    result.durations_ns.push(duration_ns);
                }
                black_box(value);
            }
            Err(error) => {
                result.failed_samples += 1;
                outputs.raw.push(RawRow {
                    campaign_id,
                    experiment,
                    operation,
                    n,
                    iteration,
                    duration_ns,
                    success: false,
                });
                record_error(
                    outputs,
                    campaign_id,
                    experiment,
                    operation,
                    n,
                    "measurement_operation",
                    iteration,
                    error,
                );
            }
        }
    }
    result
}

fn median(sorted: &[u128]) -> f64 {
    let middle = sorted.len() / 2;
    if sorted.len() % 2 == 0 {
        (sorted[middle - 1] as f64 + sorted[middle] as f64) / 2.0
    } else {
        sorted[middle] as f64
    }
}

fn statistics(values: &[u128]) -> Result<(f64, f64, f64, u128, u128, u128)> {
    ensure!(!values.is_empty(), "aucun echantillon valide");
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let mean = sorted.iter().map(|value| *value as f64).sum::<f64>() / sorted.len() as f64;
    let variance = if sorted.len() > 1 {
        sorted
            .iter()
            .map(|value| {
                let difference = *value as f64 - mean;
                difference * difference
            })
            .sum::<f64>()
            / (sorted.len() - 1) as f64
    } else {
        0.0
    };
    let rank = ((sorted.len() as f64) * 0.95).ceil().max(1.0) as usize;
    Ok((
        mean,
        median(&sorted),
        variance.sqrt(),
        sorted[0],
        sorted[sorted.len() - 1],
        sorted[rank - 1],
    ))
}

fn push_summary(
    outputs: &mut Outputs,
    campaign_id: usize,
    experiment: &'static str,
    operation: &'static str,
    n: usize,
    result: &MeasurementResult,
    total_samples: usize,
) -> Result<()> {
    if result.durations_ns.is_empty() {
        return Ok(());
    }
    let (mean_ns, median_ns, stddev_ns, min_ns, max_ns, p95_ns) = statistics(&result.durations_ns)?;
    outputs.summaries.push(SummaryRow {
        campaign_id: campaign_id.to_string(),
        scope: "campaign",
        experiment: experiment.to_string(),
        operation: operation.to_string(),
        n,
        valid_samples: result.durations_ns.len(),
        failed_samples: total_samples - result.durations_ns.len(),
        mean_ns,
        median_ns,
        stddev_ns,
        min_ns,
        max_ns,
        p95_ns,
    });
    Ok(())
}

fn validate_keygen(
    pp: &cpabe::PublicParamsV1,
    expected_attrs: &[String],
    keys: &(cpabe::PskaV1, cpabe::PsksV1),
) -> Result<()> {
    cpabe::validate_pska_for_pp(pp, &keys.0)?;
    cpabe::validate_psks_for_pp(pp, &keys.1)?;
    let mut expected = expected_attrs.to_vec();
    expected.sort();
    let mut actual = keys
        .1
        .attrs
        .iter()
        .map(|entry| entry.attr.clone())
        .collect::<Vec<_>>();
    actual.sort();
    ensure!(actual == expected, "attributs PSKS inattendus");
    Ok(())
}

fn validate_delegate(
    pp: &cpabe::PublicParamsV1,
    expected_attrs: &[String],
    delegated: &(cpabe::PsksV1, cpabe::TkV1),
) -> Result<()> {
    cpabe::validate_psks_for_pp(pp, &delegated.0)?;
    let expected_id = cpabe::public_params_id(pp)?;
    ensure!(delegated.1.version == 2, "version TK inattendue");
    ensure!(
        delegated.1.system_id == expected_id,
        "system_id TK inattendu"
    );
    let mut expected = expected_attrs.to_vec();
    expected.sort();
    let mut actual = delegated
        .0
        .attrs
        .iter()
        .map(|entry| entry.attr.clone())
        .collect::<Vec<_>>();
    actual.sort();
    ensure!(actual == expected, "attributs delegues inattendus");
    Ok(())
}

fn validate_encrypt(
    pp: &cpabe::PublicParamsV1,
    expected_leaves: usize,
    ciphertext: &cpabe::CiphertextV1,
) -> Result<()> {
    cpabe::validate_ciphertext_for_pp(pp, ciphertext)?;
    ensure!(
        ciphertext.abe.leafs.len() == expected_leaves,
        "nombre de feuilles inattendu"
    );
    Ok(())
}

fn validate_intermediate(
    pp: &cpabe::PublicParamsV1,
    expected_leaves: usize,
    intermediate: &cpabe::IntermediateCiphertextV1,
) -> Result<()> {
    let expected_id = cpabe::public_params_id(pp)?;
    ensure!(
        intermediate.version == 2,
        "version intermediaire inattendue"
    );
    ensure!(
        intermediate.system_id == expected_id,
        "system_id intermediaire inattendu"
    );
    ensure!(
        intermediate.abe.leafs.len() == expected_leaves,
        "nombre de feuilles intermediaires inattendu"
    );
    Ok(())
}

fn validate_plaintext(expected: &str, actual: &String) -> Result<()> {
    ensure!(actual == expected, "plaintext inattendu");
    Ok(())
}

fn add_size_row(
    outputs: &mut Outputs,
    campaign_id: usize,
    experiment: &'static str,
    operation: &'static str,
    n: usize,
    dimensions: (usize, usize, usize),
    object_type: &'static str,
    value: &impl Serialize,
    encoded_fields: &[&str],
    abe_fields: &[&str],
) -> Result<()> {
    let decoded_base64_bytes = encoded_fields
        .iter()
        .map(|field| decoded_field_size(field))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .sum();
    let decoded_abe_bytes = abe_fields
        .iter()
        .map(|field| decoded_field_size(field))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .sum();
    outputs.sizes.push(SizeRow {
        campaign_id,
        experiment,
        operation,
        n,
        user_attributes: dimensions.0,
        delegated_attributes: dimensions.1,
        policy_leaves: dimensions.2,
        object_type,
        serialized_json_bytes: serialized_size(value)?,
        decoded_base64_bytes,
        decoded_abe_bytes,
    });
    Ok(())
}

fn add_pp_and_msk_sizes(
    outputs: &mut Outputs,
    campaign_id: usize,
    pp: &cpabe::PublicParamsV1,
    msk: &cpabe::MasterKeyV1,
) -> Result<()> {
    add_size_row(
        outputs,
        campaign_id,
        "all",
        "Setup",
        0,
        (0, 0, 0),
        "PP",
        pp,
        &[&pp.g, &pp.g2, &pp.h, &pp.f, &pp.f2, &pp.y],
        &[&pp.g, &pp.g2, &pp.h, &pp.f, &pp.f2, &pp.y],
    )?;
    add_size_row(
        outputs,
        campaign_id,
        "all",
        "Setup",
        0,
        (0, 0, 0),
        "MSK",
        msk,
        &[&msk.alpha, &msk.beta],
        &[&msk.alpha, &msk.beta],
    )
}

fn add_pska_size(
    outputs: &mut Outputs,
    campaign_id: usize,
    experiment: &'static str,
    operation: &'static str,
    n: usize,
    user_attributes: usize,
    value: &cpabe::PskaV1,
) -> Result<()> {
    add_size_row(
        outputs,
        campaign_id,
        experiment,
        operation,
        n,
        (user_attributes, 0, 0),
        "PSKA",
        value,
        &[&value.d],
        &[&value.d],
    )
}

fn add_psks_size(
    outputs: &mut Outputs,
    campaign_id: usize,
    experiment: &'static str,
    operation: &'static str,
    n: usize,
    user_attributes: usize,
    delegated_attributes: usize,
    value: &cpabe::PsksV1,
    object_type: &'static str,
) -> Result<()> {
    let mut encoded = Vec::with_capacity(2 * value.attrs.len());
    for entry in &value.attrs {
        encoded.push(entry.d.as_str());
        encoded.push(entry.d_prime.as_str());
    }
    add_size_row(
        outputs,
        campaign_id,
        experiment,
        operation,
        n,
        (user_attributes, delegated_attributes, 0),
        object_type,
        value,
        &encoded,
        &encoded,
    )
}

fn add_tk_size(
    outputs: &mut Outputs,
    campaign_id: usize,
    experiment: &'static str,
    n: usize,
    value: &cpabe::TkV1,
) -> Result<()> {
    add_size_row(
        outputs,
        campaign_id,
        experiment,
        "Delegate",
        n,
        (50, n, 0),
        "TK",
        value,
        &[&value.t],
        &[&value.t],
    )
}

fn add_ciphertext_size(
    outputs: &mut Outputs,
    campaign_id: usize,
    experiment: &'static str,
    n: usize,
    value: &cpabe::CiphertextV1,
) -> Result<()> {
    let mut encoded = vec![
        value.abe.c_tilde.as_str(),
        value.abe.c.as_str(),
        value.sym.nonce.as_str(),
        value.sym.ciphertext.as_str(),
    ];
    let mut abe = vec![value.abe.c_tilde.as_str(), value.abe.c.as_str()];
    for leaf in &value.abe.leafs {
        encoded.push(leaf.c_i.as_str());
        encoded.push(leaf.c_i_prime.as_str());
        abe.push(leaf.c_i.as_str());
        abe.push(leaf.c_i_prime.as_str());
    }
    add_size_row(
        outputs,
        campaign_id,
        experiment,
        "Encrypt_with_policy",
        n,
        (50, 0, n),
        "ciphertext",
        value,
        &encoded,
        &abe,
    )
}

fn add_intermediate_size(
    outputs: &mut Outputs,
    campaign_id: usize,
    experiment: &'static str,
    n: usize,
    value: &cpabe::IntermediateCiphertextV1,
) -> Result<()> {
    let mut encoded = vec![
        value.abe.c_tilde.as_str(),
        value.abe.f.as_str(),
        value.sym.nonce.as_str(),
        value.sym.ciphertext.as_str(),
    ];
    let mut abe = vec![value.abe.c_tilde.as_str(), value.abe.f.as_str()];
    for leaf in &value.abe.leafs {
        encoded.push(leaf.c_i.as_str());
        encoded.push(leaf.c_i_prime.as_str());
        abe.push(leaf.c_i.as_str());
        abe.push(leaf.c_i_prime.as_str());
    }
    add_size_row(
        outputs,
        campaign_id,
        experiment,
        "TM_Decrypt",
        n,
        (50, 0, n),
        "intermediate_ciphertext",
        value,
        &encoded,
        &abe,
    )
}

fn run_experiment_a(
    config: &Config,
    campaign_id: usize,
    pp: &cpabe::PublicParamsV1,
    msk: &cpabe::MasterKeyV1,
    outputs: &mut Outputs,
) -> Result<()> {
    const EXPERIMENT: &str = "A_user_attribute_count";
    for n in ordered_cardinalities(config.seed, campaign_id) {
        let attrs = attributes(n);
        let reference = cpabe::keygen(pp, msk, &attrs)?;
        validate_keygen(pp, &attrs, &reference)?;
        let result = measure_op(
            outputs,
            campaign_id,
            EXPERIMENT,
            "KeyGen",
            n,
            config.warmups,
            config.measurements,
            || cpabe::keygen(pp, msk, &attrs),
            |value| validate_keygen(pp, &attrs, value),
        );
        push_summary(
            outputs,
            campaign_id,
            EXPERIMENT,
            "KeyGen",
            n,
            &result,
            config.measurements,
        )?;
        add_pska_size(
            outputs,
            campaign_id,
            EXPERIMENT,
            "KeyGen",
            n,
            n,
            &reference.0,
        )?;
        add_psks_size(
            outputs,
            campaign_id,
            EXPERIMENT,
            "KeyGen",
            n,
            n,
            0,
            &reference.1,
            "PSKS",
        )?;
    }
    Ok(())
}

fn run_experiment_b(
    config: &Config,
    campaign_id: usize,
    pp: &cpabe::PublicParamsV1,
    msk: &cpabe::MasterKeyV1,
    outputs: &mut Outputs,
) -> Result<()> {
    const EXPERIMENT: &str = "B_delegated_attribute_count";
    let source_attrs = attributes(50);
    let source_keys = cpabe::keygen(pp, msk, &source_attrs)?;
    validate_keygen(pp, &source_attrs, &source_keys)?;
    add_psks_size(
        outputs,
        campaign_id,
        EXPERIMENT,
        "KeyGen",
        50,
        50,
        50,
        &source_keys.1,
        "source_PSKS",
    )?;

    for n in ordered_cardinalities(config.seed ^ 0xBEEF, campaign_id) {
        let selected = delegated_subset(config.seed, campaign_id, n);
        let reference = cpabe::delegate(pp, &source_keys.1, &selected)?;
        validate_delegate(pp, &selected, &reference)?;
        let result = measure_op(
            outputs,
            campaign_id,
            EXPERIMENT,
            "Delegate",
            n,
            config.warmups,
            config.measurements,
            || cpabe::delegate(pp, &source_keys.1, &selected),
            |value| validate_delegate(pp, &selected, value),
        );
        push_summary(
            outputs,
            campaign_id,
            EXPERIMENT,
            "Delegate",
            n,
            &result,
            config.measurements,
        )?;
        add_psks_size(
            outputs,
            campaign_id,
            EXPERIMENT,
            "Delegate",
            n,
            50,
            n,
            &reference.0,
            "delegated_PSKS",
        )?;
        add_tk_size(outputs, campaign_id, EXPERIMENT, n, &reference.1)?;

        let delegated_pska = cpabe::tm_delegate(&source_keys.0, &reference.1)?;
        cpabe::validate_pska_for_pp(pp, &delegated_pska)?;
        let result = measure_op(
            outputs,
            campaign_id,
            EXPERIMENT,
            "TM_Delegate",
            n,
            config.warmups,
            config.measurements,
            || cpabe::tm_delegate(&source_keys.0, &reference.1),
            |value| cpabe::validate_pska_for_pp(pp, value),
        );
        push_summary(
            outputs,
            campaign_id,
            EXPERIMENT,
            "TM_Delegate",
            n,
            &result,
            config.measurements,
        )?;
        add_pska_size(
            outputs,
            campaign_id,
            EXPERIMENT,
            "TM_Delegate",
            n,
            n,
            &delegated_pska,
        )?;
    }
    Ok(())
}

fn run_experiment_c(
    config: &Config,
    campaign_id: usize,
    pp: &cpabe::PublicParamsV1,
    msk: &cpabe::MasterKeyV1,
    outputs: &mut Outputs,
) -> Result<()> {
    const EXPERIMENT: &str = "C_policy_leaf_count";
    let user_attrs = attributes(50);
    let keys = cpabe::keygen(pp, msk, &user_attrs)?;
    validate_keygen(pp, &user_attrs, &keys)?;
    let label = DocumentLabel {
        classification: "BENCH-CLASSIFICATION".to_string(),
        mission: "BENCH-MISSION".to_string(),
    };

    for n in ordered_cardinalities(config.seed ^ 0xCAFE, campaign_id) {
        let policy_attrs = attributes(n);
        let policy = cpabe::AndPolicy::new(policy_attrs.clone())?;
        let reference_ct = cpabe::encrypt_with_policy(pp, &label, &policy, PLAINTEXT)?;
        validate_encrypt(pp, n, &reference_ct)?;
        let result = measure_op(
            outputs,
            campaign_id,
            EXPERIMENT,
            "Encrypt_with_policy",
            n,
            config.warmups,
            config.measurements,
            || cpabe::encrypt_with_policy(pp, &label, &policy, PLAINTEXT),
            |value| validate_encrypt(pp, n, value),
        );
        push_summary(
            outputs,
            campaign_id,
            EXPERIMENT,
            "Encrypt_with_policy",
            n,
            &result,
            config.measurements,
        )?;
        add_ciphertext_size(outputs, campaign_id, EXPERIMENT, n, &reference_ct)?;

        let reference_intermediate = cpabe::tm_decrypt(pp, &reference_ct, &keys.0)?;
        validate_intermediate(pp, n, &reference_intermediate)?;
        let result = measure_op(
            outputs,
            campaign_id,
            EXPERIMENT,
            "TM_Decrypt",
            n,
            config.warmups,
            config.measurements,
            || cpabe::tm_decrypt(pp, &reference_ct, &keys.0),
            |value| validate_intermediate(pp, n, value),
        );
        push_summary(
            outputs,
            campaign_id,
            EXPERIMENT,
            "TM_Decrypt",
            n,
            &result,
            config.measurements,
        )?;
        add_intermediate_size(outputs, campaign_id, EXPERIMENT, n, &reference_intermediate)?;

        let reference_plaintext = cpabe::decrypt(pp, &reference_intermediate, &keys.1)?;
        validate_plaintext(PLAINTEXT, &reference_plaintext)?;
        let result = measure_op(
            outputs,
            campaign_id,
            EXPERIMENT,
            "Decrypt",
            n,
            config.warmups,
            config.measurements,
            || cpabe::decrypt(pp, &reference_intermediate, &keys.1),
            |value| validate_plaintext(PLAINTEXT, value),
        );
        push_summary(
            outputs,
            campaign_id,
            EXPERIMENT,
            "Decrypt",
            n,
            &result,
            config.measurements,
        )?;
    }
    Ok(())
}

fn add_pooled_summaries(outputs: &mut Outputs) -> Result<()> {
    let mut grouped: BTreeMap<(String, String, usize), (Vec<u128>, usize)> = BTreeMap::new();
    for row in &outputs.raw {
        let entry = grouped
            .entry((row.experiment.to_string(), row.operation.to_string(), row.n))
            .or_default();
        if row.success {
            entry.0.push(row.duration_ns);
        } else {
            entry.1 += 1;
        }
    }
    for ((experiment, operation, n), (durations, failed_samples)) in grouped {
        if durations.is_empty() {
            continue;
        }
        let (mean_ns, median_ns, stddev_ns, min_ns, max_ns, p95_ns) = statistics(&durations)?;
        outputs.summaries.push(SummaryRow {
            campaign_id: "ALL".to_string(),
            scope: "pooled",
            experiment,
            operation,
            n,
            valid_samples: durations.len(),
            failed_samples,
            mean_ns,
            median_ns,
            stddev_ns,
            min_ns,
            max_ns,
            p95_ns,
        });
    }
    Ok(())
}

fn command_output(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| "unavailable".to_string())
}

fn processor_name() -> String {
    fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|content| {
            content.lines().find_map(|line| {
                line.strip_prefix("model name")
                    .and_then(|value| value.split_once(':'))
                    .map(|(_, value)| value.trim().to_string())
            })
        })
        .unwrap_or_else(|| "unavailable".to_string())
}

fn metadata(config: &Config, system_ids: Vec<String>) -> Metadata {
    let experiments = match config.selection {
        Selection::All => vec![
            "A_user_attribute_count",
            "B_delegated_attribute_count",
            "C_policy_leaf_count",
        ],
        Selection::Attributes => vec!["A_user_attribute_count"],
        Selection::Delegation => vec!["B_delegated_attribute_count"],
        Selection::Policy => vec!["C_policy_leaf_count"],
    };
    Metadata {
        benchmark: "CP-ABE scalability benchmark",
        format_version: "1",
        crypto_version: "2",
        curve: "BLS12-381",
        hash_to_curve: "CP-ABE hash-to-curve domain implemented by src/crypto/cpabe.rs",
        attribute_encoding: "UTF-8 strings A0001 ... A0050",
        cardinalities: CARDINALITIES.to_vec(),
        experiments,
        warmups: config.warmups,
        measurements: config.measurements,
        campaigns: config.campaigns,
        seed: config.seed,
        selection_order: "cardinalities are deterministically shuffled per campaign; crypto randomness remains OsRng",
        raw_time_unit: "nanoseconds",
        summary_time_unit: "nanoseconds",
        plaintext_bytes: PLAINTEXT.len(),
        build_mode: "release",
        generated_at_utc: Utc::now().to_rfc3339(),
        rustc: command_output("rustc", &["--version"]),
        operating_system: command_output("uname", &["-srvm"]),
        architecture: command_output("uname", &["-m"]),
        processor: processor_name(),
        git_commit: command_output("git", &["rev-parse", "HEAD"]),
        git_worktree: if command_output("git", &["status", "--porcelain"]) == "unavailable" {
            "unavailable".to_string()
        } else if command_output("git", &["status", "--porcelain"]).is_empty() {
            "clean".to_string()
        } else {
            "modified".to_string()
        },
        dependency_snapshot: command_output("cargo", &["tree", "--depth", "1"]),
        system_ids,
        timing_scope: vec![
            "KeyGen includes only cpabe::keygen; setup and validation are outside the timer.",
            "Delegate includes only cpabe::delegate, including its current linear attribute searches and result allocations.",
            "TM_Delegate includes only cpabe::tm_delegate; N labels the delegated subset provenance.",
            "Encrypt_with_policy includes the current CP-ABE operation and its hybrid AES-GCM encryption.",
            "TM_Decrypt includes the current pairing, validation, parsing, copying, and intermediate-object construction.",
            "Decrypt includes the current parsing, pairings, GT reconstruction, AES-GCM decryption, and UTF-8 conversion.",
            "Network, ABS, CSV writing, statistics, and preparation of inputs are outside all timers.",
        ],
        limitations: vec![
            "A campaign is a repeated measurement batch, not a statistically independent machine run.",
            "Pooled summaries combine observations across campaigns and must not be interpreted as independent replicates.",
            "TM_Delegate has no explicit attribute-list parameter; its N value is a provenance label.",
            "This tool measures existing API scopes and does not claim algorithmic equivalence beyond the documented operations.",
        ],
    }
}

fn run(config: &Config) -> Result<(Outputs, Metadata)> {
    let mut outputs = Outputs::default();
    let mut system_ids = Vec::new();
    for campaign_id in 1..=config.campaigns {
        let (pp, msk) = cpabe::setup()?;
        cpabe::validate_public_params(&pp)?;
        let system_id = cpabe::public_params_id(&pp)?;
        system_ids.push(system_id);
        add_pp_and_msk_sizes(&mut outputs, campaign_id, &pp, &msk)?;

        match config.selection {
            Selection::All => {
                run_experiment_a(config, campaign_id, &pp, &msk, &mut outputs)?;
                run_experiment_b(config, campaign_id, &pp, &msk, &mut outputs)?;
                run_experiment_c(config, campaign_id, &pp, &msk, &mut outputs)?;
            }
            Selection::Attributes => {
                run_experiment_a(config, campaign_id, &pp, &msk, &mut outputs)?;
            }
            Selection::Delegation => {
                run_experiment_b(config, campaign_id, &pp, &msk, &mut outputs)?;
            }
            Selection::Policy => {
                run_experiment_c(config, campaign_id, &pp, &msk, &mut outputs)?;
            }
        }
    }
    add_pooled_summaries(&mut outputs)?;
    let metadata = metadata(config, system_ids);
    Ok((outputs, metadata))
}

fn write_outputs(output_dir: &Path, outputs: &Outputs, metadata: &Metadata) -> Result<()> {
    fs::create_dir_all(output_dir)?;
    write_csv(&output_dir.join("timings_raw.csv"), &outputs.raw)?;
    write_csv(&output_dir.join("timings_summary.csv"), &outputs.summaries)?;
    write_csv(&output_dir.join("sizes.csv"), &outputs.sizes)?;
    if outputs.errors.is_empty() {
        fs::write(
            output_dir.join("errors.csv"),
            "campaign_id,experiment,operation,n,phase,iteration,error\n",
        )?;
    } else {
        write_csv(&output_dir.join("errors.csv"), &outputs.errors)?;
    }
    let metadata_json = serde_json::to_vec_pretty(metadata)?;
    fs::write(output_dir.join("metadata.json"), metadata_json)?;
    Ok(())
}

fn main() -> Result<()> {
    let config = parse_config()?;
    let (outputs, metadata) = run(&config)?;
    write_outputs(&config.output_dir, &outputs, &metadata)?;
    println!(
        "Campagne preparee: {} observations brutes, {} erreurs, sortie {}",
        outputs.raw.len(),
        outputs.errors.len(),
        config.output_dir.display()
    );
    if !outputs.errors.is_empty() {
        return Err(anyhow!(
            "la campagne contient {} erreurs; consulter errors.csv",
            outputs.errors.len()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attributes_are_fixed_width_and_deterministic() {
        let attrs = attributes(5);
        assert_eq!(
            attrs,
            vec![
                "A0001".to_string(),
                "A0002".to_string(),
                "A0003".to_string(),
                "A0004".to_string(),
                "A0005".to_string()
            ]
        );
        assert_eq!(attributes(50).last().cloned(), Some("A0050".to_string()));
    }

    #[test]
    fn ordering_and_subsets_are_reproducible() {
        assert_eq!(ordered_cardinalities(7, 1), ordered_cardinalities(7, 1));
        assert_ne!(ordered_cardinalities(7, 1), ordered_cardinalities(7, 2));
        let first = delegated_subset(7, 1, 20);
        assert_eq!(first, delegated_subset(7, 1, 20));
        assert_eq!(first.len(), 20);
        assert!(first.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn statistics_use_sample_stddev_and_nearest_rank_p95() {
        let values = vec![1, 2, 3, 4];
        let (mean, median_value, stddev, min, max, p95) = statistics(&values).unwrap();
        assert_eq!(mean, 2.5);
        assert_eq!(median_value, 2.5);
        assert!((stddev - 1.2909944487).abs() < 1e-9);
        assert_eq!((min, max, p95), (1, 4, 4));
    }

    #[test]
    fn csv_escaping_is_explicit() {
        let value = serde_json::Value::String("a,b\"c".to_string());
        assert_eq!(csv_cell(Some(&value)), "\"a,b\"\"c\"");
    }
}
