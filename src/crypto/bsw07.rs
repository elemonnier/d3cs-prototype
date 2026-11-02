//! Standalone BSW07 CP-ABE instantiation.
//!
//! This module deliberately does not use the PM23/D3CS CP-ABE types.  It is a
//! small, fixed-policy implementation intended for functional validation and
//! later comparison experiments.  The supported policy is exactly
//! `classification AND mission`, with two leaves and Lagrange coefficients
//! `(2, -1)`.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{anyhow, ensure, Result};
use ark_bls12_381::{g2, Bls12_381, Fq12, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::hashing::curve_maps::wb::WBMap;
use ark_ec::hashing::map_to_curve_hasher::MapToCurveBasedHasher;
use ark_ec::hashing::HashToCurve;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ff::field_hashers::DefaultFieldHasher;
use ark_ff::{Field, PrimeField, UniformRand, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use base64::Engine;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const BSW07_SCHEME: &str = "BSW07";
const BSW07_FORMAT_VERSION: u8 = 1;
const BSW07_ATTR_HASH_DST: &[u8] = b"D3CS-BSW07-CPABE-ATTR-G2-v1";
const BSW07_SYSTEM_ID_DOMAIN: &[u8] = b"D3CS-BSW07-CPABE-SYSTEM-ID-v1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Bsw07PublicParams {
    pub version: u8,
    pub scheme: String,
    pub system_id: String,
    pub g: String,
    pub g2: String,
    pub h: String,
    pub f2: String,
    pub y: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Bsw07MasterKey {
    pub version: u8,
    pub scheme: String,
    pub system_id: String,
    pub beta: String,
    /// g2^alpha.  This is the standard compact BSW07 master-key component.
    pub g2_alpha: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Bsw07AttributeKey {
    pub attr: String,
    /// D_i = g2^r H(attr)^r_i.
    pub d_i: String,
    /// D'_i = g1^r_i.
    pub d_i_prime: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Bsw07SecretKey {
    pub version: u8,
    pub scheme: String,
    pub system_id: String,
    /// D = g2^((alpha+r)/beta).
    pub d: String,
    pub attrs: Vec<String>,
    pub components: Vec<Bsw07AttributeKey>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Bsw07Label {
    pub classification: String,
    pub mission: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Bsw07Leaf {
    pub index: u8,
    pub attr: String,
    pub c_i: String,
    pub c_i_prime: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Bsw07Ciphertext {
    pub version: u8,
    pub scheme: String,
    pub system_id: String,
    pub label: Bsw07Label,
    /// C_tilde = M_GT * Y^s.
    pub c_tilde: String,
    /// C = g1^(beta*s).
    pub c: String,
    pub leaves: Vec<Bsw07Leaf>,
    pub nonce: String,
    pub ciphertext: String,
}

fn b64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes)
}

fn b64_decode(value: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(value)
        .map_err(|_| anyhow!("Invalid BSW07 Base64 value"))
}

fn check_header(version: u8, scheme: &str, object: &str) -> Result<()> {
    ensure!(
        version == BSW07_FORMAT_VERSION,
        "Unsupported BSW07 {object} version {version}"
    );
    ensure!(scheme == BSW07_SCHEME, "Object is not a BSW07 {object}");
    Ok(())
}

fn check_system_id(expected: &str, actual: &str, object: &str) -> Result<()> {
    ensure!(!expected.is_empty(), "Missing BSW07 system identity");
    ensure!(
        actual == expected,
        "BSW07 system identity mismatch for {object}: expected {expected}, got {actual}"
    );
    Ok(())
}

fn encode_attribute(attr: &str) -> Vec<u8> {
    let bytes = attr.as_bytes();
    let mut encoded = Vec::with_capacity(8 + bytes.len());
    encoded.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    encoded.extend_from_slice(bytes);
    encoded
}

/// Hashes the length-prefixed UTF-8 attribute encoding to a validated G2 point.
/// The domain is intentionally distinct from D3CS CP-ABE and ABS domains.
pub fn hash_attribute(attr: &str) -> Result<G2Projective> {
    type Curve = g2::Config;
    type Hasher =
        MapToCurveBasedHasher<G2Projective, DefaultFieldHasher<Sha256, 128>, WBMap<Curve>>;

    let hasher = Hasher::new(BSW07_ATTR_HASH_DST)
        .map_err(|_| anyhow!("BSW07 attribute hasher initialization failed"))?;
    let point = hasher
        .hash(&encode_attribute(attr))
        .map_err(|_| anyhow!("BSW07 attribute hash-to-curve failed"))?;
    ensure!(
        point.is_on_curve() && point.is_in_correct_subgroup_assuming_on_curve(),
        "BSW07 attribute hash is not a valid G2 subgroup point"
    );
    Ok(point.into_group())
}

fn ser_g1(point: &G1Projective) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    point
        .into_affine()
        .serialize_compressed(&mut bytes)
        .map_err(|_| anyhow!("BSW07 G1 serialization failed"))?;
    Ok(bytes)
}

fn ser_g2(point: &G2Projective) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    point
        .into_affine()
        .serialize_compressed(&mut bytes)
        .map_err(|_| anyhow!("BSW07 G2 serialization failed"))?;
    Ok(bytes)
}

fn ser_gt(point: &Fq12) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    point
        .serialize_compressed(&mut bytes)
        .map_err(|_| anyhow!("BSW07 GT serialization failed"))?;
    Ok(bytes)
}

fn de_g1(bytes: &[u8]) -> Result<G1Projective> {
    let point = G1Affine::deserialize_compressed(bytes)
        .map_err(|_| anyhow!("Invalid compressed BSW07 G1 point"))?;
    ensure!(
        point.is_on_curve() && point.is_in_correct_subgroup_assuming_on_curve(),
        "Invalid BSW07 G1 subgroup point"
    );
    Ok(point.into_group())
}

fn de_g2(bytes: &[u8]) -> Result<G2Projective> {
    let point = G2Affine::deserialize_compressed(bytes)
        .map_err(|_| anyhow!("Invalid compressed BSW07 G2 point"))?;
    ensure!(
        point.is_on_curve() && point.is_in_correct_subgroup_assuming_on_curve(),
        "Invalid BSW07 G2 subgroup point"
    );
    Ok(point.into_group())
}

fn de_gt(bytes: &[u8]) -> Result<Fq12> {
    Fq12::deserialize_compressed(bytes).map_err(|_| anyhow!("Invalid compressed BSW07 GT element"))
}

fn ser_fr(value: &Fr) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    value
        .serialize_compressed(&mut bytes)
        .map_err(|_| anyhow!("BSW07 scalar serialization failed"))?;
    Ok(bytes)
}

fn de_fr(bytes: &[u8]) -> Result<Fr> {
    Fr::deserialize_compressed(bytes).map_err(|_| anyhow!("Invalid BSW07 scalar"))
}

fn pairing_gt(g1_point: G1Projective, g2_point: G2Projective) -> Fq12 {
    Bls12_381::pairing(g1_point.into_affine(), g2_point.into_affine()).0
}

fn gt_pow(value: &Fq12, exponent: &Fr) -> Fq12 {
    value.pow(exponent.into_bigint())
}

fn derive_aes_key(value: &Fq12) -> Result<[u8; 32]> {
    let digest = Sha256::digest(ser_gt(value)?);
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    Ok(key)
}

fn add_identity_field(hasher: &mut Sha256, name: &[u8], value: &[u8]) {
    hasher.update((name.len() as u64).to_be_bytes());
    hasher.update(name);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn calculate_system_id(pp: &Bsw07PublicParams) -> String {
    let mut hasher = Sha256::new();
    hasher.update(BSW07_SYSTEM_ID_DOMAIN);
    for (name, value) in [
        (
            b"version".as_slice(),
            pp.version.to_string().as_bytes().to_vec(),
        ),
        (b"scheme".as_slice(), pp.scheme.as_bytes().to_vec()),
        (b"g".as_slice(), pp.g.as_bytes().to_vec()),
        (b"g2".as_slice(), pp.g2.as_bytes().to_vec()),
        (b"h".as_slice(), pp.h.as_bytes().to_vec()),
        (b"f2".as_slice(), pp.f2.as_bytes().to_vec()),
        (b"y".as_slice(), pp.y.as_bytes().to_vec()),
    ] {
        add_identity_field(&mut hasher, name, &value);
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn public_params_id(pp: &Bsw07PublicParams) -> Result<String> {
    check_header(pp.version, &pp.scheme, "public parameters")?;
    Ok(calculate_system_id(pp))
}

fn decode_pp(
    pp: &Bsw07PublicParams,
) -> Result<(G1Projective, G2Projective, G1Projective, G2Projective, Fq12)> {
    validate_public_params(pp)?;
    Ok((
        de_g1(&b64_decode(&pp.g)?)?,
        de_g2(&b64_decode(&pp.g2)?)?,
        de_g1(&b64_decode(&pp.h)?)?,
        de_g2(&b64_decode(&pp.f2)?)?,
        de_gt(&b64_decode(&pp.y)?)?,
    ))
}

pub fn validate_public_params(pp: &Bsw07PublicParams) -> Result<()> {
    check_header(pp.version, &pp.scheme, "public parameters")?;
    ensure!(
        !pp.system_id.is_empty(),
        "Missing BSW07 public-parameter system identity"
    );
    ensure!(
        pp.system_id == calculate_system_id(pp),
        "Invalid BSW07 public-parameter system identity"
    );
    let g = de_g1(&b64_decode(&pp.g)?)?;
    let g2 = de_g2(&b64_decode(&pp.g2)?)?;
    let h = de_g1(&b64_decode(&pp.h)?)?;
    let f2 = de_g2(&b64_decode(&pp.f2)?)?;
    let y = de_gt(&b64_decode(&pp.y)?)?;
    ensure!(
        !g.is_zero() && !g2.is_zero() && !h.is_zero() && !f2.is_zero(),
        "Invalid BSW07 generator component"
    );
    ensure!(!y.is_zero(), "Invalid BSW07 pairing component");
    Ok(())
}

pub fn validate_master_key(msk: &Bsw07MasterKey) -> Result<()> {
    check_header(msk.version, &msk.scheme, "master key")?;
    ensure!(
        !msk.system_id.is_empty(),
        "Missing BSW07 master-key system identity"
    );
    let beta = de_fr(&b64_decode(&msk.beta)?)?;
    ensure!(!beta.is_zero(), "Invalid zero BSW07 beta");
    let g2_alpha = de_g2(&b64_decode(&msk.g2_alpha)?)?;
    ensure!(!g2_alpha.is_zero(), "Invalid BSW07 alpha component");
    Ok(())
}

pub fn validate_secret_key(sk: &Bsw07SecretKey) -> Result<()> {
    check_header(sk.version, &sk.scheme, "secret key")?;
    ensure!(
        !sk.system_id.is_empty(),
        "Missing BSW07 secret-key system identity"
    );
    ensure!(!sk.attrs.is_empty(), "BSW07 secret key has no attributes");
    ensure!(
        sk.attrs.len() == sk.components.len(),
        "BSW07 secret-key attribute/component mismatch"
    );
    let d = de_g2(&b64_decode(&sk.d)?)?;
    ensure!(!d.is_zero(), "Invalid BSW07 D component");
    for (attr, component) in sk.attrs.iter().zip(sk.components.iter()) {
        ensure!(
            !attr.is_empty() && *attr == component.attr,
            "Invalid BSW07 attribute component"
        );
        let d_i = de_g2(&b64_decode(&component.d_i)?)?;
        let d_i_prime = de_g1(&b64_decode(&component.d_i_prime)?)?;
        ensure!(
            !d_i.is_zero() && !d_i_prime.is_zero(),
            "Invalid zero BSW07 attribute component"
        );
    }
    let mut unique = sk.attrs.clone();
    unique.sort();
    unique.dedup();
    ensure!(
        unique.len() == sk.attrs.len(),
        "Duplicate attribute in BSW07 secret key"
    );
    Ok(())
}

pub fn validate_ciphertext(ct: &Bsw07Ciphertext) -> Result<()> {
    check_header(ct.version, &ct.scheme, "ciphertext")?;
    ensure!(
        !ct.system_id.is_empty(),
        "Missing BSW07 ciphertext system identity"
    );
    ensure!(
        ct.leaves.len() == 2,
        "BSW07 supports exactly two policy leaves"
    );
    ensure!(
        ct.leaves[0].index == 1 && ct.leaves[1].index == 2,
        "Invalid BSW07 leaf indexes"
    );
    ensure!(
        ct.leaves[0].attr == ct.label.classification,
        "BSW07 classification leaf mismatch"
    );
    ensure!(
        ct.leaves[1].attr == ct.label.mission,
        "BSW07 mission leaf mismatch"
    );
    de_gt(&b64_decode(&ct.c_tilde)?)?;
    let c = de_g1(&b64_decode(&ct.c)?)?;
    ensure!(!c.is_zero(), "Invalid zero BSW07 C component");
    for leaf in &ct.leaves {
        let c_i = de_g1(&b64_decode(&leaf.c_i)?)?;
        let c_i_prime = de_g2(&b64_decode(&leaf.c_i_prime)?)?;
        ensure!(
            !c_i.is_zero() && !c_i_prime.is_zero(),
            "Invalid zero BSW07 leaf component"
        );
    }
    let nonce = b64_decode(&ct.nonce)?;
    ensure!(nonce.len() == 12, "Invalid BSW07 AES-GCM nonce length");
    ensure!(
        !b64_decode(&ct.ciphertext)?.is_empty(),
        "Empty BSW07 AES-GCM payload"
    );
    Ok(())
}

fn validate_for_pp(pp: &Bsw07PublicParams, object_system_id: &str, object: &str) -> Result<()> {
    let id = public_params_id(pp)?;
    check_system_id(&id, object_system_id, object)
}

pub fn setup() -> Result<(Bsw07PublicParams, Bsw07MasterKey)> {
    let mut rng = rand_core::OsRng;
    let g = G1Projective::generator();
    let g2 = G2Projective::generator();
    let alpha = Fr::rand(&mut rng);
    let beta = loop {
        let value = Fr::rand(&mut rng);
        if !value.is_zero() {
            break value;
        }
    };
    let beta_inv = beta
        .inverse()
        .ok_or_else(|| anyhow!("BSW07 beta inversion failed"))?;
    let h = g.mul_bigint(beta.into_bigint());
    let f2 = g2.mul_bigint(beta_inv.into_bigint());
    let y = gt_pow(&pairing_gt(g, g2), &alpha);
    let g2_alpha = g2.mul_bigint(alpha.into_bigint());

    let mut pp = Bsw07PublicParams {
        version: BSW07_FORMAT_VERSION,
        scheme: BSW07_SCHEME.to_string(),
        system_id: String::new(),
        g: b64_encode(&ser_g1(&g)?),
        g2: b64_encode(&ser_g2(&g2)?),
        h: b64_encode(&ser_g1(&h)?),
        f2: b64_encode(&ser_g2(&f2)?),
        y: b64_encode(&ser_gt(&y)?),
    };
    pp.system_id = calculate_system_id(&pp);
    let msk = Bsw07MasterKey {
        version: BSW07_FORMAT_VERSION,
        scheme: BSW07_SCHEME.to_string(),
        system_id: pp.system_id.clone(),
        beta: b64_encode(&ser_fr(&beta)?),
        g2_alpha: b64_encode(&ser_g2(&g2_alpha)?),
    };
    validate_public_params(&pp)?;
    validate_master_key(&msk)?;
    Ok((pp, msk))
}

pub fn keygen(
    pp: &Bsw07PublicParams,
    msk: &Bsw07MasterKey,
    attrs: &[String],
) -> Result<Bsw07SecretKey> {
    let (g, g2, _, _, _) = decode_pp(pp)?;
    validate_master_key(msk)?;
    validate_for_pp(pp, &msk.system_id, "master key")?;
    ensure!(
        !attrs.is_empty(),
        "BSW07 key generation requires an attribute"
    );
    let mut sorted_attrs = attrs.to_vec();
    sorted_attrs.sort();
    sorted_attrs.dedup();
    ensure!(
        sorted_attrs.len() == attrs.len(),
        "Duplicate attribute in BSW07 key generation"
    );
    ensure!(
        sorted_attrs.iter().all(|attr| !attr.is_empty()),
        "Empty BSW07 attribute"
    );

    let beta = de_fr(&b64_decode(&msk.beta)?)?;
    let beta_inv = beta
        .inverse()
        .ok_or_else(|| anyhow!("Invalid BSW07 beta"))?;
    let g2_alpha = de_g2(&b64_decode(&msk.g2_alpha)?)?;
    let mut rng = rand_core::OsRng;
    let r = Fr::rand(&mut rng);
    let d = (g2_alpha + g2.mul_bigint(r.into_bigint())).mul_bigint(beta_inv.into_bigint());
    let g2_r = g2.mul_bigint(r.into_bigint());
    let mut components = Vec::with_capacity(attrs.len());
    for attr in attrs {
        let r_i = Fr::rand(&mut rng);
        let d_i = g2_r + hash_attribute(attr)?.mul_bigint(r_i.into_bigint());
        let d_i_prime = g.mul_bigint(r_i.into_bigint());
        components.push(Bsw07AttributeKey {
            attr: attr.clone(),
            d_i: b64_encode(&ser_g2(&d_i)?),
            d_i_prime: b64_encode(&ser_g1(&d_i_prime)?),
        });
    }
    let sk = Bsw07SecretKey {
        version: BSW07_FORMAT_VERSION,
        scheme: BSW07_SCHEME.to_string(),
        system_id: pp.system_id.clone(),
        d: b64_encode(&ser_g2(&d)?),
        attrs: attrs.to_vec(),
        components,
    };
    validate_secret_key(&sk)?;
    Ok(sk)
}

pub fn encrypt(
    pp: &Bsw07PublicParams,
    label: &Bsw07Label,
    message: &str,
) -> Result<Bsw07Ciphertext> {
    let (g, g2, h, _, y) = decode_pp(pp)?;
    ensure!(
        !label.classification.is_empty() && !label.mission.is_empty(),
        "BSW07 policy attributes cannot be empty"
    );
    let mut rng = rand_core::OsRng;
    let s = Fr::rand(&mut rng);
    let a = Fr::rand(&mut rng);
    let q1 = s + a;
    let q2 = s + a + a;
    let m_gt = gt_pow(&pairing_gt(g, g2), &Fr::rand(&mut rng));
    let key_bytes = derive_aes_key(&m_gt)?;
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let payload = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), message.as_bytes())
        .map_err(|_| anyhow!("BSW07 AES-GCM encryption failed"))?;
    let c_tilde = m_gt * gt_pow(&y, &s);
    let c = h.mul_bigint(s.into_bigint());
    let leaves = vec![
        Bsw07Leaf {
            index: 1,
            attr: label.classification.clone(),
            c_i: b64_encode(&ser_g1(&g.mul_bigint(q1.into_bigint()))?),
            c_i_prime: b64_encode(&ser_g2(
                &hash_attribute(&label.classification)?.mul_bigint(q1.into_bigint()),
            )?),
        },
        Bsw07Leaf {
            index: 2,
            attr: label.mission.clone(),
            c_i: b64_encode(&ser_g1(&g.mul_bigint(q2.into_bigint()))?),
            c_i_prime: b64_encode(&ser_g2(
                &hash_attribute(&label.mission)?.mul_bigint(q2.into_bigint()),
            )?),
        },
    ];
    let ct = Bsw07Ciphertext {
        version: BSW07_FORMAT_VERSION,
        scheme: BSW07_SCHEME.to_string(),
        system_id: pp.system_id.clone(),
        label: label.clone(),
        c_tilde: b64_encode(&ser_gt(&c_tilde)?),
        c: b64_encode(&ser_g1(&c)?),
        leaves,
        nonce: b64_encode(&nonce_bytes),
        ciphertext: b64_encode(&payload),
    };
    validate_ciphertext(&ct)?;
    Ok(ct)
}

pub fn decrypt(
    pp: &Bsw07PublicParams,
    ct: &Bsw07Ciphertext,
    sk: &Bsw07SecretKey,
) -> Result<String> {
    validate_public_params(pp)?;
    validate_ciphertext(ct)?;
    validate_secret_key(sk)?;
    validate_for_pp(pp, &ct.system_id, "ciphertext")?;
    validate_for_pp(pp, &sk.system_id, "secret key")?;
    let c_tilde = de_gt(&b64_decode(&ct.c_tilde)?)?;
    let c = de_g1(&b64_decode(&ct.c)?)?;
    let d = de_g2(&b64_decode(&sk.d)?)?;
    let f = pairing_gt(c, d);
    let mut values = Vec::with_capacity(2);
    for leaf in &ct.leaves {
        let component = sk
            .components
            .iter()
            .find(|component| component.attr == leaf.attr)
            .ok_or_else(|| {
                anyhow!(
                    "BSW07 policy is not satisfied: missing attribute {}",
                    leaf.attr
                )
            })?;
        let c_i = de_g1(&b64_decode(&leaf.c_i)?)?;
        let c_i_prime = de_g2(&b64_decode(&leaf.c_i_prime)?)?;
        let d_i = de_g2(&b64_decode(&component.d_i)?)?;
        let d_i_prime = de_g1(&b64_decode(&component.d_i_prime)?)?;
        let numerator = pairing_gt(c_i, d_i);
        let denominator = pairing_gt(d_i_prime, c_i_prime)
            .inverse()
            .ok_or_else(|| anyhow!("Invalid BSW07 pairing denominator"))?;
        values.push(numerator * denominator);
    }
    let a = values[0]
        * values[0]
        * values[1]
            .inverse()
            .ok_or_else(|| anyhow!("Invalid BSW07 reconstruction pairing"))?;
    let y_s = f * a
        .inverse()
        .ok_or_else(|| anyhow!("Invalid BSW07 reconstruction factor"))?;
    let m_gt = c_tilde
        * y_s
            .inverse()
            .ok_or_else(|| anyhow!("Invalid BSW07 session element"))?;
    let key_bytes = derive_aes_key(&m_gt)?;
    let nonce = b64_decode(&ct.nonce)?;
    let payload = b64_decode(&ct.ciphertext)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), payload.as_ref())
        .map_err(|_| anyhow!("BSW07 AES-GCM decryption failed"))?;
    String::from_utf8(plaintext).map_err(|_| anyhow!("BSW07 plaintext is not UTF-8"))
}

pub fn delegate(
    pp: &Bsw07PublicParams,
    sk: &Bsw07SecretKey,
    delegated_attrs: &[String],
) -> Result<Bsw07SecretKey> {
    let (_, g2, _, f2, _) = decode_pp(pp)?;
    validate_secret_key(sk)?;
    validate_for_pp(pp, &sk.system_id, "secret key")?;
    ensure!(
        !delegated_attrs.is_empty(),
        "BSW07 delegation requires an attribute"
    );
    let mut attrs = delegated_attrs.to_vec();
    attrs.sort();
    attrs.dedup();
    ensure!(
        attrs.len() == delegated_attrs.len(),
        "Duplicate attribute in BSW07 delegation"
    );
    for attr in &attrs {
        ensure!(
            sk.attrs.iter().any(|source| source == attr),
            "Cannot delegate absent BSW07 attribute {attr}"
        );
    }
    let mut rng = rand_core::OsRng;
    let rho = Fr::rand(&mut rng);
    let d = de_g2(&b64_decode(&sk.d)?)? + f2.mul_bigint(rho.into_bigint());
    let g2_rho = g2.mul_bigint(rho.into_bigint());
    let mut components = Vec::with_capacity(attrs.len());
    for attr in &attrs {
        let source = sk
            .components
            .iter()
            .find(|component| component.attr == *attr)
            .ok_or_else(|| anyhow!("Missing source BSW07 component"))?;
        let rho_i = Fr::rand(&mut rng);
        let d_i = de_g2(&b64_decode(&source.d_i)?)?
            + g2_rho
            + hash_attribute(attr)?.mul_bigint(rho_i.into_bigint());
        let d_i_prime = de_g1(&b64_decode(&source.d_i_prime)?)?
            + G1Projective::generator().mul_bigint(rho_i.into_bigint());
        components.push(Bsw07AttributeKey {
            attr: attr.clone(),
            d_i: b64_encode(&ser_g2(&d_i)?),
            d_i_prime: b64_encode(&ser_g1(&d_i_prime)?),
        });
    }
    let delegated = Bsw07SecretKey {
        version: BSW07_FORMAT_VERSION,
        scheme: BSW07_SCHEME.to_string(),
        system_id: sk.system_id.clone(),
        d: b64_encode(&ser_g2(&d)?),
        attrs,
        components,
    };
    validate_secret_key(&delegated)?;
    Ok(delegated)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn label() -> Bsw07Label {
        Bsw07Label {
            classification: "classification".to_string(),
            mission: "mission".to_string(),
        }
    }

    fn attrs(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    fn complete_key(pp: &Bsw07PublicParams, msk: &Bsw07MasterKey) -> Bsw07SecretKey {
        keygen(pp, msk, &attrs(&["classification", "mission"])).expect("keygen")
    }

    #[test]
    fn setup_and_keygen_produce_valid_complete_objects() -> Result<()> {
        let (pp, msk) = setup()?;
        validate_public_params(&pp)?;
        validate_master_key(&msk)?;
        let sk = complete_key(&pp, &msk);
        validate_secret_key(&sk)?;
        assert_eq!(pp.system_id, msk.system_id);
        assert_eq!(pp.system_id, sk.system_id);
        assert_eq!(sk.components.len(), 2);
        Ok(())
    }

    #[test]
    fn independent_keygens_are_rerandomized_and_serialize() -> Result<()> {
        let (pp, msk) = setup()?;
        let sk1 = complete_key(&pp, &msk);
        let sk2 = complete_key(&pp, &msk);
        assert_ne!(sk1.d, sk2.d);
        assert_ne!(sk1.components[0].d_i, sk2.components[0].d_i);
        let pp2: Bsw07PublicParams = serde_json::from_str(&serde_json::to_string(&pp)?)?;
        let msk2: Bsw07MasterKey = serde_json::from_str(&serde_json::to_string(&msk)?)?;
        let sk_roundtrip: Bsw07SecretKey = serde_json::from_str(&serde_json::to_string(&sk1)?)?;
        validate_public_params(&pp2)?;
        validate_master_key(&msk2)?;
        validate_secret_key(&sk_roundtrip)?;
        Ok(())
    }

    #[test]
    fn encrypt_decrypt_roundtrip_and_multiple_messages() -> Result<()> {
        let (pp, msk) = setup()?;
        let sk = complete_key(&pp, &msk);
        for message in ["hello BSW07", "second message", ""] {
            let ct = encrypt(&pp, &label(), message)?;
            assert_eq!(decrypt(&pp, &ct, &sk)?, message);
            let ct_roundtrip: Bsw07Ciphertext = serde_json::from_str(&serde_json::to_string(&ct)?)?;
            assert_eq!(decrypt(&pp, &ct_roundtrip, &sk)?, message);
        }
        Ok(())
    }

    #[test]
    fn missing_classification_or_mission_is_rejected() -> Result<()> {
        let (pp, msk) = setup()?;
        let ct = encrypt(&pp, &label(), "protected")?;
        assert!(decrypt(&pp, &ct, &keygen(&pp, &msk, &attrs(&["classification"]))?).is_err());
        assert!(decrypt(&pp, &ct, &keygen(&pp, &msk, &attrs(&["mission"]))?).is_err());
        Ok(())
    }

    #[test]
    fn independent_setup_is_rejected() -> Result<()> {
        let (pp1, msk1) = setup()?;
        let (pp2, msk2) = setup()?;
        assert_ne!(pp1.system_id, pp2.system_id);
        let sk1 = complete_key(&pp1, &msk1);
        let ct1 = encrypt(&pp1, &label(), "protected")?;
        assert!(decrypt(&pp2, &ct1, &sk1).is_err());
        let sk2 = complete_key(&pp2, &msk2);
        assert!(decrypt(&pp1, &ct1, &sk2).is_err());
        Ok(())
    }

    #[test]
    fn aes_payload_and_nonce_tampering_are_rejected() -> Result<()> {
        let (pp, msk) = setup()?;
        let sk = complete_key(&pp, &msk);
        let ct = encrypt(&pp, &label(), "protected")?;
        let mut payload_tampered = ct.clone();
        let mut payload = b64_decode(&payload_tampered.ciphertext)?;
        payload[0] ^= 1;
        payload_tampered.ciphertext = b64_encode(&payload);
        assert!(decrypt(&pp, &payload_tampered, &sk).is_err());
        let mut nonce_tampered = ct;
        let mut nonce = b64_decode(&nonce_tampered.nonce)?;
        nonce[0] ^= 1;
        nonce_tampered.nonce = b64_encode(&nonce);
        assert!(decrypt(&pp, &nonce_tampered, &sk).is_err());
        Ok(())
    }

    #[test]
    fn valid_and_successive_delegation_decrypts() -> Result<()> {
        let (pp, msk) = setup()?;
        let source = keygen(&pp, &msk, &attrs(&["classification", "mission", "extra"]))?;
        let delegated = delegate(&pp, &source, &attrs(&["classification", "mission"]))?;
        assert_eq!(delegated.attrs, attrs(&["classification", "mission"]));
        let ct = encrypt(&pp, &label(), "delegated")?;
        assert_eq!(decrypt(&pp, &ct, &delegated)?, "delegated");
        let delegated_again = delegate(&pp, &delegated, &attrs(&["classification", "mission"]))?;
        assert_eq!(decrypt(&pp, &ct, &delegated_again)?, "delegated");
        assert_ne!(delegated.d, delegated_again.d);
        assert!(delegate(&pp, &source, &attrs(&["absent"])).is_err());
        let insufficient = delegate(&pp, &source, &attrs(&["classification"]))?;
        assert!(decrypt(&pp, &ct, &insufficient).is_err());
        Ok(())
    }

    #[test]
    fn delegation_is_rerandomized() -> Result<()> {
        let (pp, msk) = setup()?;
        let source = complete_key(&pp, &msk);
        let first = delegate(&pp, &source, &attrs(&["classification", "mission"]))?;
        let second = delegate(&pp, &source, &attrs(&["classification", "mission"]))?;
        assert_ne!(first.d, second.d);
        assert_ne!(
            first.components[0].d_i_prime,
            second.components[0].d_i_prime
        );
        Ok(())
    }

    #[test]
    fn old_direct_exponent_attribute_construction_is_not_the_hash() -> Result<()> {
        let attr = "classification";
        let (_, g2, _, _, _) = decode_pp(&setup()?.0)?;
        let old_scalar = Fr::from_be_bytes_mod_order(&Sha256::digest(encode_attribute(attr)));
        let old_style = g2.mul_bigint(old_scalar.into_bigint());
        assert_ne!(hash_attribute(attr)?, old_style);
        assert!(hash_attribute(attr)?
            .into_affine()
            .is_in_correct_subgroup_assuming_on_curve());
        Ok(())
    }

    #[test]
    fn naive_cross_user_component_combination_does_not_decrypt() -> Result<()> {
        let (pp, msk) = setup()?;
        let u1 = keygen(&pp, &msk, &attrs(&["classification"]))?;
        let u2 = keygen(&pp, &msk, &attrs(&["mission"]))?;
        let ct = encrypt(&pp, &label(), "protected")?;
        let combined = Bsw07SecretKey {
            version: BSW07_FORMAT_VERSION,
            scheme: BSW07_SCHEME.to_string(),
            system_id: pp.system_id.clone(),
            d: u1.d.clone(),
            attrs: attrs(&["classification", "mission"]),
            components: vec![u1.components[0].clone(), u2.components[0].clone()],
        };
        assert!(decrypt(&pp, &ct, &combined).is_err());
        let mut other_d = combined.clone();
        other_d.d = u2.d;
        assert!(decrypt(&pp, &ct, &other_d).is_err());
        Ok(())
    }

    #[test]
    fn malformed_points_and_non_bsw07_objects_are_rejected() -> Result<()> {
        let (pp, _) = setup()?;
        let mut malformed = pp.clone();
        malformed.g = "not-a-point".to_string();
        assert!(validate_public_params(&malformed).is_err());
        let old_shape =
            r#"{"version":1,"system_id":"old","g":"x","g2":"x","h":"x","f":"x","f2":"x","y":"x"}"#;
        assert!(serde_json::from_str::<Bsw07PublicParams>(old_shape).is_err());
        Ok(())
    }

    #[test]
    fn policy_metadata_mismatch_is_rejected_explicitly() -> Result<()> {
        let (pp, msk) = setup()?;
        let sk = complete_key(&pp, &msk);
        let mut ct = encrypt(&pp, &label(), "protected")?;
        ct.label.mission = "other".to_string();
        assert!(decrypt(&pp, &ct, &sk).is_err());
        Ok(())
    }
}
