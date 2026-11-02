// ce fichier répertorie les fonctions crypto ABE provenant de la spécification docs/PM23

use anyhow::{anyhow, Result};
use base64::Engine;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};

use ark_bls12_381::{Bls12_381, Fq12, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::hashing::curve_maps::wb::WBMap;
use ark_ec::hashing::map_to_curve_hasher::MapToCurveBasedHasher;
use ark_ec::hashing::HashToCurve;
use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_ec::Group;
use ark_ff::field_hashers::DefaultFieldHasher;
use ark_ff::BigInteger;
use ark_ff::Field;
use ark_ff::One;
use ark_ff::PrimeField;
use ark_ff::UniformRand;
use ark_ff::Zero;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use super::DocumentLabel;

const CPABE_CRYPTO_VERSION: u8 = 2;
// These domain-separation tags are stable compatibility constants. Changing
// them would change derived cryptographic values and invalidate existing data.
const CPABE_ATTR_HASH_DST: &[u8] = b"D3CS-CPABE-V2-ATTR-G2";
const CPABE_SYSTEM_ID_DOMAIN: &[u8] = b"D3CS-CPABE-V2-SYSTEM-ID";

/// Maximum number of leaves representable by the current ciphertext index
/// type. This is deliberately tied to `AbeLeafV1::index` so the policy model
/// cannot silently produce indices that the ciphertext format cannot encode.
#[allow(dead_code)]
pub const MAX_AND_POLICY_LEAVES: usize = u8::MAX as usize;

/// A validated conjunction of attributes.
///
/// The public field is retained so the policy can be inspected by callers,
/// while every helper that derives indices first validates and canonicalizes
/// the attributes. New code should construct policies with `AndPolicy::new`.
#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndPolicy {
    pub attrs: Vec<String>,
}

#[allow(dead_code)]
impl AndPolicy {
    /// Construct a policy and store its attributes in canonical order.
    pub fn new(mut attrs: Vec<String>) -> Result<Self> {
        validate_and_policy_attrs(&attrs)?;
        attrs.sort();
        Ok(Self { attrs })
    }

    /// Validate a policy, including policies created through a public struct
    /// literal or deserialized from an external representation.
    pub fn validate(&self) -> Result<()> {
        validate_and_policy_attrs(&self.attrs)
    }

    /// Return the canonical attribute ordering used for deterministic leaf
    /// positions. Indices are 1-based and therefore never equal to zero.
    fn canonical_attrs(&self) -> Result<Vec<String>> {
        self.validate()?;
        let mut attrs = self.attrs.clone();
        attrs.sort();
        Ok(attrs)
    }

    /// Return deterministic `(index, attribute)` pairs for the policy.
    fn indexed_attrs(&self) -> Result<Vec<(u8, String)>> {
        self.canonical_attrs()?
            .into_iter()
            .enumerate()
            .map(|(offset, attr)| {
                let index = u8::try_from(offset + 1)
                    .map_err(|_| anyhow!("AND policy index is not representable as u8"))?;
                Ok((index, attr))
            })
            .collect()
    }
}

#[allow(dead_code)]
fn validate_and_policy_attrs(attrs: &[String]) -> Result<()> {
    if attrs.is_empty() {
        return Err(anyhow!("AND policy must contain at least one attribute"));
    }
    if attrs.len() > MAX_AND_POLICY_LEAVES {
        return Err(anyhow!(
            "AND policy contains {} leaves; maximum is {}",
            attrs.len(),
            MAX_AND_POLICY_LEAVES
        ));
    }
    if attrs.iter().any(String::is_empty) {
        return Err(anyhow!("AND policy attributes must not be empty"));
    }

    let mut canonical = attrs.to_vec();
    canonical.sort();
    if canonical.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(anyhow!("AND policy attributes must be distinct"));
    }
    Ok(())
}

/// Build coefficients for q(z) = secret + a1*z + ... + a(N-1)*z^(N-1).
///
/// The first coefficient is the supplied secret. All remaining coefficients
/// are sampled independently with the project's cryptographically secure
/// operating-system RNG. Secrets and coefficients are never logged.
#[allow(dead_code)]
fn random_secret_polynomial(secret: Fr, leaf_count: usize) -> Result<Vec<Fr>> {
    if leaf_count == 0 {
        return Err(anyhow!(
            "secret-sharing polynomial must have at least one coefficient"
        ));
    }
    if leaf_count > MAX_AND_POLICY_LEAVES {
        return Err(anyhow!(
            "secret-sharing polynomial has too many coefficients: {}",
            leaf_count
        ));
    }

    let mut rng = rand_core::OsRng;
    let mut coefficients = Vec::with_capacity(leaf_count);
    coefficients.push(secret);
    for _ in 1..leaf_count {
        coefficients.push(Fr::rand(&mut rng));
    }
    Ok(coefficients)
}

/// Evaluate a polynomial represented in ascending powers using Horner's rule.
#[allow(dead_code)]
fn evaluate_polynomial(coefficients: &[Fr], x: Fr) -> Result<Fr> {
    let mut result = *coefficients
        .last()
        .ok_or_else(|| anyhow!("cannot evaluate an empty polynomial"))?;
    for coefficient in coefficients[..coefficients.len() - 1].iter().rev() {
        result *= x;
        result += coefficient;
    }
    Ok(result)
}

#[allow(dead_code)]
fn validate_interpolation_points(points: &[Fr]) -> Result<()> {
    if points.is_empty() {
        return Err(anyhow!("interpolation requires at least one point"));
    }

    for (i, point) in points.iter().enumerate() {
        if point.is_zero() {
            return Err(anyhow!(
                "interpolation point at position {} must be non-zero",
                i
            ));
        }
        if points[..i].contains(point) {
            return Err(anyhow!("interpolation points must be distinct"));
        }
    }
    Ok(())
}

/// Compute the Lagrange coefficients at zero for the supplied non-zero,
/// pairwise-distinct interpolation points.
#[allow(dead_code)]
fn lagrange_coefficients_at_zero(points: &[Fr]) -> Result<Vec<Fr>> {
    validate_interpolation_points(points)?;

    points
        .iter()
        .enumerate()
        .map(|(i, point_i)| {
            let mut coefficient = Fr::from(1u64);
            for (j, point_j) in points.iter().enumerate() {
                if i == j {
                    continue;
                }
                let denominator = *point_i - point_j;
                let denominator_inverse = denominator
                    .inverse()
                    .ok_or_else(|| anyhow!("interpolation denominator is not invertible"))?;
                coefficient *= -*point_j * denominator_inverse;
            }
            Ok(coefficient)
        })
        .collect()
}

/// Reconstruct q(0) from `(x_i, q(x_i))` shares using interpolation at zero.
#[allow(dead_code)]
fn reconstruct_secret_at_zero(parts: &[(Fr, Fr)]) -> Result<Fr> {
    if parts.is_empty() {
        return Err(anyhow!("secret reconstruction requires at least one part"));
    }

    let points: Vec<Fr> = parts.iter().map(|(point, _)| *point).collect();
    let coefficients = lagrange_coefficients_at_zero(&points)?;
    Ok(parts
        .iter()
        .zip(coefficients)
        .fold(Fr::from(0u64), |acc, ((_, share), coefficient)| {
            acc + *share * coefficient
        }))
}

/// Reconstruct a multiplicatively shared GT element at zero.
///
/// The exponents are reconstructed in `Fr`, while the shares themselves stay
/// in `GT`: `product_i share_i ^ lambda_i(0)`.
fn reconstruct_gt_at_zero(parts: &[(Fr, Fq12)]) -> Result<Fq12> {
    if parts.is_empty() {
        return Err(anyhow!("GT reconstruction requires at least one part"));
    }

    let points: Vec<Fr> = parts.iter().map(|(point, _)| *point).collect();
    let coefficients = lagrange_coefficients_at_zero(&points)?;
    Ok(parts
        .iter()
        .zip(coefficients)
        .fold(Fq12::one(), |acc, ((_, share), coefficient)| {
            acc * gt_pow(share, &coefficient)
        }))
}

/// Validate the positional part of a ciphertext policy before doing pairings.
///
/// Historical ciphertexts may contain the same attribute name in several
/// leaves (for example when classification and mission are equal), so this
/// check deliberately validates indices rather than rejecting repeated names.
fn validate_ciphertext_leaf_structure(leafs: &[AbeLeafV1]) -> Result<()> {
    if leafs.is_empty() {
        return Err(anyhow!("ciphertext must contain at least one leaf"));
    }
    if leafs.len() > MAX_AND_POLICY_LEAVES {
        return Err(anyhow!(
            "ciphertext contains {} leaves; maximum is {}",
            leafs.len(),
            MAX_AND_POLICY_LEAVES
        ));
    }

    let mut seen = vec![false; leafs.len() + 1];
    for leaf in leafs {
        if leaf.index == 0 {
            return Err(anyhow!("ciphertext leaf index must be non-zero"));
        }
        let index = leaf.index as usize;
        if index > leafs.len() {
            return Err(anyhow!(
                "ciphertext leaf index {} is outside the contiguous range 1..={}",
                leaf.index,
                leafs.len()
            ));
        }
        if seen[index] {
            return Err(anyhow!("ciphertext leaf indices must be distinct"));
        }
        if leaf.attr.is_empty() {
            return Err(anyhow!("ciphertext leaf attribute must not be empty"));
        }
        seen[index] = true;
    }

    if seen[1..].iter().any(|present| !present) {
        return Err(anyhow!("ciphertext leaf indices must be contiguous from 1"));
    }
    Ok(())
}

fn ensure_version(version: u8, object: &str) -> Result<()> {
    if version != CPABE_CRYPTO_VERSION {
        return Err(anyhow!(
            "Unsupported {} cryptographic version {}; expected version {}",
            object,
            version,
            CPABE_CRYPTO_VERSION
        ));
    }
    Ok(())
}

#[allow(dead_code)]
pub fn validate_public_params(pp: &PublicParamsV1) -> Result<()> {
    ensure_version(pp.version, "public parameters")?;
    if !pp.system_id.is_empty() && pp.system_id != public_params_id(pp)? {
        return Err(anyhow!("CP-ABE public parameters system identity mismatch"));
    }
    Ok(())
}

#[allow(dead_code)]
pub fn validate_pska(pska: &PskaV1) -> Result<()> {
    ensure_version(pska.version, "PSKA")
}

pub fn require_system_id(system_id: &str, object: &str) -> Result<()> {
    if system_id.is_empty() {
        return Err(anyhow!("Missing CP-ABE system identity in {object}"));
    }
    Ok(())
}

fn check_system_id(expected: &str, actual: &str, object: &str) -> Result<()> {
    if !actual.is_empty() && actual != expected {
        return Err(anyhow!(
            "CP-ABE system identity mismatch for {object}: expected {expected}, got {actual}"
        ));
    }
    Ok(())
}

fn add_identity_field(hasher: &mut Sha256, name: &[u8], value: &[u8]) {
    hasher.update((name.len() as u64).to_be_bytes());
    hasher.update(name);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

/// Stable identity for one CP-ABE public-parameter set.
/// The identity is a digest of the canonical field sequence, not of the JSON
/// representation, so formatting and map ordering cannot change it.
pub fn public_params_id(pp: &PublicParamsV1) -> Result<String> {
    ensure_version(pp.version, "public parameters")?;
    let mut hasher = Sha256::new();
    hasher.update(CPABE_SYSTEM_ID_DOMAIN);
    for (name, value) in [
        (b"version".as_slice(), pp.version.to_string().as_bytes()),
        (b"g".as_slice(), pp.g.as_bytes()),
        (b"g2".as_slice(), pp.g2.as_bytes()),
        (b"h".as_slice(), pp.h.as_bytes()),
        (b"f".as_slice(), pp.f.as_bytes()),
        (b"f2".as_slice(), pp.f2.as_bytes()),
        (b"y".as_slice(), pp.y.as_bytes()),
    ] {
        add_identity_field(&mut hasher, name, value);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

pub fn validate_key_material(pp: &PublicParamsV1, pska: &PskaV1, psks: &PsksV1) -> Result<()> {
    validate_public_params(pp)?;
    validate_pska(pska)?;
    validate_psks(psks)?;
    let id = public_params_id(pp)?;
    check_system_id(&id, &pska.system_id, "PSKA")?;
    check_system_id(&id, &psks.system_id, "PSKS")?;
    Ok(())
}

pub fn validate_pska_for_pp(pp: &PublicParamsV1, pska: &PskaV1) -> Result<()> {
    validate_public_params(pp)?;
    validate_pska(pska)?;
    let id = public_params_id(pp)?;
    check_system_id(&id, &pska.system_id, "PSKA")
}

pub fn validate_psks_for_pp(pp: &PublicParamsV1, psks: &PsksV1) -> Result<()> {
    validate_public_params(pp)?;
    validate_psks(psks)?;
    let id = public_params_id(pp)?;
    check_system_id(&id, &psks.system_id, "PSKS")
}

pub fn validate_ciphertext_for_pp(pp: &PublicParamsV1, ct: &CiphertextV1) -> Result<()> {
    validate_public_params(pp)?;
    validate_ciphertext(ct)?;
    let id = public_params_id(pp)?;
    check_system_id(&id, &ct.system_id, "ciphertext")
}

#[allow(dead_code)]
pub fn validate_psks(psks: &PsksV1) -> Result<()> {
    ensure_version(psks.version, "PSKS")
}

#[allow(dead_code)]
pub fn validate_ciphertext(ct: &CiphertextV1) -> Result<()> {
    ensure_version(ct.version, "ciphertext")?;
    validate_ciphertext_leaf_structure(&ct.abe.leafs)?;

    de_gt(&b64_decode(&ct.abe.c_tilde)?)?;
    let _ = de_g1(&b64_decode(&ct.abe.c)?)?;
    for leaf in &ct.abe.leafs {
        let _ = de_g1(&b64_decode(&leaf.c_i)?)?;
        let _ = de_g2(&b64_decode(&leaf.c_i_prime)?)?;
    }

    let nonce = b64_decode(&ct.sym.nonce)?;
    if nonce.len() != 12 {
        return Err(anyhow!("Invalid nonce length"));
    }
    let ciphertext = b64_decode(&ct.sym.ciphertext)?;
    if ciphertext.len() < 16 {
        return Err(anyhow!("Ciphertext payload is shorter than an AES-GCM tag"));
    }
    Ok(())
}

// The V1 suffix is a historical Rust API name. All objects emitted and
// accepted by this module carry CPABE_CRYPTO_VERSION == 2.
#[derive(Clone, Serialize, Deserialize)]
pub struct PublicParamsV1 {
    pub version: u8,
    #[serde(default)]
    pub system_id: String,
    pub g: String,
    pub g2: String,
    pub h: String,
    pub f: String,
    pub f2: String,
    pub y: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MasterKeyV1 {
    pub version: u8,
    #[serde(default)]
    pub system_id: String,
    pub alpha: String,
    pub beta: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PskaV1 {
    pub version: u8,
    #[serde(default)]
    pub system_id: String,
    pub d: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PsksAttrV1 {
    pub attr: String,
    pub d: String,
    pub d_prime: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PsksV1 {
    pub version: u8,
    #[serde(default)]
    pub system_id: String,
    pub attrs: Vec<PsksAttrV1>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TkV1 {
    pub version: u8,
    #[serde(default)]
    pub system_id: String,
    pub t: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AbeLeafV1 {
    pub index: u8,
    pub attr: String,
    pub c_i: String,
    pub c_i_prime: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AbeCiphertextV1 {
    pub c_tilde: String,
    pub c: String,
    pub leafs: Vec<AbeLeafV1>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SymCiphertextV1 {
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CiphertextV1 {
    pub version: u8,
    #[serde(default)]
    pub system_id: String,
    pub label: DocumentLabel,
    pub abe: AbeCiphertextV1,
    pub sym: SymCiphertextV1,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AbeIntermediateV1 {
    pub c_tilde: String,
    pub f: String,
    pub leafs: Vec<AbeLeafV1>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct IntermediateCiphertextV1 {
    pub version: u8,
    #[serde(default)]
    pub system_id: String,
    pub label: DocumentLabel,
    pub abe: AbeIntermediateV1,
    pub sym: SymCiphertextV1,
}

// logique utilisée : la crypto que l'on manipule avec des opérations (multiplication, puissances) est
// convertie/manipulée en bigint, avant d'être sérialisée puis encodée b64
// les scalaires bruts sont transformés en octets big-endian avec padding, puis encodés b64

fn b64_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(data)
}

fn b64_decode(s: &str) -> Result<Vec<u8>> {
    let v = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(s)
        .map_err(|_| anyhow!("Invalid base64"))?;
    Ok(v)
}

// transformation d'un scalaire (nombre dans un corps fini) en octets big-endian pour le stockage/transport
// big-endian = octet de poids fort en premier
// ajout d'un padding de zéros à gauche pour les entiers inférieurs à 32 bits
// renvoie un tableau de bytes avec padding sous la forme big endian
fn scalar_to_bytes_be(s: &Fr) -> [u8; 32] {
    let bi = s.into_bigint();
    let mut v = bi.to_bytes_be();
    if v.len() > 32 {
        v = v[v.len() - 32..].to_vec();
    }
    let mut out = [0u8; 32];
    let start = 32 - v.len();
    out[start..].copy_from_slice(&v);
    out
}

fn bytes_be_to_scalar(bytes: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

// la sérialisation (ser) permet de transformer un objet crypto en vecteur
// la déserialisation permet de transformer un vecteur en objet crypto

fn ser_g1(p: &G1Projective) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    p.into_affine()
        .serialize_compressed(&mut v)
        .map_err(|_| anyhow!("Serialize error"))?;
    Ok(v)
}

fn de_g1(data: &[u8]) -> Result<G1Projective> {
    let p = G1Affine::deserialize_compressed(data).map_err(|_| anyhow!("Deserialize error"))?;
    if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(anyhow!("Point is not a valid G1 subgroup element"));
    }
    Ok(p.into_group())
}

fn ser_g2(p: &G2Projective) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    p.into_affine()
        .serialize_compressed(&mut v)
        .map_err(|_| anyhow!("Serialize error"))?;
    Ok(v)
}

fn de_g2(data: &[u8]) -> Result<G2Projective> {
    let p = G2Affine::deserialize_compressed(data).map_err(|_| anyhow!("Deserialize error"))?;
    if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(anyhow!("Point is not a valid G2 subgroup element"));
    }
    Ok(p.into_group())
}

fn ser_gt(x: &Fq12) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    x.serialize_compressed(&mut v)
        .map_err(|_| anyhow!("Serialize error"))?;
    Ok(v)
}

fn de_gt(data: &[u8]) -> Result<Fq12> {
    let x = Fq12::deserialize_compressed(data).map_err(|_| anyhow!("Deserialize error"))?;
    Ok(x)
}

fn encode_attribute(attr: &str) -> Vec<u8> {
    let bytes = attr.as_bytes();
    let mut encoded = Vec::with_capacity(8 + bytes.len());
    encoded.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    encoded.extend_from_slice(bytes);
    encoded
}

fn hash_attr_g2(attr: &str) -> Result<G2Projective> {
    type Curve = ark_bls12_381::g2::Config;
    type Hasher =
        MapToCurveBasedHasher<G2Projective, DefaultFieldHasher<Sha256, 128>, WBMap<Curve>>;

    let hasher = Hasher::new(CPABE_ATTR_HASH_DST)
        .map_err(|_| anyhow!("CP-ABE attribute hasher initialization failed"))?;
    let point = hasher
        .hash(&encode_attribute(attr))
        .map_err(|_| anyhow!("CP-ABE attribute hash-to-curve failed"))?;
    if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(anyhow!(
            "CP-ABE attribute hash did not produce a valid G2 subgroup element"
        ));
    }
    Ok(point.into_group())
}
// pairing : e(a,b)

fn pairing_gt(a: G1Affine, b: G2Affine) -> Fq12 {
    Bls12_381::pairing(a, b).0
}

fn gt_pow(base: &Fq12, exp: &Fr) -> Fq12 {
    base.pow(exp.into_bigint())
}

// production de clé AES selon pairing

fn derive_sym_key(gt: &Fq12) -> Result<[u8; 32]> {
    let bytes = ser_gt(gt)?;
    let digest = sha2::Sha256::digest(&bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    Ok(out)
}

pub fn setup() -> Result<(PublicParamsV1, MasterKeyV1)> {
    let mut rng = rand_core::OsRng;
    // un générateur (g ou g2) est un point de G1/G2 qui permet de reconstruire tous les autres
    // du corps via multiplication, sachant que les groupes sont définis dans la lib
    let g = G1Projective::generator();
    let g2 = G2Projective::generator();

    // Fr signifie élément du corps fini (scalaire), et le modulo est très grand
    let alpha = Fr::rand(&mut rng);
    let mut beta = Fr::rand(&mut rng);
    while beta.is_zero() {
        beta = Fr::rand(&mut rng);
    }

    let beta_inv = beta
        .inverse()
        .ok_or_else(|| anyhow!("beta inverse missing"))?;

    // dans PM23 g^beta (groupe cyclique) correspond à g*beta en scalaire
    let h = g.mul_bigint(beta.into_bigint());
    let f = g.mul_bigint(beta_inv.into_bigint());
    let f2 = g2.mul_bigint(beta_inv.into_bigint());
    let base_gt = pairing_gt(g.into_affine(), g2.into_affine());
    let y = gt_pow(&base_gt, &alpha);

    let mut pp = PublicParamsV1 {
        version: CPABE_CRYPTO_VERSION,
        system_id: String::new(),
        g: b64_encode(&ser_g1(&g)?),
        g2: b64_encode(&ser_g2(&g2)?),
        h: b64_encode(&ser_g1(&h)?),
        f: b64_encode(&ser_g1(&f)?),
        // f2 n'est pas décrit dans le papier car on utilise G1+G2 ici, et pas seulement G0 (sécurité)
        f2: b64_encode(&ser_g2(&f2)?),
        y: b64_encode(&ser_gt(&y)?),
        // on n'utilise pas h1...hn car ils sont de toute manière dérivés dans keygen/delegate/encrypt
    };
    pp.system_id = public_params_id(&pp)?;

    let msk = MasterKeyV1 {
        version: CPABE_CRYPTO_VERSION,
        system_id: pp.system_id.clone(),
        // on encode alpha et non g^alpha pour garder de la flexibilité pour keygen/delegate
        alpha: b64_encode(&scalar_to_bytes_be(&alpha)),
        beta: b64_encode(&scalar_to_bytes_be(&beta)),
        // pas de stockage de r1...rn car non utilisés ici (mais dans keygen/delegate/encrypt -> pas de pré-listage d'attributs au Setup)
    };

    // utilisation de Ok() pour correspondre au Result du prototype de la fonction
    // Ok() permet de gérer plus proprement les erreurs
    Ok((pp, msk))
}

pub fn keygen(
    pp: &PublicParamsV1,
    msk: &MasterKeyV1,
    attrs: &[String],
) -> Result<(PskaV1, PsksV1)> {
    ensure_version(pp.version, "public parameters")?;
    ensure_version(msk.version, "master key")?;
    let pp_id = public_params_id(pp)?;
    check_system_id(&pp_id, &msk.system_id, "master key")?;

    // génération de D (PSKA), D' et D'' (PSKS) : ces trois paramètres sont constitutifs de SK dans BSW07
    let mut rng = rand_core::OsRng;
    let g1 = de_g1(&b64_decode(&pp.g)?)?;
    let g2 = de_g2(&b64_decode(&pp.g2)?)?;

    let alpha = bytes_be_to_scalar(&b64_decode(&msk.alpha)?);
    let beta = bytes_be_to_scalar(&b64_decode(&msk.beta)?);
    let beta_inv = beta
        .inverse()
        .ok_or_else(|| anyhow!("beta inverse missing"))?;

    let r = Fr::rand(&mut rng);
    let exp = (alpha + r) * beta_inv;
    // génération de D, élément de la PSKA
    let d = g2.mul_bigint(exp.into_bigint());

    let mut entries = Vec::new();
    let g2_r = g2.mul_bigint(r.into_bigint());

    for attr in attrs.iter() {
        let r_i = Fr::rand(&mut rng);
        let h = hash_attr_g2(attr)?;
        let h_ri = h.mul_bigint(r_i.into_bigint());
        // une multiplication d'éléments du groupe (dans PM23) correspond à une somme
        let d_i = g2_r + h_ri;
        let d_i_prime = g1.mul_bigint(r_i.into_bigint());

        entries.push(PsksAttrV1 {
            attr: attr.clone(),
            d: b64_encode(&ser_g2(&d_i)?),
            d_prime: b64_encode(&ser_g1(&d_i_prime)?),
        });
    }

    // tri des attributs par ordre alphabétique
    entries.sort_by(|a, b| a.attr.cmp(&b.attr));

    let pska = PskaV1 {
        version: CPABE_CRYPTO_VERSION,
        system_id: pp_id.clone(),
        d: b64_encode(&ser_g2(&d)?),
    };

    let psks = PsksV1 {
        version: CPABE_CRYPTO_VERSION,
        system_id: pp_id,
        attrs: entries,
    };

    Ok((pska, psks))
}

pub fn delegate(
    pp: &PublicParamsV1,
    psks_in: &PsksV1,
    delegated_attrs: &[String],
) -> Result<(PsksV1, TkV1)> {
    ensure_version(pp.version, "public parameters")?;
    ensure_version(psks_in.version, "PSKS")?;
    let pp_id = public_params_id(pp)?;
    check_system_id(&pp_id, &psks_in.system_id, "PSKS")?;

    let mut rng = rand_core::OsRng;
    let g1 = de_g1(&b64_decode(&pp.g)?)?;
    let g2 = de_g2(&b64_decode(&pp.g2)?)?;
    let f2 = de_g2(&b64_decode(&pp.f2)?)?;

    let hat_r = Fr::rand(&mut rng);
    let g2_hat_r = g2.mul_bigint(hat_r.into_bigint());

    let mut out_entries = Vec::new();

    for a in delegated_attrs.iter() {
        // déconstruction de PSKS_in ici
        let entry = psks_in
            .attrs
            .iter()
            .find(|e| e.attr == *a)
            .ok_or_else(|| anyhow!("Attribute not found in PSKS"))?;
        let d = de_g2(&b64_decode(&entry.d)?)?;
        let d_prime = de_g1(&b64_decode(&entry.d_prime)?)?;

        let hat_r_i = Fr::rand(&mut rng);
        let h = hash_attr_g2(&entry.attr)?;
        let h_hat_r_i = h.mul_bigint(hat_r_i.into_bigint());
        let g1_hat_r_i = g1.mul_bigint(hat_r_i.into_bigint());

        let new_d = d + g2_hat_r + h_hat_r_i;
        let new_d_prime = d_prime + g1_hat_r_i;

        out_entries.push(PsksAttrV1 {
            attr: entry.attr.clone(),
            d: b64_encode(&ser_g2(&new_d)?),
            // oubli dans le schéma de PM23 : D seconde doit être intégré dans PSKS pour pouvoir déchiffrer
            // BSW07 intègre Dj_seconde_hat de la sorte : Dj_seconde . g^rj_hat
            // ce qui est intégré ici :
            d_prime: b64_encode(&ser_g1(&new_d_prime)?),
        });
    }

    out_entries.sort_by(|a, b| a.attr.cmp(&b.attr));

    let tk_point = f2.mul_bigint(hat_r.into_bigint());
    let tk = TkV1 {
        version: CPABE_CRYPTO_VERSION,
        system_id: pp_id.clone(),
        t: b64_encode(&ser_g2(&tk_point)?),
    };

    Ok((
        PsksV1 {
            version: CPABE_CRYPTO_VERSION,
            system_id: pp_id,
            attrs: out_entries,
        },
        tk,
    ))
}

pub fn tm_delegate(pska_in: &PskaV1, tk: &TkV1) -> Result<PskaV1> {
    ensure_version(pska_in.version, "PSKA")?;
    ensure_version(tk.version, "transformation key")?;
    check_system_id(&pska_in.system_id, &tk.system_id, "transformation key")?;

    let d = de_g2(&b64_decode(&pska_in.d)?)?;

    // analytiquement, on a : g^((alpha+r)/beta)*f_2^r_hat=g^((alpha+r)/beta)*g^r_hat/beta=g^((alpha+r+r_hat)/beta)
    // ce qui nous permet de garder le nouveau random dans la nouvelle PSKA
    let t = de_g2(&b64_decode(&tk.t)?)?;
    let new_d = d + t;

    Ok(PskaV1 {
        version: CPABE_CRYPTO_VERSION,
        system_id: pska_in.system_id.clone(),
        d: b64_encode(&ser_g2(&new_d)?),
    })
}

pub fn encrypt(pp: &PublicParamsV1, label: &DocumentLabel, message: &str) -> Result<CiphertextV1> {
    ensure_version(pp.version, "public parameters")?;
    let pp_id = public_params_id(pp)?;

    let mut rng = rand_core::OsRng;

    let g = de_g1(&b64_decode(&pp.g)?)?;
    let g2 = de_g2(&b64_decode(&pp.g2)?)?;
    let h = de_g1(&b64_decode(&pp.h)?)?;
    let y = de_gt(&b64_decode(&pp.y)?)?;

    let s = Fr::rand(&mut rng);
    let a = Fr::rand(&mut rng);

    let share1 = s + a;
    let share2 = s + a + a;

    let base_gt = pairing_gt(g.into_affine(), g2.into_affine());
    let t = Fr::rand(&mut rng);
    let m_gt = base_gt.pow(t.into_bigint());

    let aes_key_bytes = derive_sym_key(&m_gt)?;
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);

    let key = Key::<Aes256Gcm>::from_slice(&aes_key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, message.as_bytes())
        .map_err(|_| anyhow!("AES encrypt failed"))?;

    let y_s = gt_pow(&y, &s);
    let c_tilde = m_gt * y_s;
    let c = h.mul_bigint(s.into_bigint());

    let leaf1_attr = label.classification.clone();
    let leaf2_attr = label.mission.clone();

    let c1 = g.mul_bigint(share1.into_bigint());
    let h1 = hash_attr_g2(&leaf1_attr)?;
    let c1p = h1.mul_bigint(share1.into_bigint());

    let c2 = g.mul_bigint(share2.into_bigint());
    let h2 = hash_attr_g2(&leaf2_attr)?;
    let c2p = h2.mul_bigint(share2.into_bigint());

    // ici, on a la structure d'accès "Classification AND Mission" : 2 feuilles
    // racine = AND, possède l'équation de noeud q(z)=s+az (degré 1 car threshold-1 = 2-1 = 1)
    // feuille 1 hérite de la racine mais au degré 0 -> q=s+a -> Ci=g^sa -> Ci'=h_1^sa
    // feuille 2 hérite aussi de la racine mais avec "2a" -> q=s+a+a -> Ci=g^sa² -> Ci'=h_2^sa²
    // pas de notation de la racine car les feuilles portent implicitement le AND
    let leafs = vec![
        AbeLeafV1 {
            index: 1,
            attr: leaf1_attr,
            c_i: b64_encode(&ser_g1(&c1)?),
            c_i_prime: b64_encode(&ser_g2(&c1p)?),
        },
        AbeLeafV1 {
            index: 2,
            attr: leaf2_attr,
            c_i: b64_encode(&ser_g1(&c2)?),
            c_i_prime: b64_encode(&ser_g2(&c2p)?),
        },
    ];

    // c_tilde vaut ici e(g,g)^(t+alpha*s), t représente un nouvel aléa utilisé dans Encrypt
    // s représente le secret de session (spécifié dans PM23)
    // pas d'instanciation de C(x,y)childj car on ne fonctionne qu'avec 2 feuilles
    // sur un AND+OR on en aurait besoin (car noeuds intermédiaires)
    Ok(CiphertextV1 {
        version: CPABE_CRYPTO_VERSION,
        system_id: pp_id,
        label: label.clone(),
        abe: AbeCiphertextV1 {
            c_tilde: b64_encode(&ser_gt(&c_tilde)?),
            c: b64_encode(&ser_g1(&c)?),
            leafs,
        },
        sym: SymCiphertextV1 {
            nonce: b64_encode(&nonce_bytes),
            ciphertext: b64_encode(&ciphertext),
        },
    })
}

/// Encrypt with a validated flat AND policy.
///
/// `label` remains application metadata. The CP-ABE policy is represented by
/// the attributes and indices stored in `abe.leafs`; it is therefore possible
/// for an experimental policy to differ from the two business dimensions in
/// `DocumentLabel` without changing the application-level authorization code.
#[allow(dead_code)]
pub fn encrypt_with_policy(
    pp: &PublicParamsV1,
    label: &DocumentLabel,
    policy: &AndPolicy,
    message: &str,
) -> Result<CiphertextV1> {
    ensure_version(pp.version, "public parameters")?;
    let indexed_attrs = policy.indexed_attrs()?;
    let pp_id = public_params_id(pp)?;

    let mut rng = rand_core::OsRng;

    let g = de_g1(&b64_decode(&pp.g)?)?;
    let g2 = de_g2(&b64_decode(&pp.g2)?)?;
    let h = de_g1(&b64_decode(&pp.h)?)?;
    let y = de_gt(&b64_decode(&pp.y)?)?;

    let s = Fr::rand(&mut rng);
    let coefficients = random_secret_polynomial(s, indexed_attrs.len())?;

    let base_gt = pairing_gt(g.into_affine(), g2.into_affine());
    let t = Fr::rand(&mut rng);
    let m_gt = base_gt.pow(t.into_bigint());

    let aes_key_bytes = derive_sym_key(&m_gt)?;
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);

    let key = Key::<Aes256Gcm>::from_slice(&aes_key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, message.as_bytes())
        .map_err(|_| anyhow!("AES encrypt failed"))?;

    let y_s = gt_pow(&y, &s);
    let c_tilde = m_gt * y_s;
    let c = h.mul_bigint(s.into_bigint());

    let leafs = indexed_attrs
        .into_iter()
        .map(|(index, attr)| {
            let q_i = evaluate_polynomial(&coefficients, Fr::from(index as u64))?;
            let c_i = g.mul_bigint(q_i.into_bigint());
            let h_i = hash_attr_g2(&attr)?;
            let c_i_prime = h_i.mul_bigint(q_i.into_bigint());

            Ok(AbeLeafV1 {
                index,
                attr,
                c_i: b64_encode(&ser_g1(&c_i)?),
                c_i_prime: b64_encode(&ser_g2(&c_i_prime)?),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    if leafs.len() != policy.attrs.len() {
        return Err(anyhow!(
            "generated ciphertext leaf count does not match the AND policy"
        ));
    }

    Ok(CiphertextV1 {
        version: CPABE_CRYPTO_VERSION,
        system_id: pp_id,
        label: label.clone(),
        abe: AbeCiphertextV1 {
            c_tilde: b64_encode(&ser_gt(&c_tilde)?),
            c: b64_encode(&ser_g1(&c)?),
            leafs,
        },
        sym: SymCiphertextV1 {
            nonce: b64_encode(&nonce_bytes),
            ciphertext: b64_encode(&ciphertext),
        },
    })
}

pub fn tm_decrypt(
    pp: &PublicParamsV1,
    ct: &CiphertextV1,
    pska: &PskaV1,
) -> Result<IntermediateCiphertextV1> {
    ensure_version(pp.version, "public parameters")?;
    ensure_version(ct.version, "ciphertext")?;
    ensure_version(pska.version, "PSKA")?;
    let pp_id = public_params_id(pp)?;
    check_system_id(&pp_id, &ct.system_id, "ciphertext")?;
    check_system_id(&pp_id, &pska.system_id, "PSKA")?;
    validate_ciphertext(ct)?;

    let c = de_g1(&b64_decode(&ct.abe.c)?)?;
    let d = de_g2(&b64_decode(&pska.d)?)?;

    let f = pairing_gt(c.into_affine(), d.into_affine());

    // TM_Decrypt : reprise de tous les éléments de CT sauf f (qui remplace c, qui a été pairé avec PSKA)
    Ok(IntermediateCiphertextV1 {
        version: CPABE_CRYPTO_VERSION,
        system_id: pp_id,
        label: ct.label.clone(),
        abe: AbeIntermediateV1 {
            c_tilde: ct.abe.c_tilde.clone(),
            f: b64_encode(&ser_gt(&f)?),
            leafs: ct.abe.leafs.clone(),
        },
        sym: ct.sym.clone(),
    })
}

pub fn decrypt(
    pp: &PublicParamsV1,
    cti: &IntermediateCiphertextV1,
    psks: &PsksV1,
) -> Result<String> {
    ensure_version(pp.version, "public parameters")?;
    ensure_version(cti.version, "intermediate ciphertext")?;
    ensure_version(psks.version, "PSKS")?;
    let pp_id = public_params_id(pp)?;
    check_system_id(&pp_id, &cti.system_id, "intermediate ciphertext")?;
    check_system_id(&pp_id, &psks.system_id, "PSKS")?;
    validate_ciphertext_leaf_structure(&cti.abe.leafs)?;

    let c_tilde = de_gt(&b64_decode(&cti.abe.c_tilde)?)?;
    let f = de_gt(&b64_decode(&cti.abe.f)?)?;

    let mut res_map: Vec<(Fr, Fq12)> = Vec::with_capacity(cti.abe.leafs.len());

    // Application de la méthode "DecryptLeafNode" de PM23 à chaque feuille.
    for leaf in cti.abe.leafs.iter() {
        let sk = psks
            .attrs
            .iter()
            .find(|e| e.attr == leaf.attr)
            .ok_or_else(|| anyhow!("Missing attribute in PSKS"))?;

        let c_i = de_g1(&b64_decode(&leaf.c_i)?)?;
        let c_i_prime = de_g2(&b64_decode(&leaf.c_i_prime)?)?;
        let d_i = de_g2(&b64_decode(&sk.d)?)?;
        let d_i_prime = de_g1(&b64_decode(&sk.d_prime)?)?;

        let num = pairing_gt(c_i.into_affine(), d_i.into_affine());
        let den = pairing_gt(d_i_prime.into_affine(), c_i_prime.into_affine());
        let den_inv = den
            .inverse()
            .ok_or_else(|| anyhow!("Invalid pairing result"))?;
        let res = num * den_inv;

        res_map.push((Fr::from(leaf.index as u64), res));
    }

    // F_root = product_i F_i^lambda_i(0), with the same positions used by
    // encrypt_with_policy. For two leaves this is F1^2 * F2^(-1).
    let f_root = reconstruct_gt_at_zero(&res_map)?;

    // utilisation de la formule de BSW07 (ambiguïté dans PM23) : message = c_tilde / e(C,D) / A
    // ce qui correspond dans notre cas à c_tilde / f / f_root
    let f_root_inv = f_root
        .inverse()
        .ok_or_else(|| anyhow!("Invalid GT element"))?;
    let y_s = f * f_root_inv;

    let y_s_inv = y_s.inverse().ok_or_else(|| anyhow!("Invalid GT element"))?;
    let m_gt = c_tilde * y_s_inv;

    let aes_key_bytes = derive_sym_key(&m_gt)?;
    let nonce_bytes = b64_decode(&cti.sym.nonce)?;
    if nonce_bytes.len() != 12 {
        return Err(anyhow!("Invalid nonce length"));
    }
    let ciphertext = b64_decode(&cti.sym.ciphertext)?;

    let key = Key::<Aes256Gcm>::from_slice(&aes_key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| anyhow!("AES decrypt failed"))?;

    let s = String::from_utf8(plaintext).map_err(|_| anyhow!("Invalid UTF-8 message"))?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_attrs(count: usize) -> Vec<String> {
        (1..=count).map(|i| format!("A{i:03}")).collect()
    }

    fn assert_ciphertext_group_components_are_valid(ct: &CiphertextV1) -> Result<()> {
        de_gt(&b64_decode(&ct.abe.c_tilde)?)?;
        let _ = de_g1(&b64_decode(&ct.abe.c)?)?;
        for leaf in &ct.abe.leafs {
            let _ = de_g1(&b64_decode(&leaf.c_i)?)?;
            let _ = de_g2(&b64_decode(&leaf.c_i_prime)?)?;
        }
        Ok(())
    }

    #[test]
    fn and_policy_accepts_requested_cardinalities_and_assigns_stable_indices() -> Result<()> {
        for count in [1, 2, 5, 10, 20, 50] {
            let mut attrs = policy_attrs(count);
            attrs.reverse();
            let policy = AndPolicy::new(attrs)?;

            assert_eq!(policy.attrs, policy_attrs(count));
            let indexed = policy.indexed_attrs()?;
            assert_eq!(indexed.len(), count);
            for (offset, (index, attr)) in indexed.iter().enumerate() {
                assert_eq!(*index, (offset + 1) as u8);
                assert_eq!(attr, &format!("A{:03}", offset + 1));
            }
        }
        Ok(())
    }

    #[test]
    fn and_policy_rejects_empty_empty_attribute_duplicate_and_oversized_inputs() {
        assert!(AndPolicy::new(Vec::new()).is_err());
        assert!(AndPolicy::new(vec![String::new()]).is_err());
        assert!(AndPolicy::new(vec!["A".to_string(), "A".to_string()]).is_err());

        let oversized = (0..=u8::MAX).map(|i| format!("A{i}")).collect::<Vec<_>>();
        assert!(AndPolicy::new(oversized).is_err());
    }

    #[test]
    fn and_policy_rejects_invalid_public_struct_values() {
        let empty = AndPolicy { attrs: Vec::new() };
        assert!(empty.validate().is_err());

        let duplicate = AndPolicy {
            attrs: vec!["A".to_string(), "A".to_string()],
        };
        assert!(duplicate.validate().is_err());
    }

    #[test]
    fn lagrange_coefficients_match_single_and_two_leaf_cases() -> Result<()> {
        let single = lagrange_coefficients_at_zero(&[Fr::from(1u64)])?;
        assert_eq!(single, vec![Fr::from(1u64)]);

        let two = lagrange_coefficients_at_zero(&[Fr::from(1u64), Fr::from(2u64)])?;
        assert_eq!(two, vec![Fr::from(2u64), -Fr::from(1u64)]);
        Ok(())
    }

    #[test]
    fn lagrange_rejects_empty_zero_and_duplicate_points() {
        assert!(lagrange_coefficients_at_zero(&[]).is_err());
        assert!(lagrange_coefficients_at_zero(&[Fr::from(0u64)]).is_err());
        assert!(lagrange_coefficients_at_zero(&[Fr::from(1u64), Fr::from(1u64)]).is_err());
    }

    #[test]
    fn polynomial_reconstruction_is_exact_for_all_target_cardinalities() -> Result<()> {
        let mut rng = rand_core::OsRng;

        for count in [1, 2, 5, 10, 20, 50] {
            for _ in 0..8 {
                let secret = Fr::rand(&mut rng);
                let coefficients = random_secret_polynomial(secret, count)?;
                assert_eq!(coefficients.len(), count);

                let parts = (1..=count)
                    .map(|index| {
                        let x = Fr::from(index as u64);
                        let share = evaluate_polynomial(&coefficients, x)?;
                        Ok((x, share))
                    })
                    .collect::<Result<Vec<_>>>()?;

                assert_eq!(reconstruct_secret_at_zero(&parts)?, secret);

                let mut permuted = parts.clone();
                permuted.reverse();
                assert_eq!(reconstruct_secret_at_zero(&permuted)?, secret);
            }
        }
        Ok(())
    }

    #[test]
    fn encrypt_with_policy_builds_exactly_n_valid_leaves() -> Result<()> {
        let (pp, _msk) = setup()?;
        let pp_before = serde_json::to_string(&pp)?;
        let label = DocumentLabel {
            classification: "BUSINESS-CLASSIFICATION".to_string(),
            mission: "BUSINESS-MISSION".to_string(),
        };

        for count in [1, 2, 5, 10, 20, 50] {
            let policy = AndPolicy::new(policy_attrs(count))?;
            let ciphertext = encrypt_with_policy(&pp, &label, &policy, "AND policy test")?;

            assert_eq!(ciphertext.abe.leafs.len(), count);
            assert_eq!(ciphertext.system_id, public_params_id(&pp)?);
            assert_eq!(ciphertext.label.classification, label.classification);
            assert_eq!(ciphertext.label.mission, label.mission);

            let attrs = ciphertext
                .abe
                .leafs
                .iter()
                .map(|leaf| leaf.attr.clone())
                .collect::<Vec<_>>();
            assert_eq!(attrs, policy.attrs);

            let indices = ciphertext
                .abe
                .leafs
                .iter()
                .map(|leaf| leaf.index)
                .collect::<Vec<_>>();
            assert_eq!(indices, (1..=count).map(|i| i as u8).collect::<Vec<_>>());
            assert_ciphertext_group_components_are_valid(&ciphertext)?;

            let serialized = serde_json::to_string(&ciphertext)?;
            let roundtrip: CiphertextV1 = serde_json::from_str(&serialized)?;
            assert_eq!(serde_json::to_string(&roundtrip)?, serialized);
            assert_ciphertext_group_components_are_valid(&roundtrip)?;
        }

        assert_eq!(serde_json::to_string(&pp)?, pp_before);
        Ok(())
    }

    #[test]
    fn encrypt_with_policy_two_leaves_is_compatible_with_historical_decrypt() -> Result<()> {
        let (pp, msk) = setup()?;
        let attrs = vec!["FR-DR".to_string(), "MISSION-TEST".to_string()];
        let policy = AndPolicy::new(attrs.clone())?;
        let label = DocumentLabel {
            classification: attrs[0].clone(),
            mission: attrs[1].clone(),
        };
        let message = "two-leaf policy compatibility";
        let (pska, psks) = keygen(&pp, &msk, &attrs)?;

        let ciphertext = encrypt_with_policy(&pp, &label, &policy, message)?;
        let intermediate = tm_decrypt(&pp, &ciphertext, &pska)?;
        assert_eq!(decrypt(&pp, &intermediate, &psks)?, message);
        Ok(())
    }

    #[test]
    fn decrypt_with_policy_supports_all_target_cardinalities_after_tm_decrypt() -> Result<()> {
        let (pp, msk) = setup()?;
        let label = DocumentLabel {
            classification: "BUSINESS-CLASSIFICATION".to_string(),
            mission: "BUSINESS-MISSION".to_string(),
        };

        for count in [1, 2, 5, 10, 20, 50] {
            let attrs = policy_attrs(count);
            let policy = AndPolicy::new(attrs.clone())?;
            let (pska, psks) = keygen(&pp, &msk, &attrs)?;
            let message = format!("generic decrypt with {count} leaves");
            let ciphertext = encrypt_with_policy(&pp, &label, &policy, &message)?;

            let serialized = serde_json::to_string(&ciphertext)?;
            let roundtrip: CiphertextV1 = serde_json::from_str(&serialized)?;
            let intermediate = tm_decrypt(&pp, &roundtrip, &pska)?;
            assert_eq!(decrypt(&pp, &intermediate, &psks)?, message);

            let mut reordered = intermediate;
            reordered.abe.leafs.reverse();
            assert_eq!(decrypt(&pp, &reordered, &psks)?, message);
        }
        Ok(())
    }

    #[test]
    fn decrypt_rejects_missing_required_attributes_for_all_target_cardinalities() -> Result<()> {
        let (pp, msk) = setup()?;
        let label = DocumentLabel {
            classification: "BUSINESS-CLASSIFICATION".to_string(),
            mission: "BUSINESS-MISSION".to_string(),
        };

        for count in [1, 2, 5, 10, 20, 50] {
            let attrs = policy_attrs(count);
            let policy = AndPolicy::new(attrs.clone())?;
            let ciphertext = encrypt_with_policy(&pp, &label, &policy, "missing attribute")?;

            let mut missing_indices = vec![0];
            if count > 1 {
                missing_indices.push(count / 2);
            }
            if count > 1 && count - 1 != count / 2 {
                missing_indices.push(count - 1);
            }

            for missing_index in missing_indices {
                let available = attrs
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| *index != missing_index)
                    .map(|(_, attr)| attr.clone())
                    .collect::<Vec<_>>();
                let (pska, psks) = keygen(&pp, &msk, &available)?;
                let intermediate = tm_decrypt(&pp, &ciphertext, &pska)?;
                let error = decrypt(&pp, &intermediate, &psks)
                    .expect_err("a missing policy attribute must be rejected")
                    .to_string();
                assert_eq!(error, "Missing attribute in PSKS");
            }
        }
        Ok(())
    }

    #[test]
    fn decrypt_accepts_extra_attributes_beyond_the_policy() -> Result<()> {
        let (pp, msk) = setup()?;
        let label = DocumentLabel {
            classification: "BUSINESS-CLASSIFICATION".to_string(),
            mission: "BUSINESS-MISSION".to_string(),
        };

        for count in [1, 2, 5, 10, 20, 50] {
            let attrs = policy_attrs(count);
            let policy = AndPolicy::new(attrs.clone())?;
            let mut key_attrs = attrs.clone();
            key_attrs.extend(["EXTRA-A".to_string(), "EXTRA-B".to_string()]);
            let (pska, psks) = keygen(&pp, &msk, &key_attrs)?;
            let ciphertext = encrypt_with_policy(&pp, &label, &policy, "extra attributes")?;
            let intermediate = tm_decrypt(&pp, &ciphertext, &pska)?;

            assert_eq!(decrypt(&pp, &intermediate, &psks)?, "extra attributes");
        }
        Ok(())
    }

    #[test]
    fn decrypt_rejects_invalid_leaf_indices_and_group_components() -> Result<()> {
        let (pp, msk) = setup()?;
        let attrs = policy_attrs(2);
        let policy = AndPolicy::new(attrs.clone())?;
        let (pska, psks) = keygen(&pp, &msk, &attrs)?;
        let ciphertext = encrypt_with_policy(
            &pp,
            &DocumentLabel {
                classification: "BUSINESS-CLASSIFICATION".to_string(),
                mission: "BUSINESS-MISSION".to_string(),
            },
            &policy,
            "invalid leaf structure",
        )?;
        let intermediate = tm_decrypt(&pp, &ciphertext, &pska)?;

        let mut duplicate_index = intermediate.clone();
        duplicate_index.abe.leafs[1].index = 1;
        assert!(decrypt(&pp, &duplicate_index, &psks)
            .expect_err("duplicate indices must be rejected")
            .to_string()
            .contains("distinct"));

        let mut zero_index = intermediate.clone();
        zero_index.abe.leafs[0].index = 0;
        assert!(decrypt(&pp, &zero_index, &psks)
            .expect_err("zero indices must be rejected")
            .to_string()
            .contains("non-zero"));

        let mut out_of_range_index = intermediate.clone();
        out_of_range_index.abe.leafs[1].index = 3;
        assert!(decrypt(&pp, &out_of_range_index, &psks)
            .expect_err("out-of-range indices must be rejected")
            .to_string()
            .contains("contiguous"));

        let mut empty_leaf_set = intermediate.clone();
        empty_leaf_set.abe.leafs.clear();
        assert!(decrypt(&pp, &empty_leaf_set, &psks)
            .expect_err("an empty policy must be rejected")
            .to_string()
            .contains("at least one"));

        let mut malformed_point = intermediate;
        malformed_point.abe.leafs[0].c_i_prime = b64_encode(&[0u8; 8]);
        assert!(decrypt(&pp, &malformed_point, &psks).is_err());
        Ok(())
    }

    #[test]
    fn historical_encrypt_preserves_equal_label_attributes() -> Result<()> {
        let (pp, msk) = setup()?;
        let label = DocumentLabel {
            classification: "SAME-ATTRIBUTE".to_string(),
            mission: "SAME-ATTRIBUTE".to_string(),
        };
        let attrs = vec![label.classification.clone()];
        let (pska, psks) = keygen(&pp, &msk, &attrs)?;

        let ciphertext = encrypt(&pp, &label, "historical equal label")?;
        assert_eq!(ciphertext.abe.leafs.len(), 2);
        assert_eq!(ciphertext.abe.leafs[0].attr, label.classification);
        assert_eq!(ciphertext.abe.leafs[1].attr, label.mission);

        let intermediate = tm_decrypt(&pp, &ciphertext, &pska)?;
        assert_eq!(
            decrypt(&pp, &intermediate, &psks)?,
            "historical equal label"
        );
        Ok(())
    }

    #[test]
    fn cpabe_abe_decrypt_does_not_authenticate_document_label_metadata() -> Result<()> {
        let (pp, msk) = setup()?;
        let attrs = vec!["FR-DR".to_string(), "MISSION-TEST".to_string()];
        let (pska, psks) = keygen(&pp, &msk, &attrs)?;
        let label = DocumentLabel {
            classification: attrs[0].clone(),
            mission: attrs[1].clone(),
        };
        let ciphertext = encrypt(&pp, &label, "label metadata audit")?;
        let mut altered = ciphertext.clone();
        altered.label.classification = "ALTERED-LABEL".to_string();

        validate_ciphertext(&altered)?;
        let intermediate = tm_decrypt(&pp, &altered, &pska)?;
        assert_eq!(decrypt(&pp, &intermediate, &psks)?, "label metadata audit");
        Ok(())
    }

    #[test]
    fn cpabe_hybrid_roundtrip_decrypts_aes_payload() -> Result<()> {
        let (pp, msk) = setup()?;
        let attrs = vec!["FR-S".to_string(), "FR-DR".to_string(), "M1".to_string()];
        let (pska, psks) = keygen(&pp, &msk, &attrs)?;
        let label = DocumentLabel {
            classification: "FR-S".to_string(),
            mission: "M1".to_string(),
        };

        let ct = encrypt(&pp, &label, "hello d3cs")?;
        let cti = tm_decrypt(&pp, &ct, &pska)?;
        let msg = decrypt(&pp, &cti, &psks)?;

        assert_eq!(msg, "hello d3cs");
        let mut tampered_cti = cti;
        let mut tampered_payload = b64_decode(&tampered_cti.sym.ciphertext)?;
        tampered_payload[0] ^= 1;
        tampered_cti.sym.ciphertext = b64_encode(&tampered_payload);
        assert!(decrypt(&pp, &tampered_cti, &psks).is_err());
        Ok(())
    }

    #[test]
    fn cpabe_attribute_component_forgery_breaks_unsatisfied_policy() -> Result<()> {
        let (pp, msk) = setup()?;
        let classification = "FR-DR";
        let mission = "MISSION-TEST";
        let attrs = vec![classification.to_string()];
        let (pska, initial_psks) = keygen(&pp, &msk, &attrs)?;
        let label = DocumentLabel {
            classification: classification.to_string(),
            mission: mission.to_string(),
        };
        let message = "CP-ABE attribute forgery regression";

        let ct = encrypt(&pp, &label, message)?;
        let cti = tm_decrypt(&pp, &ct, &pska)?;

        let initial_error = decrypt(&pp, &cti, &initial_psks)
            .expect_err("a PSKS containing only FR-DR must not satisfy FR-DR AND MISSION-TEST")
            .to_string();
        assert_eq!(initial_error, "Missing attribute in PSKS");

        let source = initial_psks
            .attrs
            .iter()
            .find(|entry| entry.attr == classification)
            .ok_or_else(|| anyhow!("missing source attribute in generated PSKS"))?;
        let g1 = de_g1(&b64_decode(&pp.g)?)?;
        let source_d = source.d.clone();

        // The former exploit required D'_i to be a G2 element and H(i) to be
        // a publicly known scalar multiple of g2. In the current implementation
        // D'_i is G1,
        // while H_attr(i) is an independently hashed G2 point.
        assert!(de_g2(&b64_decode(&source.d_prime)?).is_err());

        // Adding only the missing name must not make the key satisfy the
        // policy, even when the existing component is copied verbatim.
        let mut name_only_attrs = initial_psks.attrs.clone();
        name_only_attrs.push(PsksAttrV1 {
            attr: mission.to_string(),
            d: source_d.clone(),
            d_prime: source.d_prime.clone(),
        });
        name_only_attrs.sort_by(|left, right| left.attr.cmp(&right.attr));
        let name_only_psks = PsksV1 {
            version: initial_psks.version,
            system_id: initial_psks.system_id.clone(),
            attrs: name_only_attrs,
        };
        assert!(decrypt(&pp, &cti, &name_only_psks).is_err());

        // Also try a syntactically valid pair of points unrelated to the
        // missing attribute. This exercises the cryptographic equation rather
        // than an application-level attribute-name filter.
        let mut valid_point_attrs = initial_psks.attrs.clone();
        valid_point_attrs.push(PsksAttrV1 {
            attr: mission.to_string(),
            d: source_d,
            d_prime: b64_encode(&ser_g1(&g1)?),
        });
        valid_point_attrs.sort_by(|left, right| left.attr.cmp(&right.attr));
        let valid_point_psks = PsksV1 {
            version: initial_psks.version,
            system_id: initial_psks.system_id.clone(),
            attrs: valid_point_attrs,
        };
        assert!(decrypt(&pp, &cti, &valid_point_psks).is_err());

        let both_attrs = vec![classification.to_string(), mission.to_string()];
        let (both_pska, both_psks) = keygen(&pp, &msk, &both_attrs)?;
        let both_cti = tm_decrypt(&pp, &ct, &both_pska)?;
        assert_eq!(decrypt(&pp, &both_cti, &both_psks)?, message);

        Ok(())
    }

    #[test]
    fn cpabe_independent_user_collusion_does_not_satisfy_and_policy() -> Result<()> {
        let (pp, msk) = setup()?;
        let classification = "FR-DR".to_string();
        let mission = "MISSION-TEST".to_string();
        let label = DocumentLabel {
            classification: classification.clone(),
            mission: mission.clone(),
        };
        let message = "CP-ABE collusion regression";

        for _generation in 0..8 {
            let (u1_pska, u1_psks) = keygen(&pp, &msk, std::slice::from_ref(&classification))?;
            let (u2_pska, u2_psks) = keygen(&pp, &msk, std::slice::from_ref(&mission))?;
            assert_eq!(u1_pska.system_id, u2_pska.system_id);
            assert_eq!(u1_psks.system_id, u2_psks.system_id);
            assert_eq!(u1_pska.system_id, public_params_id(&pp)?);

            let ct = encrypt(&pp, &label, message)?;

            let u1_cti = tm_decrypt(&pp, &ct, &u1_pska)?;
            assert!(decrypt(&pp, &u1_cti, &u1_psks).is_err());
            let u2_cti = tm_decrypt(&pp, &ct, &u2_pska)?;
            assert!(decrypt(&pp, &u2_cti, &u2_psks).is_err());

            let u1_component = u1_psks
                .attrs
                .iter()
                .find(|entry| entry.attr == classification)
                .cloned()
                .ok_or_else(|| anyhow!("missing U1 classification component"))?;
            let u2_component = u2_psks
                .attrs
                .iter()
                .find(|entry| entry.attr == mission)
                .cloned()
                .ok_or_else(|| anyhow!("missing U2 mission component"))?;
            let combined_psks = PsksV1 {
                version: u1_psks.version,
                system_id: u1_psks.system_id.clone(),
                attrs: vec![u1_component, u2_component],
            };
            validate_psks(&combined_psks)?;

            let combined_u1_cti = tm_decrypt(&pp, &ct, &u1_pska)?;
            let u1_collusion_error = decrypt(&pp, &combined_u1_cti, &combined_psks)
                .expect_err("U1 PSKA must not repair a PSKS assembled from U1 and U2");
            assert_eq!(u1_collusion_error.to_string(), "AES decrypt failed");

            let combined_u2_cti = tm_decrypt(&pp, &ct, &u2_pska)?;
            let u2_collusion_error = decrypt(&pp, &combined_u2_cti, &combined_psks)
                .expect_err("U2 PSKA must not repair a PSKS assembled from U1 and U2");
            assert_eq!(u2_collusion_error.to_string(), "AES decrypt failed");

            let (legitimate_pska, legitimate_psks) =
                keygen(&pp, &msk, &[classification.clone(), mission.clone()])?;
            assert_eq!(legitimate_pska.system_id, u1_pska.system_id);
            assert_eq!(legitimate_psks.system_id, u1_psks.system_id);
            let legitimate_cti = tm_decrypt(&pp, &ct, &legitimate_pska)?;
            assert_eq!(decrypt(&pp, &legitimate_cti, &legitimate_psks)?, message);
        }

        Ok(())
    }

    #[test]
    fn cpabe_hash_to_curve_g2_is_deterministic_and_subgroup_valid() -> Result<()> {
        let first = hash_attr_g2("MISSION-TEST")?;
        let second = hash_attr_g2("MISSION-TEST")?;
        let other = hash_attr_g2("MISSION-OTHER")?;

        assert_eq!(first, second);
        assert_ne!(first, other);
        let affine = first.into_affine();
        assert!(affine.is_on_curve());
        assert!(affine.is_in_correct_subgroup_assuming_on_curve());
        Ok(())
    }

    #[test]
    fn cpabe_delegation_supports_restriction_and_successive_delegation() -> Result<()> {
        let (pp, msk) = setup()?;
        let classification = "FR-DR".to_string();
        let mission = "MISSION-TEST".to_string();
        let extra = "UNUSED".to_string();
        let attrs = vec![classification.clone(), mission.clone(), extra];
        let (pska, psks) = keygen(&pp, &msk, &attrs)?;
        let label = DocumentLabel {
            classification: classification.clone(),
            mission: mission.clone(),
        };
        let message = "delegated CP-ABE message";
        let ct = encrypt(&pp, &label, message)?;
        let delegated_attrs = vec![classification.clone(), mission.clone()];

        let (delegated_psks, tk) = delegate(&pp, &psks, &delegated_attrs)?;
        let delegated_pska = tm_delegate(&pska, &tk)?;
        let delegated_cti = tm_decrypt(&pp, &ct, &delegated_pska)?;
        assert_eq!(decrypt(&pp, &delegated_cti, &delegated_psks)?, message);

        let (successive_psks, successive_tk) = delegate(&pp, &delegated_psks, &delegated_attrs)?;
        let successive_pska = tm_delegate(&delegated_pska, &successive_tk)?;
        let successive_cti = tm_decrypt(&pp, &ct, &successive_pska)?;
        assert_eq!(decrypt(&pp, &successive_cti, &successive_psks)?, message);

        let restricted_attrs = vec![mission.clone()];
        let (restricted_psks, restricted_tk) = delegate(&pp, &psks, &restricted_attrs)?;
        let restricted_pska = tm_delegate(&pska, &restricted_tk)?;
        let restricted_cti = tm_decrypt(&pp, &ct, &restricted_pska)?;
        assert!(decrypt(&pp, &restricted_cti, &restricted_psks).is_err());
        assert!(delegate(&pp, &psks, &["ABSENT".to_string()]).is_err());
        Ok(())
    }

    #[test]
    fn cpabe_delegation_workflow_supports_all_target_cardinalities() -> Result<()> {
        let (pp, msk) = setup()?;
        let label = DocumentLabel {
            classification: "BUSINESS-CLASSIFICATION".to_string(),
            mission: "BUSINESS-MISSION".to_string(),
        };

        for count in [1, 2, 5, 10, 20, 50] {
            let attrs = policy_attrs(count);
            let policy = AndPolicy::new(attrs.clone())?;
            let mut source_attrs = attrs.clone();
            source_attrs.extend(["EXTRA-A".to_string(), "EXTRA-B".to_string()]);
            let (source_pska, source_psks) = keygen(&pp, &msk, &source_attrs)?;
            let message = format!("delegated policy with {count} leaves");
            let ciphertext = encrypt_with_policy(&pp, &label, &policy, &message)?;

            // Required attributes only: this is a strict subset of the source
            // key because the source also contains EXTRA-A and EXTRA-B.
            let (delegated_psks, tk) = delegate(&pp, &source_psks, &attrs)?;
            let delegated_pska = tm_delegate(&source_pska, &tk)?;
            let delegated_psks: PsksV1 =
                serde_json::from_str(&serde_json::to_string(&delegated_psks)?)?;
            let delegated_pska: PskaV1 =
                serde_json::from_str(&serde_json::to_string(&delegated_pska)?)?;
            let delegated_cti = tm_decrypt(&pp, &ciphertext, &delegated_pska)?;
            assert_eq!(delegated_cti.abe.leafs.len(), count);
            assert_eq!(decrypt(&pp, &delegated_cti, &delegated_psks)?, message);

            // A delegated key containing all policy attributes and an extra
            // source attribute remains valid for the same policy.
            let mut delegated_with_extra_attrs = attrs.clone();
            delegated_with_extra_attrs.push("EXTRA-A".to_string());
            let (delegated_with_extra, extra_tk) =
                delegate(&pp, &source_psks, &delegated_with_extra_attrs)?;
            let extra_pska = tm_delegate(&source_pska, &extra_tk)?;
            let extra_cti = tm_decrypt(&pp, &ciphertext, &extra_pska)?;
            assert_eq!(decrypt(&pp, &extra_cti, &delegated_with_extra)?, message);

            // Removing one required attribute from the delegated subset must
            // fail at the PSKS attribute lookup, including for N = 1.
            let missing_attrs = attrs[..attrs.len() - 1].to_vec();
            let (missing_psks, missing_tk) = delegate(&pp, &source_psks, &missing_attrs)?;
            let missing_pska = tm_delegate(&source_pska, &missing_tk)?;
            let missing_cti = tm_decrypt(&pp, &ciphertext, &missing_pska)?;
            assert_eq!(
                decrypt(&pp, &missing_cti, &missing_psks)
                    .expect_err("a delegated key missing one policy attribute must fail")
                    .to_string(),
                "Missing attribute in PSKS"
            );

            // Delegation can be applied successively while preserving the
            // complete policy subset.
            let mut first_subset = attrs.clone();
            first_subset.push("EXTRA-A".to_string());
            let (first_psks, first_tk) = delegate(&pp, &source_psks, &first_subset)?;
            let first_pska = tm_delegate(&source_pska, &first_tk)?;
            let (second_psks, second_tk) = delegate(&pp, &first_psks, &attrs)?;
            let second_pska = tm_delegate(&first_pska, &second_tk)?;
            let second_cti = tm_decrypt(&pp, &ciphertext, &second_pska)?;
            assert_eq!(decrypt(&pp, &second_cti, &second_psks)?, message);
        }
        Ok(())
    }

    #[test]
    fn validate_ciphertext_rejects_malformed_structure_and_payloads() -> Result<()> {
        let (pp, _msk) = setup()?;
        let label = DocumentLabel {
            classification: "FR-DR".to_string(),
            mission: "MISSION-TEST".to_string(),
        };
        let valid = encrypt(&pp, &label, "validation")?;
        validate_ciphertext(&valid)?;

        let mut empty = valid.clone();
        empty.abe.leafs.clear();
        assert!(validate_ciphertext(&empty).is_err());

        let mut zero_index = valid.clone();
        zero_index.abe.leafs[0].index = 0;
        assert!(validate_ciphertext(&zero_index).is_err());

        let mut duplicate_index = valid.clone();
        duplicate_index.abe.leafs[1].index = 1;
        assert!(validate_ciphertext(&duplicate_index).is_err());

        let mut non_contiguous = valid.clone();
        non_contiguous.abe.leafs[1].index = 3;
        assert!(validate_ciphertext(&non_contiguous).is_err());

        let mut empty_attribute = valid.clone();
        empty_attribute.abe.leafs[0].attr.clear();
        assert!(validate_ciphertext(&empty_attribute).is_err());

        let mut malformed_point = valid.clone();
        malformed_point.abe.leafs[0].c_i_prime = b64_encode(&[0u8; 8]);
        assert!(validate_ciphertext(&malformed_point).is_err());

        let mut malformed_gt = valid.clone();
        malformed_gt.abe.c_tilde = b64_encode(&[0u8; 8]);
        assert!(validate_ciphertext(&malformed_gt).is_err());

        let mut invalid_nonce = valid.clone();
        invalid_nonce.sym.nonce = b64_encode(&[0u8; 11]);
        assert!(validate_ciphertext(&invalid_nonce).is_err());

        let mut short_payload = valid.clone();
        short_payload.sym.ciphertext = b64_encode(&[0u8; 15]);
        assert!(validate_ciphertext(&short_payload).is_err());

        let mut oversized = valid.clone();
        oversized.abe.leafs = vec![valid.abe.leafs[0].clone(); MAX_AND_POLICY_LEAVES + 1];
        assert!(validate_ciphertext(&oversized).is_err());

        let mut truncated = serde_json::to_string(&valid)?;
        truncated.pop();
        assert!(serde_json::from_str::<CiphertextV1>(&truncated).is_err());
        Ok(())
    }

    #[test]
    fn cpabe_rejects_legacy_versions_and_tampered_points() -> Result<()> {
        let (pp, msk) = setup()?;
        let attrs = vec!["FR-DR".to_string(), "MISSION-TEST".to_string()];
        let (pska, psks) = keygen(&pp, &msk, &attrs)?;
        let label = DocumentLabel {
            classification: attrs[0].clone(),
            mission: attrs[1].clone(),
        };
        let ct = encrypt(&pp, &label, "versioned message")?;
        let cti = tm_decrypt(&pp, &ct, &pska)?;

        let mut old_pp = pp.clone();
        old_pp.version = 1;
        assert!(keygen(&old_pp, &msk, &attrs).is_err());

        let mut old_msk = msk.clone();
        old_msk.version = 1;
        assert!(keygen(&pp, &old_msk, &attrs).is_err());

        let mut old_ct = ct.clone();
        old_ct.version = 1;
        assert!(tm_decrypt(&pp, &old_ct, &pska).is_err());

        let mut old_pska = pska.clone();
        old_pska.version = 1;
        assert!(tm_decrypt(&pp, &ct, &old_pska).is_err());

        let mut old_cti = cti.clone();
        old_cti.version = 1;
        assert!(decrypt(&pp, &old_cti, &psks).is_err());

        let mut old_psks = psks.clone();
        old_psks.version = 1;
        assert!(decrypt(&pp, &cti, &old_psks).is_err());

        let mut malformed = cti;
        malformed.abe.leafs[0].c_i_prime = b64_encode(&[0u8; 8]);
        assert!(decrypt(&pp, &malformed, &psks).is_err());
        Ok(())
    }

    #[test]
    fn cpabe_system_identity_detects_independent_parameter_sets() -> Result<()> {
        let (pp_a, msk_a) = setup()?;
        let (pp_b, _msk_b) = setup()?;
        assert_ne!(public_params_id(&pp_a)?, public_params_id(&pp_b)?);

        let attrs = vec!["FR-DR".to_string(), "MISSION-TEST".to_string()];
        let (pska, psks) = keygen(&pp_a, &msk_a, &attrs)?;
        let label = DocumentLabel {
            classification: attrs[0].clone(),
            mission: attrs[1].clone(),
        };
        let ct = encrypt(&pp_a, &label, "system identity")?;
        let cti = tm_decrypt(&pp_a, &ct, &pska)?;
        assert_eq!(decrypt(&pp_a, &cti, &psks)?, "system identity");
        assert!(tm_decrypt(&pp_b, &ct, &pska).is_err());
        assert!(decrypt(&pp_b, &cti, &psks).is_err());
        Ok(())
    }

    #[test]
    fn cpabe_system_identity_rejects_tampered_association() -> Result<()> {
        let (pp, msk) = setup()?;
        let attrs = vec!["FR-DR".to_string(), "MISSION-TEST".to_string()];
        let (mut pska, mut psks) = keygen(&pp, &msk, &attrs)?;
        let mut ct = encrypt(
            &pp,
            &DocumentLabel {
                classification: attrs[0].clone(),
                mission: attrs[1].clone(),
            },
            "system identity",
        )?;
        let pp_id = public_params_id(&pp)?;
        let other_id = public_params_id(&setup()?.0)?;
        assert_ne!(pp_id, other_id);

        pska.system_id = other_id.clone();
        assert!(tm_decrypt(&pp, &ct, &pska).is_err());
        pska.system_id = pp_id.clone();
        psks.system_id = other_id.clone();
        let cti = tm_decrypt(&pp, &ct, &pska)?;
        assert!(decrypt(&pp, &cti, &psks).is_err());
        psks.system_id = pp_id.clone();
        ct.system_id = other_id;
        assert!(tm_decrypt(&pp, &ct, &pska).is_err());
        Ok(())
    }
}
