use anyhow::{anyhow, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};

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
use ark_ff::PrimeField;
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sha2::Sha256;

#[derive(Clone, Serialize, Deserialize)]
pub struct AbsParamsV1 {
    pub version: u8,
    pub d: u8,
    pub g: String,
    pub g1: String,
    pub g2: String,
    pub z: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AbsMasterKeyV1 {
    pub version: u8,
    pub x: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AbsUserKeyV1 {
    pub version: u8,
    pub attr: String,
    pub d0: String,
    pub d1: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AbsSignatureV1 {
    pub version: u8,
    pub r1: String,
    pub r2: String,
    pub r3: String,
}

fn b64_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(data)
}

fn b64_decode(s: &str) -> Result<Vec<u8>> {
    let v = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(s)
        .map_err(|_| anyhow!("Invalid base64"))?;
    Ok(v)
}

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

fn ser_g1(p: &G1Projective) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    p.into_affine()
        .serialize_compressed(&mut v)
        .map_err(|_| anyhow!("Serialize error"))?;
    Ok(v)
}

fn de_g1(data: &[u8]) -> Result<G1Projective> {
    let p = G1Affine::deserialize_compressed(data).map_err(|_| anyhow!("Deserialize error"))?;
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

fn pairing_gt(a: G1Affine, b: G2Affine) -> Fq12 {
    Bls12_381::pairing(a, b).0
}

fn hash_to_g1(dst: &'static [u8], msg: &[u8]) -> Result<G1Projective> {
    type Curve = ark_bls12_381::g1::Config;
    type Hasher = MapToCurveBasedHasher<G1Projective, DefaultFieldHasher<Sha256, 128>, WBMap<Curve>>;

    let hasher = Hasher::new(dst).map_err(|_| anyhow!("Hasher init failed"))?;
    let p = hasher.hash(msg).map_err(|_| anyhow!("Hash-to-curve failed"))?;
    Ok(p.into())
}

pub fn setup() -> Result<(AbsParamsV1, AbsMasterKeyV1)> {
    let mut rng = rand_core::OsRng;

    let g = G2Projective::generator();
    let x = Fr::rand(&mut rng);
    let g1 = g.mul_bigint(x.into_bigint());

    let g2 = G1Projective::rand(&mut rng);
    let z = pairing_gt(g2.into_affine(), g1.into_affine());

    let params = AbsParamsV1 {
        version: 1,
        d: 1,
        g: b64_encode(&ser_g2(&g)?),
        g1: b64_encode(&ser_g2(&g1)?),
        g2: b64_encode(&ser_g1(&g2)?),
        z: b64_encode(&ser_gt(&z)?),
    };

    let sk = AbsMasterKeyV1 {
        version: 1,
        x: b64_encode(&scalar_to_bytes_be(&x)),
    };

    Ok((params, sk))
}

pub fn extract(params: &AbsParamsV1, msk: &AbsMasterKeyV1, attr: &str) -> Result<AbsUserKeyV1> {
    if params.d != 1 {
        return Err(anyhow!("This demo only supports d=1"));
    }

    let mut rng = rand_core::OsRng;

    let x = bytes_be_to_scalar(&b64_decode(&msk.x)?);
    let g = de_g2(&b64_decode(&params.g)?)?;
    let g2 = de_g1(&b64_decode(&params.g2)?)?;

    let r = Fr::rand(&mut rng);

    let h1 = hash_to_g1(b"D3CS-ABS-H1", attr.as_bytes())?;
    let d0 = g2.mul_bigint(x.into_bigint()) + h1.mul_bigint(r.into_bigint());
    let d1 = g.mul_bigint(r.into_bigint());

    Ok(AbsUserKeyV1 {
        version: 1,
        attr: attr.to_string(),
        d0: b64_encode(&ser_g1(&d0)?),
        d1: b64_encode(&ser_g2(&d1)?),
    })
}

pub fn sign(params: &AbsParamsV1, skw: &AbsUserKeyV1, message: &[u8]) -> Result<AbsSignatureV1> {
    if params.d != 1 {
        return Err(anyhow!("This demo only supports d=1"));
    }

    let mut rng = rand_core::OsRng;

    let g = de_g2(&b64_decode(&params.g)?)?;
    let d0 = de_g1(&b64_decode(&skw.d0)?)?;
    let d1 = de_g2(&b64_decode(&skw.d1)?)?;

    let r_prime = Fr::rand(&mut rng);
    let s = Fr::rand(&mut rng);

    let h1 = hash_to_g1(b"D3CS-ABS-H1", skw.attr.as_bytes())?;
    let h2 = hash_to_g1(b"D3CS-ABS-H2", message)?;

    let r1 = d0 + h1.mul_bigint(r_prime.into_bigint()) + h2.mul_bigint(s.into_bigint());
    let r2 = d1 + g.mul_bigint(r_prime.into_bigint());
    let r3 = g.mul_bigint(s.into_bigint());

    Ok(AbsSignatureV1 {
        version: 1,
        r1: b64_encode(&ser_g1(&r1)?),
        r2: b64_encode(&ser_g2(&r2)?),
        r3: b64_encode(&ser_g2(&r3)?),
    })
}

pub fn verify_with_attr(params: &AbsParamsV1, sig: &AbsSignatureV1, message: &[u8], attr: &str) -> Result<bool> {
    if params.d != 1 {
        return Err(anyhow!("This demo only supports d=1"));
    }

    let g = de_g2(&b64_decode(&params.g)?)?;
    let z = de_gt(&b64_decode(&params.z)?)?;

    let r1 = de_g1(&b64_decode(&sig.r1)?)?;
    let r2 = de_g2(&b64_decode(&sig.r2)?)?;
    let r3 = de_g2(&b64_decode(&sig.r3)?)?;

    let h1 = hash_to_g1(b"D3CS-ABS-H1", attr.as_bytes())?;
    let h2 = hash_to_g1(b"D3CS-ABS-H2", message)?;

    let num = pairing_gt(r1.into_affine(), g.into_affine());
    let den1 = pairing_gt(h1.into_affine(), r2.into_affine());
    let den2 = pairing_gt(h2.into_affine(), r3.into_affine());
    let den = den1 * den2;
    let den_inv = den.inverse().ok_or_else(|| anyhow!("Invalid GT element"))?;
    let lhs = num * den_inv;

    Ok(lhs == z)
}

pub fn verify_any(params: &AbsParamsV1, sig: &AbsSignatureV1, message: &[u8]) -> Result<bool> {
    let candidates = ["FR-S", "FR-DR"];
    for a in candidates.iter() {
        if verify_with_attr(params, sig, message, a)? {
            return Ok(true);
        }
    }
    Ok(false)
}
