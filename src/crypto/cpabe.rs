use anyhow::{anyhow, Result};
use base64::Engine;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Digest;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};

use ark_bls12_381::{Bls12_381, Fq12, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_ec::Group;
use ark_ff::BigInteger;
use ark_ff::Field;
use ark_ff::PrimeField;
use ark_ff::UniformRand;
use ark_ff::Zero;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use super::DocumentLabel;

#[derive(Clone, Serialize, Deserialize)]
pub struct PublicParamsV1 {
    pub version: u8,
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
    pub alpha: String,
    pub beta: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PskaV1 {
    pub version: u8,
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
    pub attrs: Vec<PsksAttrV1>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TkV1 {
    pub version: u8,
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
    pub label: DocumentLabel,
    pub abe: AbeIntermediateV1,
    pub sym: SymCiphertextV1,
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

fn hash_attr_scalar(attr: &str) -> Fr {
    let digest = sha2::Sha256::digest(attr.as_bytes());
    Fr::from_be_bytes_mod_order(&digest)
}

fn h_g1(g: &G1Projective, attr: &str) -> G1Projective {
    let s = hash_attr_scalar(attr);
    g.mul_bigint(s.into_bigint())
}

fn h_g2(g2: &G2Projective, attr: &str) -> G2Projective {
    let s = hash_attr_scalar(attr);
    g2.mul_bigint(s.into_bigint())
}

fn pairing_gt(a: G1Affine, b: G2Affine) -> Fq12 {
    Bls12_381::pairing(a, b).0
}

fn gt_pow(base: &Fq12, exp: &Fr) -> Fq12 {
    base.pow(exp.into_bigint())
}

fn derive_sym_key(gt: &Fq12) -> Result<[u8; 32]> {
    let bytes = ser_gt(gt)?;
    let digest = sha2::Sha256::digest(&bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    Ok(out)
}

pub fn setup() -> Result<(PublicParamsV1, MasterKeyV1)> {
    let mut rng = rand_core::OsRng;
    let g = G1Projective::generator();
    let g2 = G2Projective::generator();

    let alpha = Fr::rand(&mut rng);
    let mut beta = Fr::rand(&mut rng);
    while beta.is_zero() {
        beta = Fr::rand(&mut rng);
    }

    let beta_inv = beta
        .inverse()
        .ok_or_else(|| anyhow!("beta inverse missing"))?;

    let h = g.mul_bigint(beta.into_bigint());
    let f = g.mul_bigint(beta_inv.into_bigint());
    let f2 = g2.mul_bigint(beta_inv.into_bigint());
    let base_gt = pairing_gt(g.into_affine(), g2.into_affine());
    let y = gt_pow(&base_gt, &alpha);

    let pp = PublicParamsV1 {
        version: 1,
        g: b64_encode(&ser_g1(&g)?),
        g2: b64_encode(&ser_g2(&g2)?),
        h: b64_encode(&ser_g1(&h)?),
        f: b64_encode(&ser_g1(&f)?),
        f2: b64_encode(&ser_g2(&f2)?),
        y: b64_encode(&ser_gt(&y)?),
    };

    let msk = MasterKeyV1 {
        version: 1,
        alpha: b64_encode(&scalar_to_bytes_be(&alpha)),
        beta: b64_encode(&scalar_to_bytes_be(&beta)),
    };

    Ok((pp, msk))
}

pub fn keygen(pp: &PublicParamsV1, msk: &MasterKeyV1, attrs: &[String]) -> Result<(PskaV1, PsksV1)> {
    let mut rng = rand_core::OsRng;
    let g2 = de_g2(&b64_decode(&pp.g2)?)?;

    let alpha = bytes_be_to_scalar(&b64_decode(&msk.alpha)?);
    let beta = bytes_be_to_scalar(&b64_decode(&msk.beta)?);
    let beta_inv = beta
        .inverse()
        .ok_or_else(|| anyhow!("beta inverse missing"))?;

    let r = Fr::rand(&mut rng);
    let exp = (alpha + r) * beta_inv;
    let d = g2.mul_bigint(exp.into_bigint());

    let mut entries = Vec::new();
    let g2_r = g2.mul_bigint(r.into_bigint());

    for attr in attrs.iter() {
        let r_i = Fr::rand(&mut rng);
        let h = h_g2(&g2, attr);
        let h_ri = h.mul_bigint(r_i.into_bigint());
        let d_i = g2_r + h_ri;
        let d_i_prime = g2.mul_bigint(r_i.into_bigint());

        entries.push(PsksAttrV1 {
            attr: attr.clone(),
            d: b64_encode(&ser_g2(&d_i)?),
            d_prime: b64_encode(&ser_g2(&d_i_prime)?),
        });
    }

    entries.sort_by(|a, b| a.attr.cmp(&b.attr));

    let pska = PskaV1 {
        version: 1,
        d: b64_encode(&ser_g2(&d)?),
    };

    let psks = PsksV1 {
        version: 1,
        attrs: entries,
    };

    Ok((pska, psks))
}

pub fn delegate(pp: &PublicParamsV1, psks_in: &PsksV1, delegated_attrs: &[String]) -> Result<(PsksV1, TkV1)> {
    let mut rng = rand_core::OsRng;
    let g2 = de_g2(&b64_decode(&pp.g2)?)?;
    let f2 = de_g2(&b64_decode(&pp.f2)?)?;

    let hat_r = Fr::rand(&mut rng);
    let g2_hat_r = g2.mul_bigint(hat_r.into_bigint());

    let mut out_entries = Vec::new();

    for a in delegated_attrs.iter() {
        let entry = psks_in
            .attrs
            .iter()
            .find(|e| e.attr == *a)
            .ok_or_else(|| anyhow!("Attribute not found in PSKS"))?;
        let d = de_g2(&b64_decode(&entry.d)?)?;
        let d_prime = de_g2(&b64_decode(&entry.d_prime)?)?;

        let hat_r_i = Fr::rand(&mut rng);
        let h = h_g2(&g2, &entry.attr);
        let h_hat_r_i = h.mul_bigint(hat_r_i.into_bigint());
        let g2_hat_r_i = g2.mul_bigint(hat_r_i.into_bigint());

        let new_d = d + g2_hat_r + h_hat_r_i;
        let new_d_prime = d_prime + g2_hat_r_i;

        out_entries.push(PsksAttrV1 {
            attr: entry.attr.clone(),
            d: b64_encode(&ser_g2(&new_d)?),
            d_prime: b64_encode(&ser_g2(&new_d_prime)?),
        });
    }

    out_entries.sort_by(|a, b| a.attr.cmp(&b.attr));

    let tk_point = f2.mul_bigint(hat_r.into_bigint());
    let tk = TkV1 {
        version: 1,
        t: b64_encode(&ser_g2(&tk_point)?),
    };

    Ok((
        PsksV1 {
            version: 1,
            attrs: out_entries,
        },
        tk,
    ))
}

pub fn tm_delegate(pska_in: &PskaV1, tk: &TkV1) -> Result<PskaV1> {
    let d = de_g2(&b64_decode(&pska_in.d)?)?;
    let t = de_g2(&b64_decode(&tk.t)?)?;
    let new_d = d + t;

    Ok(PskaV1 {
        version: 1,
        d: b64_encode(&ser_g2(&new_d)?),
    })
}

pub fn encrypt(pp: &PublicParamsV1, label: &DocumentLabel, message: &str) -> Result<CiphertextV1> {
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
    let h1 = h_g1(&g, &leaf1_attr);
    let c1p = h1.mul_bigint(share1.into_bigint());

    let c2 = g.mul_bigint(share2.into_bigint());
    let h2 = h_g1(&g, &leaf2_attr);
    let c2p = h2.mul_bigint(share2.into_bigint());

    let leafs = vec![
        AbeLeafV1 {
            index: 1,
            attr: leaf1_attr,
            c_i: b64_encode(&ser_g1(&c1)?),
            c_i_prime: b64_encode(&ser_g1(&c1p)?),
        },
        AbeLeafV1 {
            index: 2,
            attr: leaf2_attr,
            c_i: b64_encode(&ser_g1(&c2)?),
            c_i_prime: b64_encode(&ser_g1(&c2p)?),
        },
    ];

    Ok(CiphertextV1 {
        version: 1,
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

pub fn tm_decrypt(_pp: &PublicParamsV1, ct: &CiphertextV1, pska: &PskaV1) -> Result<IntermediateCiphertextV1> {
    let c = de_g1(&b64_decode(&ct.abe.c)?)?;
    let d = de_g2(&b64_decode(&pska.d)?)?;

    let f = pairing_gt(c.into_affine(), d.into_affine());

    Ok(IntermediateCiphertextV1 {
        version: 1,
        label: ct.label.clone(),
        abe: AbeIntermediateV1 {
            c_tilde: ct.abe.c_tilde.clone(),
            f: b64_encode(&ser_gt(&f)?),
            leafs: ct.abe.leafs.clone(),
        },
        sym: ct.sym.clone(),
    })
}

pub fn decrypt(pp: &PublicParamsV1, cti: &IntermediateCiphertextV1, psks: &PsksV1) -> Result<String> {
    let c_tilde = de_gt(&b64_decode(&cti.abe.c_tilde)?)?;
    let f = de_gt(&b64_decode(&cti.abe.f)?)?;

    let mut res_map: Vec<(u8, Fq12)> = Vec::new();

    for leaf in cti.abe.leafs.iter() {
        let sk = psks
            .attrs
            .iter()
            .find(|e| e.attr == leaf.attr)
            .ok_or_else(|| anyhow!("Missing attribute in PSKS"))?;

        let c_i = de_g1(&b64_decode(&leaf.c_i)?)?;
        let c_i_prime = de_g1(&b64_decode(&leaf.c_i_prime)?)?;
        let d_i = de_g2(&b64_decode(&sk.d)?)?;
        let d_i_prime = de_g2(&b64_decode(&sk.d_prime)?)?;

        let num = pairing_gt(c_i.into_affine(), d_i.into_affine());
        let den = pairing_gt(c_i_prime.into_affine(), d_i_prime.into_affine());
        let den_inv = den.inverse().ok_or_else(|| anyhow!("Invalid pairing result"))?;
        let res = num * den_inv;

        res_map.push((leaf.index, res));
    }

    let r1 = res_map
        .iter()
        .find(|(i, _)| *i == 1)
        .map(|(_, r)| r.clone())
        .ok_or_else(|| anyhow!("Missing leaf index 1"))?;
    let r2 = res_map
        .iter()
        .find(|(i, _)| *i == 2)
        .map(|(_, r)| r.clone())
        .ok_or_else(|| anyhow!("Missing leaf index 2"))?;

    let r1_sq = r1 * r1;
    let r2_inv = r2.inverse().ok_or_else(|| anyhow!("Invalid pairing result"))?;
    let f_root = r1_sq * r2_inv;

    let f_root_inv = f_root.inverse().ok_or_else(|| anyhow!("Invalid GT element"))?;
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
