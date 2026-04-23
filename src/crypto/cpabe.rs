// ce fichier répertorie les fonctions crypto ABE provenant de la spécification docs/PM23

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

// hash_attr_scalar permet de prendre un attribut, le hacher et le transformer en opérateur crypto

fn hash_attr_scalar(attr: &str) -> Fr {
    let digest = sha2::Sha256::digest(attr.as_bytes());
    Fr::from_be_bytes_mod_order(&digest)
}

// h_g1 = g ^ s avec s attribut haché

fn h_g1(g: &G1Projective, attr: &str) -> G1Projective {
    let s = hash_attr_scalar(attr);
    g.mul_bigint(s.into_bigint())
}

fn h_g2(g2: &G2Projective, attr: &str) -> G2Projective {
    let s = hash_attr_scalar(attr);
    g2.mul_bigint(s.into_bigint())
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

    let pp = PublicParamsV1 {
        version: 1,
        g: b64_encode(&ser_g1(&g)?),
        g2: b64_encode(&ser_g2(&g2)?),
        h: b64_encode(&ser_g1(&h)?),
        f: b64_encode(&ser_g1(&f)?),
        // f2 n'est pas décrit dans le papier car on utilise G1+G2 ici, et pas seulement G0 (sécurité)
        f2: b64_encode(&ser_g2(&f2)?),
        y: b64_encode(&ser_gt(&y)?),
        // on n'utilise pas h1...hn car ils sont de toute manière dérivés dans keygen/delegate/encrypt
    };

    let msk = MasterKeyV1 {
        version: 1,
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
    // génération de D (PSKA), D' et D'' (PSKS) : ces trois paramètres sont constitutifs de SK dans BSW07
    let mut rng = rand_core::OsRng;
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
        let h = h_g2(&g2, attr);
        let h_ri = h.mul_bigint(r_i.into_bigint());
        // une multiplication d'éléments du groupe (dans PM23) correspond à une somme
        let d_i = g2_r + h_ri;
        let d_i_prime = g2.mul_bigint(r_i.into_bigint());

        entries.push(PsksAttrV1 {
            attr: attr.clone(),
            d: b64_encode(&ser_g2(&d_i)?),
            d_prime: b64_encode(&ser_g2(&d_i_prime)?),
        });
    }

    // tri des attributs par ordre alphabétique
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

pub fn delegate(
    pp: &PublicParamsV1,
    psks_in: &PsksV1,
    delegated_attrs: &[String],
) -> Result<(PsksV1, TkV1)> {
    let mut rng = rand_core::OsRng;
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
            // oubli dans le schéma de PM23 : D seconde doit être intégré dans PSKS pour pouvoir déchiffrer
            // BSW07 intègre Dj_seconde_hat de la sorte : Dj_seconde . g^rj_hat
            // ce qui est intégré ici :
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

    // analytiquement, on a : g^((alpha+r)/beta)*f_2^r_hat=g^((alpha+r)/beta)*g^r_hat/beta=g^((alpha+r+r_hat)/beta)
    // ce qui nous permet de garder le nouveau random dans la nouvelle PSKA
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
            c_i_prime: b64_encode(&ser_g1(&c1p)?),
        },
        AbeLeafV1 {
            index: 2,
            attr: leaf2_attr,
            c_i: b64_encode(&ser_g1(&c2)?),
            c_i_prime: b64_encode(&ser_g1(&c2p)?),
        },
    ];

    // c_tilde vaut ici e(g,g)^(t+alpha*s), t représente un nouvel aléa utilisé dans Encrypt
    // s représente le secret de session (spécifié dans PM23)
    // pas d'instanciation de C(x,y)childj car on ne fonctionne qu'avec 2 feuilles
    // sur un AND+OR on en aurait besoin (car noeuds intermédiaires)
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

pub fn tm_decrypt(
    _pp: &PublicParamsV1,
    ct: &CiphertextV1,
    pska: &PskaV1,
) -> Result<IntermediateCiphertextV1> {
    let c = de_g1(&b64_decode(&ct.abe.c)?)?;
    let d = de_g2(&b64_decode(&pska.d)?)?;

    let f = pairing_gt(c.into_affine(), d.into_affine());

    // TM_Decrypt : reprise de tous les éléments de CT sauf f (qui remplace c, qui a été pairé avec PSKA)
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

pub fn decrypt(
    _pp: &PublicParamsV1,
    cti: &IntermediateCiphertextV1,
    psks: &PsksV1,
) -> Result<String> {
    let c_tilde = de_gt(&b64_decode(&cti.abe.c_tilde)?)?;
    let f = de_gt(&b64_decode(&cti.abe.f)?)?;

    let mut res_map: Vec<(u8, Fq12)> = Vec::new();

    // application de la méthode "DecryptLeafNode" de PM23 sur les 2 feuilles
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
        let den_inv = den
            .inverse()
            .ok_or_else(|| anyhow!("Invalid pairing result"))?;
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

    // calcul de F_root à l'aide de la formule de Lagrange avec delta(0)=(0-k)/(j-k)
    // 1ere node (j=1, donc k=2 (car il n'y a que 2 nodes)) : delta1=(0-2)/(1-2)=2
    // 2e node (j=2, donc k=1) : delta2=(0-1)/(2-1)=-1
    // donc nous avons F_root=delta1*delta2=F1^2*F2^(-1), avec F1=r1 et F2=r2 dans le code (feuilles)
    let r1_sq = r1 * r1;
    let r2_inv = r2
        .inverse()
        .ok_or_else(|| anyhow!("Invalid pairing result"))?;
    let f_root = r1_sq * r2_inv;

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
        Ok(())
    }
}
