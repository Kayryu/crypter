#![allow(dead_code)]

use num_bigint_dig::{BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::identities::One;
use rand::{rngs::OsRng, CryptoRng, RngCore};
use rsa::{PaddingScheme, PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use std::ops::BitXor;
use num_traits::Zero;

#[derive(Debug)]
pub struct Ring {
    // public key in group
    pub pub_keys: Vec<RsaPublicKey>,
    // the private key
    pub piv_key: RsaPrivateKey,
    // the index of private key in group
    pub i: usize,
    // rsa bit size
    pub S: usize,
    // the maximum of rand value
    pub Q: BigUint,
}

impl Ring {
    pub fn new(
        pub_keys: Vec<RsaPublicKey>,
        piv_key: RsaPrivateKey,
        i: usize,
        s: usize,
    ) -> Self {
        let Q = BigUint::one() << s.clone();
        Self {
            pub_keys,
            piv_key,
            i,
            S:s,
            Q,
        }
    }
}

#[derive(Debug)]
pub struct Signature {
    // public key in group
    pub pki: Vec<RsaPublicKey>,
    // rand data vector
    pub xi: Vec<BigUint>,
    // target value
    pub v: BigUint,
}

impl Signature {
    pub fn new(pki: Vec<RsaPublicKey>, xi: Vec<BigUint>, v: BigUint) -> Self {
        Self { pki, xi, v }
    }
}

/// generate the key pair of RSA
pub fn gen_keypair<R: CryptoRng + RngCore>(
    mut rng: R,
    bit_size: usize,
) -> (RsaPrivateKey, RsaPublicKey) {
    let priv_key =
        RsaPrivateKey::new(&mut rng, bit_size).expect("create private failed.");
    let pub_key = priv_key.to_public_key();
    return (priv_key, pub_key);
}

/// sign the message using the ring signature scheme
pub fn sign(ring: &Ring, msg: &[u8]) -> Signature {
    assert!(ring.i > 0);
    assert!(ring.pub_keys.len() >= ring.i as usize);

    let common = BigUint::one() << 16;
    let mut rng = rand::thread_rng();

    // 1. compute key k = H(m);
    let k = digest(msg);

    // 2. select v the rand value;
    let v = rng.gen_biguint(ring.S.clone());

    // 3. select xi  , 1 <= i <= n,  yi = gi(xi)
    let mut xi: Vec<BigUint> =
        (0..ring.pub_keys.len()).map(|_| rng.gen_biguint(ring.S.clone())).collect();

    // set xt = 0; if the value of xt is zero, than the yt = g(xt) must zero
    xi[ring.i.clone() - 1] = BigUint::zero();

    let yi: Vec<BigUint> = xi
        .iter()
        .zip(ring.pub_keys.iter())
        .map(|(x, pk)| gx(&x, &pk, &common))
        .collect();

    // 4. solve the yt of signer
    let yt = solve(&yi, &v, &k, &common);

    // 5. invert the signer's trap-door permutation
    xi[ring.i.clone() - 1] = dgx(&yt, &ring.piv_key, &common);

    // signature = (p1, p2, ...., pn, x1, x2, ...xs, .., xn, v)
    Signature::new(ring.pub_keys.clone(), xi, v)
}

/// verify the ring signature with message
pub fn verify(sig: &Signature, msg: &[u8]) -> bool {
    assert!(sig.pki.len() == sig.xi.len());

    let common = BigUint::one() << 16;
    // 1. compute key k = H(m);
    let k = digest(msg);

    // 2. compute yi = gi(xi)
    let yi: Vec<BigUint> = sig
        .xi
        .iter()
        .zip(sig.pki.iter())
        .map(|(x, pk)| gx(&x, &pk, &common))
        .collect();

    // 3. compute Ck,v(y1, ..., yr)
    let v = combine(&yi, &sig.v, &k, &common);
    return v == sig.v;
}

/// The combining function described in the paper. Ck,v(y1, ..., yr)
fn combine(
    yi: &[BigUint],
    v: &BigUint,
    k: &BigUint,
    common_n: &BigUint,
) -> BigUint {
    let mut tmp: BigUint = v.clone();
    for i in 0..yi.len() {
        tmp = tmp.bitxor(&yi[i]);
        tmp = ek(&tmp, &k);
    }
    return tmp;
}

/// solve the ring equation Ck,v(y1, ..., yr) = v for a given yt.
/// the yt is zero.
fn solve(
    yi: &[BigUint],
    v: &BigUint,
    k: &BigUint,
    common_n: &BigUint,
) -> BigUint {
    let mut tmp = v.clone();
    for i in 0..yi.len() {
        tmp = dek(&tmp, &k);
        if !yi[i].is_zero() {
            tmp = tmp.bitxor(&yi[i]);
        } else {
            let s = combine(&yi[i+1..], &v, &k, & common_n);
            tmp = tmp.bitxor(&s);
            break;
        }
    }
    return tmp;
}

/// The SHA256 hash digest of input.
fn digest(msg: &[u8]) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update(&msg);
    BigUint::from_bytes_be(&hasher.finalize().to_vec())
}

/// the extended trap-door permutation `g(x)`.
///
///  x = q * n + r
///  g(x) = |-  q * n + f(r)   if (q + 1) *  n <= 2^b
///         |-  x              esle
fn gx(x: &BigUint, pub_key: &RsaPublicKey, common_n: &BigUint) -> BigUint {
    let (mut q, mut r) = x.div_mod_floor(pub_key.n());
    let t = (q.clone() + 1u32) * pub_key.n();
    let mut ret = x.clone();
    if t < *common_n {
        ret = q * pub_key.n() + fx(&r, pub_key);
    }
    return ret;
}

/// the encrypt with public key
fn fx(x: &BigUint, pub_key: &RsaPublicKey) -> BigUint {
    x.modpow(pub_key.e(), pub_key.n())
}

/// the decrypt with private key
fn dfx(x: &BigUint, priv_key: &RsaPrivateKey) -> BigUint {
    x.modpow(priv_key.d(), priv_key.n())
}

/// the inverse function of `y=g(x)`
fn dgx(x: &BigUint, priv_key: &RsaPrivateKey, common_n: &BigUint) -> BigUint {
    // y = g(x) = q * n + f(r)
    let q = x / priv_key.n();
    let t = (q.clone() + 1u32) * priv_key.n();
    if t > *common_n {
        println!("!!!!!not use private key");
        return x.clone();
    }
    // y - q * n = f(r)
    let fr = x - q.clone() * priv_key.n();
    // f^{-1}(y - q * n) = r
    let r = dfx(&x, &priv_key);
    // x = q * n + r
    return q * priv_key.n() + r;
}

/// Ek(x) = x xor k
fn ek(x: &BigUint, k: &BigUint) -> BigUint {
    return x.bitxor(k)
}

/// Ek{-1}(x) = x xor k
fn dek(x: &BigUint, k: &BigUint) -> BigUint { return x.bitxor(k); }

#[test]
fn test_gx() {
    const RSA_SIZE: usize = 16;
    let common: BigUint = BigUint::one() << 16;

    let mut rng = rand::thread_rng();
    let (priv_key, pub_key) = gen_keypair(&mut rng, RSA_SIZE);

    let x = rng.gen_biguint(RSA_SIZE);
    let enc = gx(&x, &pub_key, &common);
    let dec = dgx(&enc, &priv_key, &common);
    assert!(x == dec);

    let msg: &[u8] = b"hello world";
    let x = BigUint::from_bytes_be(msg);
    let enc = gx(&x, &pub_key, &common);
    let dec = dgx(&enc, &priv_key, &common);
    println!("x: {} enc: {}, dec: {}", x, enc, dec);
    assert!(msg == dec.to_bytes_be());
}

#[test]
fn test_ek() {
    const RSA_SIZE: usize = 16;
    let common: BigUint = BigUint::one() << RSA_SIZE;
    let n = 4;
    let mut rng = rand::thread_rng();
    let mut xi: Vec<BigUint> =
        (0..n).map(|_| rng.gen_biguint(RSA_SIZE)).collect();
    let mut pairs: Vec<(RsaPrivateKey, RsaPublicKey)> =
        (0..n).map(|_| gen_keypair(&mut rng, RSA_SIZE)).collect();

    pairs
        .iter()
        .for_each(|p| println!("sk: {:?}, pk: {:?}", p.0, p.1));

    pairs.iter().for_each(|p| {
        println!(
            "sk-d:{:018b} sk-e:{:018b}, pk-n:{:018b} pk-e:{:018b}",
            p.0.d(),
            p.0.e(),
            p.1.n(),
            p.1.e()
        )
    });


    // k = hash(msg)
    let k = rng.gen_biguint(RSA_SIZE);
    let v = rng.gen_biguint(RSA_SIZE);

    println!("v: {:018b} \nk: {:018b}", v, k);
    xi.iter().for_each(|x| println!("x: {:018b}", x));

    let mut lr = v.clone();
    for i in 0..(n - 1) {
        lr ^= gx(&xi[i], &pairs[i].1, &common);
        lr = ek(&lr, &k);
        println!("l-{} : {:018b}", i, lr);
    }

    let mut d = dek(&v, &k);
    d = d.bitxor(&lr);
    xi[n - 1] = dgx(&d, &pairs[n - 1].0, &common);

    let mut z = v.clone();
    for i in 0..xi.len() {
        z ^= gx(&xi[i], &pairs[i].1, &common);
        z = ek(&z, &k);
    }

    println!("z: {}, v: {}", z, v);
    assert!(z == v);
}

#[test]
fn test_sign() {
    // create sign
    let mut rng = rand::thread_rng();
    const RSA_SIZE: usize = 256;
    let msg: &[u8] = b"test";
    let (priv_key, pub_key) = gen_keypair(&mut rng, RSA_SIZE);
    let group_size = 5;
    let index:usize = 1;
    let mut pks: Vec<RsaPublicKey> = (0..group_size)
        .map(|_| {
            let sk = RsaPrivateKey::new(&mut rng, RSA_SIZE).unwrap();
            let public_key = RsaPublicKey::from(&sk);
            public_key
        })
        .collect();
    pks[index.clone() - 1] = pub_key;
    let ring = Ring::new(pks, priv_key, index, RSA_SIZE);
    println!("ring: {:?}", ring);

    // sign
    let sig = sign(&ring, msg);
    println!("signature: {:?}", sig);

    // verify
    let ret = verify(&sig, msg);

    assert!(ret);
}
