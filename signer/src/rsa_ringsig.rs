#![allow(dead_code)]

use num_bigint_dig::{BigUint, RandBigInt};
use rsa::{RsaPublicKey, RsaPrivateKey, PublicKeyParts, PaddingScheme};
use rand::{rngs::OsRng, RngCore, CryptoRng};
use sha2::{Digest, Sha256};
use num_integer::Integer;
use num_traits::identities::One;
use std::ops::BitXor;

#[derive(Debug)]
pub struct Ring {
    // public key in group
    pub pub_keys: Vec<RsaPublicKey>,
    // the private key
    pub piv_key: RsaPrivateKey,
    // the index of private key in group
    pub l: u32,
    // rsa bit size
    pub S: usize,
}

impl Ring {
    pub fn new(pub_keys: Vec<RsaPublicKey>, piv_key: RsaPrivateKey, l: u32) -> Self {
        Self {
            pub_keys,
            piv_key,
            l,
            S: 64,
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
        Self {
            pki,
            xi,
            v
        }
    }
}

pub fn gen_keypair<R: CryptoRng + RngCore>(mut rng: R, bit_size: usize) -> (RsaPrivateKey, RsaPublicKey) {
    let priv_key = RsaPrivateKey::new(&mut rng, bit_size).expect("create private failed.");
    let pub_key = priv_key.to_public_key();
    return (priv_key, pub_key)
}

/*
    note:  s, Ss, P1, P2, .... ,Pn
    k = H(m)
    select v
    select xi  , 1 <= i <= n,  yi = gi(xi)
    ys = v / Ck,v(y1, y2,..., yn)
    xs = gs-1(ys)
    signature = (p1, p2, ...., pn, x1, x2, ...xs, .., xn, v)
*/
pub fn sign(ring: &Ring, msg: &[u8]) -> Signature {
    assert!(ring.pub_keys.len() >= ring.l as usize);

    let mut rng = rand::thread_rng();

    let k = hash(msg);
    let v = rng.gen_biguint(ring.S.clone());
    let n = ring.pub_keys.len() - 1;
    let mut xi:Vec<BigUint> = (0..n).map(|_| rng.gen_biguint(ring.S.clone())).collect();
    let mut yi = vec![];
    for i in 0..xi.len() {
        let g = gx(&xi[i],&ring.pub_keys[i]);
        yi.push(g);
    }
    let mut r = v.clone();
    for i in 0..xi.len() {
        r = r + yi[i].clone();
        r = ek(&r, &k);
    }

    // latest
    let d = ek(&v, &k);
    let yt = d - r;
    let xt = dgx(&yt, &ring.piv_key);
    xi.push(xt);
    Signature::new(ring.pub_keys.clone(), xi, v)
}

/*
    calc xi  , 1 <= i <= n,  yi = gi(xi)
    calc r = Ck,v(y1, y2,..., yn)
    check r == v
*/
pub fn verify(sig: &Signature, msg: &[u8]) -> bool {
    assert!(sig.pki.len() == sig.xi.len());

    let k = hash(msg);

    let mut r = sig.v.clone();
    for i in 0..sig.xi.len() {
        r = r + gx(&sig.xi[i],&sig.pki[i]);
        r = ek(&r, &k);
    }

    return r == sig.v
}

fn hash(msg: &[u8]) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update(&msg);
    BigUint::from_bytes_be(&hasher.finalize().to_vec())
}

fn gx(x: &BigUint, pub_key: &RsaPublicKey) -> BigUint {
    x.modpow(pub_key.e(), pub_key.n())
}

fn dgx(x: &BigUint, priv_key: &RsaPrivateKey) -> BigUint {
    x.modpow(priv_key.d(), priv_key.n())
}

/// Mk(m) = m xor k
fn ek(x: &BigUint, k: &BigUint) -> BigUint {
    let r = x.bitxor(k);
    return r
}

#[test]
fn test_gx() {
    let mut rng = rand::thread_rng();
    let (priv_key, pub_key) = gen_keypair(&mut rng, 64);
    println!("priv_key: {:?}", priv_key);
    let msg: &[u8] = b"123456";
    let x = BigUint::from_bytes_be(msg);
    let enc = gx(&x, &pub_key);
    let dec = dgx(&enc, &priv_key);

    println!("enc: {}, dec: {}",enc, dec);
    println!("msg: {}", std::str::from_utf8(&dec.to_bytes_be()).unwrap());
    assert!(msg == dec.to_bytes_be());
}

#[test]
fn test_ek() {
    const RSA_SIZE: usize = 16;
    let n = 4;
    let mut rng = rand::thread_rng();
    let mut xi:Vec<BigUint> = (0..n).map(|_| rng.gen_biguint(RSA_SIZE)).collect();
    let mut pairs: Vec<(RsaPrivateKey, RsaPublicKey)> = (0..n).map(|_| {
        gen_keypair(&mut rng, RSA_SIZE)
    }).collect();

    pairs.iter().for_each(|p| println!("sk:{:?}, pk:{:?}", p.0, p.1));
    xi.iter().for_each(|x|println!("x: {}", x));

    let k = rng.gen_biguint(RSA_SIZE);
    let v = rng.gen_biguint(RSA_SIZE);

    println!("v: {} \nk: {}", v, k);
    let mut lr = v.clone();
    for i in (0..n-1) {
        let y = gx(&xi[i],&pairs[i].1);
        lr = lr + y;
        lr = ek(&lr, &k);
    }

    println!("{}", lr);

    // Ek(r, k)=v,  r = lr + yt
    let mut d = ek(&v, &k);
    d = d - lr;
    let xt = dgx(&d, &pairs[n-1].0);
    xi[n-1] = xt;

    let mut z = v.clone();
    for i in 0..xi.len() {
        z = z + gx(&xi[i],&pairs[i].1);
        z = ek(&z, &k);
    }

    println!("z: {}, v: {}", z, v);
}

#[test]
fn test_sign() {
    // create sign
    let mut rng = rand::thread_rng();
    const RSA_SIZE: usize = 64;
    let msg: &[u8] = b"test";
    let (priv_key, pub_key) = gen_keypair(&mut rng, RSA_SIZE);
    let group_size = 2;
    let mut pks: Vec<RsaPublicKey> = (0..(group_size-1)).map(|_| {
        let sk = RsaPrivateKey::new(&mut rng, RSA_SIZE).unwrap();
        let public_key = RsaPublicKey::from(&sk);
        public_key
    }).collect();
    pks.push(pub_key);
    let ring = Ring::new(pks, priv_key, group_size);
    println!("ring: {:?}", ring);

    // sign
    let sig = sign(&ring, msg);
    println!("signature: {:?}", sig);

    // verify
    let ret = verify(&sig, msg);

    assert!(ret);
}