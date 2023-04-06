#![allow(dead_code)]
#![allow(unused_variables)]
// #![feature(generic_const_expr)]
// #![allow(incomplete_features)]

use elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use elliptic_curve::sec1::ToEncodedPoint;
use hex_literal::hex;
use k256::{
    // ecdsa::{signature::Signer, Signature, SigningKey},
    elliptic_curve::group::ff::PrimeField,
    sha2::{Digest, Sha256, Sha512},
    FieldBytes,
    ProjectivePoint,
    Scalar,
    Secp256k1,
}; // requires 'getrandom' feature

use crate::utils::{byte_array_to_scalar, encode_pt, hash_m_pk_to_secp, hash_to_secp};

const L: usize = 48;
const COUNT: usize = 2;
const OUT: usize = L * COUNT;
const DST: &[u8] = b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_"; // Hash to curve algorithm

#[derive(Debug, PartialEq)]
pub enum Error {
    IsPointAtInfinityError,
}

fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>());
}

// Generates a deterministic secret key for us temporarily. Can be replaced by random oracle anytime.
fn gen_test_scalar_x() -> Scalar {
    Scalar::from_repr(
        hex!("519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464").into(),
    )
    .unwrap()
}

// Generates a deterministic r for us temporarily. Can be replaced by random oracle anytime.
fn gen_test_scalar_r() -> Scalar {
    Scalar::from_repr(
        hex!("93b9323b629f251b8f3fc2dd11f4672c5544e8230d493eceea98a90bda789808").into(),
    )
    .unwrap()
}

// These generate test signals as if it were passed from a secure enclave to wallet. Note that leaking these signals would leak pk, but not sk.
// Outputs these 6 signals, in this order
// g^sk																(private)
// hash[m, pk]^sk 													public nullifier
// c = hash2(g, pk, hash[m, pk], hash[m, pk]^sk, gr, hash[m, pk]^r)	(public or private)
// r + sk * c														(public or private)
// g^r																(public)
// hash[m, pk]^r													(public)

// new
// pk = g^sk
//
fn test_gen_signals(
    m: &[u8],
) -> (
    ProjectivePoint,
    ProjectivePoint,
    Scalar,
    Scalar,
    ProjectivePoint,
    ProjectivePoint,
) {
    // The base point or generator of the curve.
    let g = ProjectivePoint::GENERATOR;

    // The signer's secret key. It is only accessed within the secure enclave.
    let sk = gen_test_scalar_x();

    // A random value r. It is only accessed within the secure enclave.
    let r = gen_test_scalar_r();

    // The user's public key: g^sk.
    let pk = &g * &sk;

    // The generator exponentiated by r: g^r.
    let g_r = &g * &r;

    // hash[m, pk]
    let hash_m_pk = hash_m_pk_to_secp(m, &pk);

    println!(
        "h.x: {:?}",
        hex::encode(hash_m_pk.to_affine().to_encoded_point(false).x().unwrap())
    );
    println!(
        "h.y: {:?}",
        hex::encode(hash_m_pk.to_affine().to_encoded_point(false).y().unwrap())
    );

    // hash[m, pk]^r
    let hash_m_pk_pow_r = &hash_m_pk * &r;
    println!(
        "hash_m_pk_pow_r.x: {:?}",
        hex::encode(
            hash_m_pk_pow_r
                .to_affine()
                .to_encoded_point(false)
                .x()
                .unwrap()
        )
    );
    println!(
        "hash_m_pk_pow_r.y: {:?}",
        hex::encode(
            hash_m_pk_pow_r
                .to_affine()
                .to_encoded_point(false)
                .y()
                .unwrap()
        )
    );

    // The public nullifier: hash[m, pk]^sk.
    let nullifier = &hash_m_pk * &sk;

    // The Fiat-Shamir type step.
    let c = sha512_hash_signals(&[nullifier, g_r, hash_m_pk_pow_r]);
    // This value is part of the discrete log equivalence (DLEQ) proof.
    let r_sk_c = r + sk * c;

    // Return the signature.
    (pk, nullifier, c, r_sk_c, g_r, hash_m_pk_pow_r)
}

fn sha512_hash_signals(signals: &[ProjectivePoint]) -> Scalar {
    let preimage_vec = signals
        .iter()
        .map(|signal| encode_pt(*signal).unwrap())
        .collect::<Vec<_>>()
        .concat();
    let mut sha512_hasher = Sha512::new();
    sha512_hasher.update(preimage_vec.as_slice());
    let sha512_hasher_result = sha512_hasher.finalize(); //512 bit hash

    let bytes_hash = FieldBytes::from_iter(sha512_hasher_result.iter().copied());
    let scalar_hash = Scalar::from_repr(bytes_hash).unwrap();
    scalar_hash
}


// Verifier check in SNARK:
// g^[r + sk * c] / (g^sk)^c = g^r
// hash[m, gsk]^[r + sk * c] / (hash[m, pk]^sk)^c = hash[m, pk]^r
// c = hash2(g, g^sk, hash[m, g^sk], hash[m, pk]^sk, gr, hash[m, pk]^r)
pub fn verify_signals(
    m: &[u8],
    pk: &ProjectivePoint,
    nullifier: &ProjectivePoint,
    c: &Scalar,
    r_sk_c: &Scalar,
    g_r: &ProjectivePoint,
    hash_m_pk_pow_r: &ProjectivePoint,
) -> bool {
    let mut verified: bool = true;

    // The base point or generator of the curve.
    let g = &ProjectivePoint::GENERATOR;

    // hash[m, pk]
    let hash_m_pk = &hash_m_pk_to_secp(m, pk);

    if (g * r_sk_c - pk * c) != *g_r {
        verified = false;
    }

    if (hash_m_pk * r_sk_c - nullifier * c) != *hash_m_pk_pow_r {
        verified = false;
    }

    // Check if the given hash matches
    if (sha512_hash_signals(&[*nullifier, *g_r, *hash_m_pk_pow_r])) != *c {
        verified = false;
    }
    verified
}

#[cfg(test)]
mod plume_v2_tests {
    use super::*;

    #[test]
    fn verify_signals_v2_test() {
        let g = ProjectivePoint::GENERATOR;

        let m = b"An example app message string";

        // Fixed key nullifier, secret key, and random value for testing
        // Normally a secure enclave would generate these values, and output to a wallet implementation
        let (pk, nullifier, c, r_sk_c, g_r, hash_m_pk_pow_r) = test_gen_signals(m);

        // The signer's secret key. It is only accessed within the secure enclave.
        let sk = gen_test_scalar_x();

        // The user's public key: g^sk.
        let pk = &g * &sk;

        // Verify the signals, normally this would happen in ZK with only the nullifier public, which would have a zk verifier instead
        // The wallet should probably run this prior to snarkify-ing as a sanity check
        // m and nullifier should be public, so we can verify that they are correct
        let verified = verify_signals(m, &pk, &nullifier, &c, &r_sk_c, &g_r, &hash_m_pk_pow_r);
        println!("Verified: {}", verified);

        assert!(verified);
        // Print nullifier
        println!(
            "nullifier.x: {:?}",
            hex::encode(nullifier.to_affine().to_encoded_point(false).x().unwrap())
        );
        println!(
            "nullifier.y: {:?}",
            hex::encode(nullifier.to_affine().to_encoded_point(false).y().unwrap())
        );

        // Print c
        println!("c: {:?}", hex::encode(&c.to_bytes()));

        // Print r_sk_c
        println!("r_sk_c: {:?}", hex::encode(r_sk_c.to_bytes()));

        // Print g_r
        println!(
            "g_r.x: {:?}",
            hex::encode(g_r.to_affine().to_encoded_point(false).x().unwrap())
        );
        println!(
            "g_r.y: {:?}",
            hex::encode(g_r.to_affine().to_encoded_point(false).y().unwrap())
        );

        // Print hash_m_pk_pow_r
        println!(
            "hash_m_pk_pow_r.x: {:?}",
            hex::encode(
                hash_m_pk_pow_r
                    .to_affine()
                    .to_encoded_point(false)
                    .x()
                    .unwrap()
            )
        );
        println!(
            "hash_m_pk_pow_r.y: {:?}",
            hex::encode(
                hash_m_pk_pow_r
                    .to_affine()
                    .to_encoded_point(false)
                    .y()
                    .unwrap()
            )
        );

        // Test encode_pt()
        let g_as_bytes = encode_pt(g).unwrap();
        assert_eq!(
            hex::encode(g_as_bytes),
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );

        // Test byte_array_to_scalar()
        let bytes_to_convert = c.to_bytes();
        let scalar = byte_array_to_scalar(&bytes_to_convert);
        assert_eq!(
            hex::encode(scalar.to_bytes()),
            "d898f5fa7e4af2d694cb948cfe3226aebd602852beb7b32f5e9225a10c2bc925"
        );

        // Test the hash-to-curve algorithm
        let h = hash_to_secp(b"abc");
        assert_eq!(
            hex::encode(h.to_affine().to_encoded_point(false).x().unwrap()),
            "3377e01eab42db296b512293120c6cee72b6ecf9f9205760bd9ff11fb3cb2c4b"
        );
        assert_eq!(
            hex::encode(h.to_affine().to_encoded_point(false).y().unwrap()),
            "7f95890f33efebd1044d382a01b1bee0900fb6116f94688d487c6c7b9c8371f6"
        );
    }
}
