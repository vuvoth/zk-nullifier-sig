use elliptic_curve::sec1::ToEncodedPoint;
use elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
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

#[derive(Debug, PartialEq)]
pub enum Error {
    IsPointAtInfinityError,
}

const DST: &[u8] = b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_"; // Hash to curve algorithm


/// Format a ProjectivePoint to 64 bytes - the concatenation of the x and y values.  We use 64
/// bytes instead of SEC1 encoding as our arkworks secp256k1 implementation doesn't support SEC1
/// encoding yet.
pub fn encode_pt(
    point: ProjectivePoint
) -> Result<Vec::<u8>, Error> {
    let encoded = point.to_encoded_point(true);
    Ok(encoded.to_bytes().to_vec())
}

/// Convert a 32-byte array to a scalar
pub fn byte_array_to_scalar(
    bytes: &[u8],
) -> Scalar {
    // From https://docs.rs/ark-ff/0.3.0/src/ark_ff/fields/mod.rs.html#371-393
    assert!(bytes.len() == 32);
    let mut res = Scalar::from(0u64);
    let window_size = Scalar::from(256u64);
    for byte in bytes.iter() {
        res *= window_size;
        res += Scalar::from(*byte as u64);
    }
    res
}

// Calls the hash to curve function for secp256k1, and returns the result as a ProjectivePoint
pub fn hash_to_secp(s: &[u8]) -> ProjectivePoint {
    let pt: ProjectivePoint = Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256>>(
        &[s],
        //b"CURVE_XMD:SHA-256_SSWU_RO_"
        DST,
    )
    .unwrap();
    pt
}

// Hashes two values to the curve
pub fn hash_m_pk_to_secp(m: &[u8], pk: &ProjectivePoint) -> ProjectivePoint {
    let pt: ProjectivePoint = Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256>>(
        &[[m, &encode_pt(*pk).unwrap()].concat().as_slice()],
        //b"CURVE_XMD:SHA-256_SSWU_RO_",
        DST,
    )
    .unwrap();
    pt
}
