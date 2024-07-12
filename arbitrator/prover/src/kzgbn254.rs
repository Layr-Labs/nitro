use crate::Bytes32;
use ark_bn254::G2Affine;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::CanonicalSerialize;
use eyre::{ensure, Result};
use hex::encode;
use kzgbn254::{blob::Blob, kzg::Kzg, polynomial::PolynomialFormat};
use num::BigUint;
use sha2::{Digest, Sha256};
use std::io::Write;

lazy_static::lazy_static! {

    // note that we are loading 3000 for testing purposes atm, but for production use these values:
    // g1 and g2 points from the operator setup guide
    // srs_order = 268435456
    // srs_points_to_load = 131072

    pub static ref KZG: Kzg = Kzg::setup(
        "./arbitrator/prover/src/test-files/g1.point",
        "./arbitrator/prover/src/test-files/g2.point",
        "./arbitrator/prover/src/test-files/g2.point.powerOf2",
        3000,
        3000
    ).unwrap();

    // modulus for the underlying field F_r of the elliptic curve
    // see https://docs.eigenlayer.xyz/eigenda/integrations-guides/dispersal/blob-serialization-requirements
    pub static ref BLS_MODULUS: BigUint = "21888242871839275222246405745257275088548364400416034343698204186575808495617".parse().unwrap();

    // (2*1024*1024)/32 = 65536
    pub static ref FIELD_ELEMENTS_PER_BLOB: usize = 65536;
}

/// Creates a KZG preimage proof consumable by the point evaluation precompile.
pub fn prove_kzg_preimage_bn254(
    hash: Bytes32,
    preimage: &[u8],
    offset: u32,
    out: &mut impl Write,
) -> Result<()> {
    let mut kzg = KZG.clone();

    println!("preimage: {}", encode(&preimage));

    // expand roots of unity
    kzg.calculate_roots_of_unity(preimage.len() as u64)?;

    // preimage is already padded, unpadding and repadding already padded data can destroy context post IFFT
    // as some elements in the bn254 field are represented by 32 bytes, we know that the preimage is padded
    // to 32 bytes per DA spec as the preimage is retrieved from DA, so we can use this unchecked function
    let blob = Blob::from_padded_bytes_unchecked(preimage);

    let blob_polynomial_evaluation_form = blob.to_polynomial(PolynomialFormat::InEvaluationForm)?;
    let blob_commitment = kzg.commit(&blob_polynomial_evaluation_form)?;

    let mut commitment_bytes = Vec::new();
    blob_commitment.serialize_uncompressed(&mut commitment_bytes)?;

    let mut expected_hash: Bytes32 = Sha256::digest(&*commitment_bytes).into();
    expected_hash[0] = 1;

    ensure!(
        hash == expected_hash,
        "Trying to prove versioned hash {} preimage but recomputed hash {}",
        hash,
        expected_hash,
    );

    ensure!(
        offset % 32 == 0,
        "Cannot prove blob preimage at unaligned offset {}",
        offset,
    );

    // retrieve commitment to preimage
    let preimage_polynomial = blob.to_polynomial(PolynomialFormat::InCoefficientForm)?;
    let preimage_commitment = kzg.commit(&preimage_polynomial)?;
    let mut preimage_commitment_bytes = Vec::new();
    preimage_commitment.serialize_uncompressed(&mut preimage_commitment_bytes)?;
    println!(
        "preimage commitment: {}",
        encode(&preimage_commitment_bytes)
    );

    let mut proving_offset = offset;

    let length_usize = preimage_polynomial.len() as usize;

    // address proving past end edge case later
    let proving_past_end = offset as usize >= length_usize;
    if proving_past_end {
        // Proving any offset proves the length which is all we need here,
        // because we're past the end of the preimage.
        proving_offset = 0;
    }

    let proving_offset_bytes = proving_offset.to_be_bytes();
    let mut padded_proving_offset_bytes: [u8; 32] = [0u8; 32];
    padded_proving_offset_bytes[32 - proving_offset_bytes.len()..]
        .copy_from_slice(&proving_offset_bytes);

    let proven_y_fr = preimage_polynomial
        .get_at_index(proving_offset as usize)
        .ok_or_else(|| {
            eyre::eyre!(
                "Index ({}) out of bounds for preimage of length {} with data of size {}",
                proving_offset,
                length_usize,
                preimage_polynomial.len()
            )
        })?;

    let z_fr = kzg
        .get_nth_root_of_unity(proving_offset as usize)
        .ok_or_else(|| eyre::eyre!("Failed to get nth root of unity"))?;

    let proven_y = proven_y_fr.into_bigint().to_bytes_be();
    let z = z_fr.into_bigint().to_bytes_be();

    let g2_generator = G2Affine::generator();
    let z_g2 = (g2_generator * z_fr).into_affine();

    // if we are loading in g2 pow2 this is index 0 not 1
    let g2_tau: G2Affine = kzg
        .get_g2_points()
        .get(1)
        .ok_or_else(|| eyre::eyre!("Failed to get g2 point at index 1 in SRS"))?
        .clone();
    let g2_tau_minus_g2_z = (g2_tau - z_g2).into_affine();

    let kzg_proof =
        kzg.compute_kzg_proof_with_roots_of_unity(&preimage_polynomial, proving_offset as u64)?;

    let xminusz_x0: BigUint = g2_tau_minus_g2_z.x.c0.into();
    let xminusz_x1: BigUint = g2_tau_minus_g2_z.x.c1.into();
    let xminusz_y0: BigUint = g2_tau_minus_g2_z.y.c0.into();
    let xminusz_y1: BigUint = g2_tau_minus_g2_z.y.c1.into();

    // turn each element of xminusz into bytes, then pad each to 32 bytes, then append in order x1,x0,y1,y0
    let mut xminusz_encoded_bytes = Vec::with_capacity(128);
    append_left_padded_biguint_be(&mut xminusz_encoded_bytes, &xminusz_x1);
    append_left_padded_biguint_be(&mut xminusz_encoded_bytes, &xminusz_x0);
    append_left_padded_biguint_be(&mut xminusz_encoded_bytes, &xminusz_y1);
    append_left_padded_biguint_be(&mut xminusz_encoded_bytes, &xminusz_y0);

    // encode the commitment
    let commitment_x_bigint: BigUint = preimage_commitment.x.into();
    let commitment_y_bigint: BigUint = preimage_commitment.y.into();
    let mut commitment_encoded_bytes = Vec::with_capacity(32);
    append_left_padded_biguint_be(&mut commitment_encoded_bytes, &commitment_x_bigint);
    append_left_padded_biguint_be(&mut commitment_encoded_bytes, &commitment_y_bigint);

    // encode the proof
    let proof_x_bigint: BigUint = kzg_proof.x.into();
    let proof_y_bigint: BigUint = kzg_proof.y.into();
    let mut proof_encoded_bytes = Vec::with_capacity(64);
    append_left_padded_biguint_be(&mut proof_encoded_bytes, &proof_x_bigint);
    append_left_padded_biguint_be(&mut proof_encoded_bytes, &proof_y_bigint);

    out.write_all(&*hash)?; // hash [:32]
    out.write_all(&*z)?; // evaluation point [32:64]
    out.write_all(&*proven_y)?; // expected output [64:96]
    out.write_all(&xminusz_encoded_bytes)?; // g2TauMinusG2z [96:224]
    out.write_all(&*commitment_encoded_bytes)?; // kzg commitment [224:288]
    out.write_all(&proof_encoded_bytes)?; // proof [288:352]

    Ok(())
}

// Helper function to append BigUint bytes into the vector with padding; left padded big endian bytes to 32
fn append_left_padded_biguint_be(vec: &mut Vec<u8>, biguint: &BigUint) {
    let bytes = biguint.to_bytes_be();
    let padding = 32 - bytes.len();
    vec.extend_from_slice(&vec![0; padding]);
    vec.extend_from_slice(&bytes);
}
