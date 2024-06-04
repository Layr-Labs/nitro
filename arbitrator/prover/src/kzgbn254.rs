
use crate::utils::Bytes32;
use ark_ec::{AffineRepr, CurveGroup};
use kzgbn254::{
    blob::Blob, kzg::Kzg, polynomial::PolynomialFormat
};
use eyre::{ensure, Result};
use ark_bn254::{G2Affine, Fr};
use num::BigUint;
use sha2::{Digest, Sha256};
use std::{io::Write, convert::TryInto};
use ark_serialize::CanonicalSerialize;
use ark_ff::{PrimeField, BigInteger};


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

    // expand roots of unity
    kzg.calculate_roots_of_unity(preimage.len() as u64)?;

    // preimage is already padded, unpadding and repadding already padded data can destroy context post IFFT
    // as some elements in the bn254 field are represented by 32 bytes, we know that the preimage is padded
    // to 32 bytes per DA spec as the preimage is retrieved from DA, so we can use this unchecked function
    let blob = Blob::from_padded_bytes_unchecked(preimage);

    let blob_polynomial_evaluation_form = blob.to_polynomial(PolynomialFormat::InEvaluationForm)?;
    let blob_commitment = kzg.commit(&blob_polynomial_evaluation_form)?;

    let mut blob_polynomial_coefficient_form = blob_polynomial_evaluation_form.clone();
    blob_polynomial_coefficient_form.transform_to_form(PolynomialFormat::InCoefficientForm)?;

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

    // transform polynomial into coefficient form
    let mut blob_polynomial_coefficient_form = blob_polynomial_evaluation_form.clone();
    blob_polynomial_coefficient_form.transform_to_form(PolynomialFormat::InCoefficientForm)?;

    let blob_coefficients = blob_polynomial_coefficient_form.to_vec();
    let mut blob_bytes = Vec::new();
    deserialize_montgomery_elements(&blob_coefficients, &mut blob_bytes);

    // blob header is the first 32 bytes of the blob bytes
    let blob_header = blob_bytes[..32].to_vec();

    // decode blob header, version is currently unused however in the future we probabky
    let (_, length) = decode_codec_blob_header(&blob_header)?;

    let length_usize = length as usize;

    // we set the proving offset to offset + 32 because the first 32 bytes of the array are the header
    let mut proving_offset = (offset + 32) / 32;

    // address proving past end edge case later
    let proving_past_end = offset as usize >= length_usize;
    if proving_past_end {
        // Proving any offset proves the length which is all we need here,
        // because we're past the end of the preimage.
        proving_offset = 0;
    }

    let proving_offset_bytes = proving_offset.to_be_bytes();
    let mut padded_proving_offset_bytes: [u8; 32] = [0u8; 32];
    padded_proving_offset_bytes[32 - proving_offset_bytes.len()..].copy_from_slice(&proving_offset_bytes);

    let proven_y_fr = blob_polynomial_coefficient_form.get_at_index(proving_offset as usize)
        .ok_or_else(|| eyre::eyre!("Index out of bounds"))?;

    let z_fr = kzg.get_nth_root_of_unity(proving_offset as usize)
        .ok_or_else(|| eyre::eyre!("Failed to get nth root of unity"))?;

    let proven_y = proven_y_fr.into_bigint().to_bytes_be();
    
    let g2_generator = G2Affine::generator();
    let z_g2= (g2_generator * z_fr).into_affine();

    // if we are loading in g2 pow2 this is index 0 not 1
    let g2_tau: G2Affine = kzg.get_g2_points().get(1)
        .ok_or_else(|| eyre::eyre!("Failed to get g2 point at index 1 in SRS"))?
        .clone();
    let g2_tau_minus_g2_z = (g2_tau - z_g2).into_affine();

    let kzg_proof = kzg.compute_kzg_proof_with_roots_of_unity(&blob_polynomial_coefficient_form, proving_offset as u64)?;

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
    let commitment_x_bigint: BigUint = blob_commitment.x.into();
    let commitment_y_bigint: BigUint = blob_commitment.y.into();
    let mut commitment_encoded_bytes = Vec::with_capacity(32);
    append_left_padded_biguint_be(&mut commitment_encoded_bytes, &commitment_x_bigint);
    append_left_padded_biguint_be(&mut commitment_encoded_bytes, &commitment_y_bigint);


    // encode the proof
    let proof_x_bigint: BigUint = kzg_proof.x.into();
    let proof_y_bigint: BigUint = kzg_proof.y.into();
    let mut proof_encoded_bytes = Vec::with_capacity(64);
    append_left_padded_biguint_be(&mut proof_encoded_bytes, &proof_x_bigint);
    append_left_padded_biguint_be(&mut proof_encoded_bytes, &proof_y_bigint);

    out.write_all(&*hash)?;                           // hash [:32]
    out.write_all(&padded_proving_offset_bytes)?;     // evaluation point [32:64]
    out.write_all(&*proven_y)?;                       // expected output [64:96]
    out.write_all(&xminusz_encoded_bytes)?;           // g2TauMinusG2z [96:224]
    out.write_all(&*commitment_encoded_bytes)?;       // kzg commitment [224:288]
    out.write_all(&proof_encoded_bytes)?;             // proof [288:352]
    

    Ok(())
}

// Helper function to append BigUint bytes into the vector with padding; left padded big endian bytes to 32
fn append_left_padded_biguint_be(vec: &mut Vec<u8>, biguint: &BigUint) {
    let bytes = biguint.to_bytes_be();
    let padding = 32 - bytes.len();
    vec.extend_from_slice(&vec![0; padding]);
    vec.extend_from_slice(&bytes);            
}

pub fn deserialize_montgomery_elements(data: &[Fr], buffer: &mut Vec<u8>) {
    let mut temp_buffer: Vec<u8> = data.iter()
        .rev()
        .flat_map(|elem| elem.into_bigint().to_bytes_le())
        .collect();
    
    temp_buffer.reverse();
    buffer.extend(temp_buffer);
}

fn decode_codec_blob_header(codec_blob_header: &[u8]) -> Result<(u8, u32)> {
    ensure!(
        codec_blob_header.len() == 32,
        "Codec blob header must be 32 bytes long",
    );

    let version = codec_blob_header[1];
    let length_bytes: [u8; 4] = codec_blob_header[2..6]
        .try_into()
        .map_err(|_| eyre::eyre!("Failed to decode length bytes"))?;
    let length = u32::from_be_bytes(length_bytes);

    Ok((version, length))
}