
use crate::utils::Bytes32;
use ark_ec::{AffineRepr, CurveGroup,pairing::Pairing};
use kzgbn254::{
    kzg::Kzg,
    blob::Blob,
    helpers::{remove_empty_byte_from_padded_bytes, to_fr_array}
};
use eyre::{ensure, Result};
use ark_bn254::{Bn254, G1Affine, G1Projective, G2Affine};
use num::BigUint;
use sha2::{Digest, Sha256};
use std::{convert::TryFrom, io::Write};
use ark_serialize::CanonicalSerialize;
use num::Zero;

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

pub fn prove_kzg_preimage_bn254(
    hash: Bytes32,
    preimage: &[u8],
    offset: u32,
    out: &mut impl Write,
) -> Result<()> {

    let mut kzg = KZG.clone();

    // expand the roots of unity, should work as long as it's longer than chunk length and chunks
    // from my understanding the data_setup_mins pads both min_chunk_len and min_num_chunks to 
    // the next power of 2 so we can load a max of 2048 from the test values here
    // then we can take the roots of unity we actually need (len polynomial) and pass them in
    // @anup, this is a really gross way to do this, pls tell better way
    kzg.data_setup_mins(1, 2048)?;

    // we are expecting the preimage to be unpadded when turned into a blob function so need to unpad it first
    let unpadded_preimage_vec: Vec<u8> = remove_empty_byte_from_padded_bytes(preimage);
    let unpadded_preimage = unpadded_preimage_vec.as_slice();

    // repad it here, TODO: need to ask to change the interface for this
    let blob = Blob::from_bytes_and_pad(unpadded_preimage);
    let blob_polynomial = blob.to_polynomial().unwrap();
    let blob_commitment = kzg.commit(&blob_polynomial).unwrap();

    let mut commitment_bytes = Vec::new();
    blob_commitment.serialize_uncompressed(&mut commitment_bytes).unwrap();

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

    let offset_usize = usize::try_from(offset)?;
    let mut proving_offset = offset;

    // address proving past end edge case later
    let proving_past_end = offset_usize >= preimage.len();
    if proving_past_end {
        // Proving any offset proves the length which is all we need here,
        // because we're past the end of the preimage.
        proving_offset = 0;
    }
    
    let proving_offset_bytes = proving_offset.to_le_bytes();
    let mut padded_proving_offset_bytes = [0u8; 32];
    padded_proving_offset_bytes[32 - proving_offset_bytes.len()..].copy_from_slice(&proving_offset_bytes);

    // in production we will first need to perform an IFFT on the blob data to get the expected y value
    let mut proven_y = blob.get_blob_data();
    let offset_usize = offset as usize; // Convert offset to usize
    proven_y = proven_y[offset_usize..(offset_usize + 32)].to_vec();

    let proven_y_fr = to_fr_array(&proven_y);

    let polynomial = blob.to_polynomial().unwrap();
    
    let g2_generator = G2Affine::generator();
    let z_g2= (g2_generator * proven_y_fr[0]).into_affine();

    let g2_tau: G2Affine = kzg.get_g2_points().get(1).unwrap().clone();
    let g2_tau_minus_g2_z = (g2_tau - z_g2).into_affine();

    // required roots of unity are the first polynomial length roots in the expanded set
    let roots_of_unity = kzg.get_expanded_roots_of_unity();
    let required_roots_of_unity = &roots_of_unity[0..polynomial.len()];
    // TODO: ask for interface alignment later
    let kzg_proof = match kzg.compute_kzg_proof(&blob_polynomial, offset as u64, &required_roots_of_unity.to_vec()) {
        Ok(proof) => proof,
        Err(err) => return Err(err.into()),
    };

    let mut kzg_proof_uncompressed_bytes = Vec::new();
    kzg_proof.serialize_uncompressed(&mut kzg_proof_uncompressed_bytes).unwrap();

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

