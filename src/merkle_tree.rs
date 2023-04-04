use ark_r1cs_std::prelude::*;

use ark_bls12_381::Fr;

use ark_crypto_primitives::{
    crh::{
        constraints::{CRHSchemeGadget, TwoToOneCRHSchemeGadget},
        sha256::{constraints::Sha256Gadget, Sha256},
        CRHScheme, TwoToOneCRHScheme,
    },
    merkle_tree::{
        constraints::{BytesVarDigestConverter, ConfigGadget},
        Config, DigestConverter, MerkleTree,
    },
    Error,
};

pub type ConstraintF = Fr;

pub type LeafH = Sha256;
pub type LeafHG = Sha256Gadget<ConstraintF>;

pub type CompressH = Sha256;
pub type CompressHG = Sha256Gadget<ConstraintF>;

pub type LeafVar<ConstraintF> = [UInt8<ConstraintF>];

pub struct CustomDigestConverter;

impl DigestConverter<Vec<u8>, [u8]> for CustomDigestConverter {
    type TargetType = Vec<u8>;

    fn convert(item: Vec<u8>) -> Result<Self::TargetType, Error> {
        Ok(item)
    }
}

pub struct Sha256MerkleTreeParams;

impl Config for Sha256MerkleTreeParams {
    type Leaf = [u8];
    type LeafDigest = <LeafH as CRHScheme>::Output;
    type LeafInnerDigestConverter = CustomDigestConverter;

    type InnerDigest = <CompressH as TwoToOneCRHScheme>::Output;
    type LeafHash = LeafH;
    type TwoToOneHash = CompressH;
}

#[derive(Debug)]
pub struct Sha256MerkleTreeParamsVar;

impl ConfigGadget<Sha256MerkleTreeParams, ConstraintF> for Sha256MerkleTreeParamsVar {
    type Leaf = LeafVar<ConstraintF>;
    type LeafDigest = <LeafHG as CRHSchemeGadget<LeafH, ConstraintF>>::OutputVar;
    type LeafInnerConverter = BytesVarDigestConverter<Self::LeafDigest, ConstraintF>;

    type InnerDigest = <CompressHG as TwoToOneCRHSchemeGadget<CompressH, ConstraintF>>::OutputVar;
    type LeafHash = LeafHG;
    type TwoToOneHash = CompressHG;
}

pub type Sha256MerkleTree = MerkleTree<Sha256MerkleTreeParams>;
