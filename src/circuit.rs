use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use ark_crypto_primitives::{
    crh::{
        constraints::{CRHSchemeGadget, TwoToOneCRHSchemeGadget},
        sha256::constraints::DigestVar,
    },
    merkle_tree::{constraints::PathVar, Config, Path},
};

use crate::merkle_tree::*;

#[derive(Clone, Default)]
pub struct Sha256MerkleProofCircuit {
    pub root: <Sha256MerkleTreeParams as Config>::InnerDigest,
    pub leaf: Vec<u8>,
    pub proof: Path<Sha256MerkleTreeParams>,
}

impl ConstraintSynthesizer<ConstraintF> for Sha256MerkleProofCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        assert!(self.root.len() == 32, "invalid root");
        let root_var = UInt8::new_input_vec(cs.clone(), &self.root).unwrap();

        let constraints_from_root = cs.num_constraints();
        println!("constraints from root: {}", constraints_from_root);

        let crh_params = ();
        let leaf_crh_params_var =
            <LeafHG as CRHSchemeGadget<LeafH, ConstraintF>>::ParametersVar::new_constant(
                ark_relations::ns!(cs, "leaf_crh_parameter"),
                &crh_params,
            )
            .unwrap();
        let two_to_one_crh_params_var = <CompressHG as TwoToOneCRHSchemeGadget<
            CompressH,
            ConstraintF,
        >>::ParametersVar::new_constant(
            ark_relations::ns!(cs, "two_to_one_crh_parameter"),
            &crh_params,
        )
        .unwrap();

        let constraints_from_params = cs.num_constraints() - constraints_from_root;
        println!("constraints from parameters: {}", constraints_from_params);

        let leaf_var = UInt8::new_witness_vec(cs.clone(), &self.leaf).unwrap();

        let constraints_from_leaf =
            cs.num_constraints() - constraints_from_root - constraints_from_params;
        println!("constraints from leaf: {}", constraints_from_leaf);

        let path_var: PathVar<Sha256MerkleTreeParams, ConstraintF, Sha256MerkleTreeParamsVar> =
            PathVar::new_witness(ark_relations::ns!(cs, "new_witness"), || Ok(&self.proof))
                .unwrap();

        let constraints_from_path = cs.num_constraints()
            - constraints_from_root
            - constraints_from_params
            - constraints_from_leaf;
        println!("constraints from path: {}", constraints_from_path);

        let verified = path_var
            .verify_membership(
                &leaf_crh_params_var,
                &two_to_one_crh_params_var,
                &DigestVar(root_var),
                &leaf_var,
            )
            .unwrap()
            .value();

        if !cs.is_in_setup_mode() {
            assert!(verified.unwrap());
        };

        let setup_constraints = constraints_from_params
            + constraints_from_root
            + constraints_from_leaf
            + constraints_from_path;
        println!(
            "number of constraints: {}",
            cs.num_constraints() - setup_constraints
        );

        if !cs.is_in_setup_mode() {
            assert!(cs.is_satisfied().unwrap(), "constraints not satisfied");
        }

        Ok(())
    }
}
