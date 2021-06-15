use rand_chacha::ChaCha20Rng;
use crate::{CRHFunction, poseidon_parameters_for_test1};
use ark_crypto_primitives::{FixedLengthCRH, FixedLengthCRHGadget};
use rand_chacha::rand_core::SeedableRng;
use ark_relations::r1cs::ConstraintSystem;
use ark_crypto_primitives::crh::poseidon::constraints::{PoseidonRoundParamsVar, PoseidonCRHGadget};
use ark_r1cs_std::bits::uint8::UInt8;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::R1CSVar;
use ark_relations::*;
#[test]
fn test_poseidon_constraints() {
    let seed =  &[32u8; 32];
    let mut rng = ChaCha20Rng::from_seed(*seed);
    let mut parameter =CRHFunction::setup(&mut rng).unwrap();
    parameter = poseidon_parameters_for_test1(parameter);

    let inp= [32u8; 32];
    //output
    let out =
        <CRHFunction as FixedLengthCRH>::evaluate(&parameter, &inp).unwrap();

    let cs = ConstraintSystem::new_ref();
    let param_var = PoseidonRoundParamsVar::new_witness(ns!(cs, "t"), ||Ok(parameter.clone())).unwrap();
    let out_var = PoseidonCRHGadget::evaluate(&param_var,
                                              &UInt8::new_witness_vec(ark_relations::ns!(cs, "declare_input"), &inp).unwrap()).unwrap();

    assert_eq!(out, out_var.value().unwrap());
}