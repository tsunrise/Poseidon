//use ark_bls12_381::Fq;
use ark_crypto_primitives::{FixedLengthCRH};//, crh::poseidon::PoseidonCRH};
//use ark_crypto_primitives::CommitmentScheme;
//use ark_ed_on_bls12_381::*;
//use ark_crypto_primitives::{crh::{poseidon,FixedLengthCRH},};
//use ark_bls12_381::Bls12_381;
//use ark_ed_on_bls12_381::Fq;
//use ark_ed_on_bls12_381::*;
//use ark_ff::UniformRand;
//use crate::poseidon::{PoseidonCRH};
use poseidon_from_arkworks::*;
use std::time::Instant;
use rand_chacha::ChaCha20Rng;
use ark_std::{rand::SeedableRng};
fn main() {
	let start = Instant::now();
    //  fix a secret key
    let seed =  &[32u8; 32];
    let mut rng = ChaCha20Rng::from_seed(*seed);
	let mut parameter =CRHFunction::setup(&mut rng).unwrap();  
	parameter = poseidon_parameters_for_test1(parameter);
    
    //println!("parameter.params ={:?}",parameter.params);

	let inp= [32u8; 32];
	//output
	let out =
	 <CRHFunction as FixedLengthCRH>::evaluate(&parameter, &inp).unwrap();
	//println!("out ={:?}",out);
    // build the circuit
    let circuit = CRHCircuit {
        param: parameter.clone(),
        input: inp,
        output: out,
    };

    let elapse = start.elapsed();
    let start2 = Instant::now();

    // generate a zkp parameters
    let zk_param = groth_param_gen1(parameter);

    let elapse2 = start2.elapsed();
    let start3 = Instant::now();
    
    let proof = groth_proof_gen1(&zk_param, circuit, &[32u8; 32]);

    let elapse3 = start3.elapsed();

    let start4 = Instant::now();
    groth_verify1(&zk_param, &proof, &out);
    let elapse4 = start4.elapsed();

    println!("time to prepare comm: {:?}", elapse);
    println!("time to gen groth param: {:?}", elapse2);
    println!("time to gen proof: {:?}", elapse3);
    println!("time to verify proof: {:?}", elapse4);
}
    
