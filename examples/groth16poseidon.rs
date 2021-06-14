use ark_crypto_primitives::{CRH as CRHTrait};
use poseidon_from_arkworks::*;
use std::time::Instant;
use rand_chacha::ChaCha20Rng;
use ark_std::{rand::SeedableRng};
fn main() {
	let start = Instant::now();

    let seed =  &[32u8; 32];
    let mut rng = ChaCha20Rng::from_seed(*seed);
	let mut parameter =CRHFunction::setup(&mut rng).unwrap();  
	parameter = poseidon_parameters_for_test1(parameter);
    
	let inp= [32u8; 32];
	//output
	let out =
	 <CRHFunction as CRHTrait>::evaluate(&parameter, &inp).unwrap();

     // build the circuit
    let circuit = CRHCircuit {
        param: parameter.clone(),
        input: inp,
        output: out,
    };

    let elapse = start.elapsed();
    let start2 = Instant::now();

    // generate zkp parameters
    let zk_param = groth_param_gen_p(parameter);

    let elapse2 = start2.elapsed();
    let start3 = Instant::now();
    
    let proof = groth_proof_gen_p(&zk_param, circuit, &[32u8; 32]);

    let elapse3 = start3.elapsed();

    let start4 = Instant::now();
    groth_verify_p(&zk_param, &proof, &out);
    let elapse4 = start4.elapsed();

    println!("time to prepare comm: {:?}", elapse);
    println!("time to gen groth param: {:?}", elapse2);
    println!("time to gen proof: {:?}", elapse3);
    println!("time to verify proof: {:?}", elapse4);
}
    
