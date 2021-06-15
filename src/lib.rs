#![no_std]

pub mod poseidon;
mod test;
//mod test_poss;
//mod poseidon_com;

//mod blake2s;
use ark_bls12_377::Bls12_377;

pub type CurveTypeG = Bls12_377;
pub use poseidon::*;
//pub use poseidon::CRHCircuit;

//