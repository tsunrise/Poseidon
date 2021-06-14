use ark_crypto_primitives::{
	SNARK,
    crh::{poseidon, poseidon::sbox::PoseidonSbox,
        poseidon::Poseidon,poseidon::CRH,poseidon::constraints::{CRHGadget,PoseidonRoundParamsVar},CRH as CRHTrait,CRHGadget as CRHGadgetTrait},
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_bls12_381::Bls12_381;
use ark_ed_on_bls12_381::Fq;
use ark_ff::ToConstraintField;
use ark_groth16::*;
use ark_r1cs_std::{alloc::AllocVar, prelude::*};
use ark_std::{rand::SeedableRng,vec::Vec};
use rand_chacha::ChaCha20Rng;
use ark_std::vec;
use ark_ff::PrimeField;


//Parameters for Poseidon
pub const POSEIDON_WIDTH: usize = 6;
pub const POSEIDON_FULL_ROUNDS_BEGINNING: usize = 8;
pub const POSEIDON_FULL_ROUNDS_END: usize = 0;
pub const POSEIDON_PARTIAL_ROUNDS: usize = 36;
pub const POSEIDON_SBOX: PoseidonSbox=PoseidonSbox::Exponentiation(5);

#[derive(Default,Clone, Debug)]
pub struct PParams;
impl poseidon::PoseidonRoundParams<Fq> for PParams {
    const WIDTH: usize = POSEIDON_WIDTH;
    /// Number of full SBox rounds in beginning
    const FULL_ROUNDS_BEGINNING: usize =POSEIDON_FULL_ROUNDS_BEGINNING;
    /// Number of full SBox rounds in end
    const FULL_ROUNDS_END: usize = POSEIDON_FULL_ROUNDS_END;
    /// Number of partial rounds
    const PARTIAL_ROUNDS: usize = POSEIDON_PARTIAL_ROUNDS;

    const SBOX :PoseidonSbox= POSEIDON_SBOX;
}

pub type PoseidonParam =Poseidon<Fq, PParams>;
pub type CRHFunction =CRH<Fq, PParams>;
pub type CRHOutput= <CRHFunction as CRHTrait>::Output;
pub type CRHParam=<CRHFunction as CRHTrait>::Parameters;
pub type CRHInput = [u8; 32];

//#[derive(Clone)]
pub struct CRHCircuit {
	pub param: CRHParam,
	pub input: CRHInput,
	pub output: CRHOutput
}


impl ConstraintSynthesizer<Fq> for CRHCircuit{
	/// Input a circuit, build the constraint system and add it to `cs`
	fn generate_constraints(self, cs: ConstraintSystemRef<Fq>) -> Result<(), SynthesisError>{
        let pos_param_var = PoseidonRoundParamsVar::new_input(ark_relations::ns!(cs, "gadget_parameters"), || {
            Ok(&self.param)
        })
        .unwrap();      
		crh_circuit_helper( &self.input, &self.output, cs,pos_param_var)?;
		Ok(())
	}
}

/// generate CRS given parameter of poseidon hash
#[allow(dead_code)]
pub fn groth_param_gen_p(param11: PoseidonParam) -> <Groth16<Bls12_381> as SNARK<Fq>>::ProvingKey {
	let inpt = [32u8; 32]; 
	let out = <CRHFunction as CRHTrait>::evaluate(&param11, &inpt).unwrap();

    let circuit = CRHCircuit {
        param: param11,
        input: inpt,
        output: out,
    };	
    let mut rng = ark_std::test_rng();

    generate_random_parameters::<Bls12_381, _, _>(circuit, &mut rng).unwrap()
}

#[allow(dead_code)]
pub fn groth_proof_gen_p(
    param: &<Groth16<Bls12_381> as SNARK<Fq>>::ProvingKey,
    circuit: CRHCircuit,
    seed: &[u8; 32],
) -> <Groth16<Bls12_381> as SNARK<Fq>>::Proof {
    let mut rng = ChaCha20Rng::from_seed(*seed);
    create_random_proof(circuit, &param, &mut rng).unwrap()
}

#[allow(dead_code)]
pub fn groth_verify_p(
    param: &<Groth16<Bls12_381> as SNARK<Fq>>::ProvingKey,
    proof: &<Groth16<Bls12_381> as SNARK<Fq>>::Proof,
    output: &CRHOutput,
) -> bool {
    let pvk = prepare_verifying_key(&param.vk);
	let output_fq: Vec<Fq> = ToConstraintField::<Fq>::to_field_elements(output).unwrap();
    verify_proof(&pvk, &proof, &output_fq).unwrap()
}

// ======

pub(crate) fn crh_circuit_helper(
	input: &[u8; 32],
	output: &CRHOutput,
	cs: ConstraintSystemRef<Fq>,
    pos_param_var: PoseidonRoundParamsVar<Fq,PParams>,
) -> Result<(), SynthesisError> {

	// step 1. Allocate parameter
    let parameters_var = pos_param_var;

	// step 2. Allocate inputs
	let input_var = UInt8::new_witness_vec(ark_relations::ns!(cs, "declare_input"), input)?;
	
	// step 3. Allocate evaluated output
	let output_var = CRHGadget::evaluate(&parameters_var, &input_var)?;

	// step 4. Actual output
	 let actual_out_var = <CRHGadget<Fq,PParams> as CRHGadgetTrait<_,Fq >>::OutputVar::new_input(
	 	ark_relations::ns!(cs, "declare_output"),
	 	|| Ok(output),
	 )?;
     
	// step 5. compare the outputs
	output_var.enforce_equal(&actual_out_var)?;

	Ok(())
}



pub fn poseidon_parameters_for_test1<F: PrimeField>(mut pos: Poseidon<F, PParams>) -> Poseidon<F, PParams> {
    //let alpha = 5;
    let mds = vec![
        vec![
            F::from_str(
                "43228725308391137369947362226390319299014033584574058394339561338097152657858",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "20729134655727743386784826341366384914431326428651109729494295849276339718592",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "14275792724825301816674509766636153429127896752891673527373812580216824074377",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "43228725308391137369947362226390319299014033584574058394339561338097152657858",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "20729134655727743386784826341366384914431326428651109729494295849276339718592",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "14275792724825301816674509766636153429127896752891673527373812580216824074377",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "3039440043015681380498693766234886011876841428799441709991632635031851609481",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "6678863357926068615342013496680930722082156498064457711885464611323928471101",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "37355038393562575053091209735467454314247378274125943833499651442997254948957",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "3039440043015681380498693766234886011876841428799441709991632635031851609481",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "6678863357926068615342013496680930722082156498064457711885464611323928471101",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "37355038393562575053091209735467454314247378274125943833499651442997254948957",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "26481612700543967643159862864328231943993263806649000633819754663276818191580",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "30103264397473155564098369644643015994024192377175707604277831692111219371047",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "5712721806190262694719203887224391960978962995663881615739647362444059585747",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "26481612700543967643159862864328231943993263806649000633819754663276818191580",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "30103264397473155564098369644643015994024192377175707604277831692111219371047",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "5712721806190262694719203887224391960978962995663881615739647362444059585747",
            )
            .map_err(|_| ())
            .unwrap(),

        ],
         vec![
            F::from_str(
                "43228725308391137369947362226390319299014033584574058394339561338097152657858",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "20729134655727743386784826341366384914431326428651109729494295849276339718592",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "14275792724825301816674509766636153429127896752891673527373812580216824074377",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "43228725308391137369947362226390319299014033584574058394339561338097152657858",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "20729134655727743386784826341366384914431326428651109729494295849276339718592",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "14275792724825301816674509766636153429127896752891673527373812580216824074377",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "3039440043015681380498693766234886011876841428799441709991632635031851609481",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "6678863357926068615342013496680930722082156498064457711885464611323928471101",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "37355038393562575053091209735467454314247378274125943833499651442997254948957",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "3039440043015681380498693766234886011876841428799441709991632635031851609481",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "6678863357926068615342013496680930722082156498064457711885464611323928471101",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "37355038393562575053091209735467454314247378274125943833499651442997254948957",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "26481612700543967643159862864328231943993263806649000633819754663276818191580",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "30103264397473155564098369644643015994024192377175707604277831692111219371047",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "5712721806190262694719203887224391960978962995663881615739647362444059585747",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "26481612700543967643159862864328231943993263806649000633819754663276818191580",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "30103264397473155564098369644643015994024192377175707604277831692111219371047",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "5712721806190262694719203887224391960978962995663881615739647362444059585747",
            )
            .map_err(|_| ())
            .unwrap(),

        ],
    ];
	//let mut seed = ark_std::test_rng();
    let mut seed =[0u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);
    let  rng1 = F::rand(&mut rng);
    let mut vals: Vec<F> = vec![rng1];
    let mut  k = 0;
    for i in 0..269 {
        k = k + 1;
        seed[i%8] = seed[i%8]+1;
        let mut rng = ChaCha20Rng::from_seed(seed);
        let  rng1 = F::rand(&mut rng);
        vals.push(rng1);
        if k>(32*7-1){
            k = 0;
        }
    }
    //println("vals = {:?}",vals);
    pos.mds_matrix=mds;
    pos.round_keys=vals;
    pos.params = PParams;
    pos

}
