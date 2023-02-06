// For benchmark, run:
//     RAYON_NUM_THREADS=N cargo bench --no-default-features --features "std parallel" -- --nocapture
// where N is the number of threads you want to use (N = 1 for single-thread).

use std::env;

use ark_bn254::Bn254;
use ark_crypto_primitives::{
    crh::sha256::constraints::{DigestVar, Sha256Gadget},
    snark::SNARK,
};
use ark_ff::{PrimeField, ToConstraintField};
use ark_groth16::Groth16;
use ark_r1cs_std::{prelude::EqGadget, uint8::UInt8};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::rand::{self, rngs::StdRng};

struct Sha256Circuit {
    pub data: Vec<u8>,
    pub expect: Vec<u8>,
}

impl Clone for Sha256Circuit {
    fn clone(&self) -> Self {
        Sha256Circuit {
            data: self.data.as_slice().to_vec(),
            expect: self.expect.as_slice().to_vec(),
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for Sha256Circuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let data = UInt8::new_witness_vec(cs.clone(), &self.data).unwrap();
        let expect = UInt8::new_input_vec(cs.clone(), &self.expect).unwrap();

        let mut sha256_var = Sha256Gadget::default();
        sha256_var.update(&data).unwrap();

        sha256_var
            .finalize()?
            .enforce_equal(&DigestVar(expect.clone()))?;

        println!(
            "num_constraints of sha256 with input size {} bytes : {}",
            self.data.len(),
            cs.num_constraints()
        );

        Ok(())
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let num_of_64_bytes = args[1].parse::<usize>().unwrap();
    let expect = hex::decode(args[2].parse::<String>().unwrap()).unwrap();

    let input_size = 64 * num_of_64_bytes;
    let input_str = vec![0u8; input_size];
    let circuit = Sha256Circuit {
        data: input_str,
        expect: expect.clone(),
    };

    type GrothSetup = Groth16<Bn254>;
    let mut test_rng = test_rng();
    let (pk, vk) = GrothSetup::circuit_specific_setup(circuit.clone(), &mut test_rng).unwrap();
    let start = ark_std::time::Instant::now();
    let proof = GrothSetup::prove(&pk, circuit, &mut test_rng).unwrap();
    println!(
        "proving time for sha256 with input size {} bytes: {} ms",
        input_size,
        start.elapsed().as_millis()
    );
    let start = ark_std::time::Instant::now();
    let res = GrothSetup::verify(&vk, &expect.to_field_elements().unwrap(), &proof).unwrap();
    println!(
        "verifying time for sha256 with input size {} bytes: {} ms",
        input_size,
        start.elapsed().as_millis()
    );
    assert!(res);
}

fn test_rng() -> StdRng {
    use rand::SeedableRng;
    // arbitrary seed
    let seed = [
        1, 0, 0, 0, 23, 0, 0, 0, 200, 1, 0, 0, 210, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0,
    ];
    rand::rngs::StdRng::from_seed(seed)
}
