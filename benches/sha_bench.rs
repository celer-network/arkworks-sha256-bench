// For benchmark, run:
//     RAYON_NUM_THREADS=N cargo bench --no-default-features --features "std parallel" -- --nocapture
// where N is the number of threads you want to use (N = 1 for single-thread).

use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::{
    crh::sha256::{
        constraints::{DigestVar, Sha256Gadget},
        digest::Digest,
        Sha256,
    },
    snark::SNARK,
};
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_r1cs_std::{prelude::EqGadget, uint8::UInt8};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::rand::{self, rngs::StdRng, RngCore};

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
        let expect = UInt8::new_witness_vec(cs, &self.expect).unwrap();

        let mut sha256_var = Sha256Gadget::default();
        sha256_var.update(&data).unwrap();

        sha256_var.finalize()?.enforce_equal(&DigestVar(expect))?;

        Ok(())
    }
}

fn main() {
    let mut rng = ark_std::test_rng();
    // Make a random string of the given length
    let mut input_str = vec![0u8; 24];
    rng.fill_bytes(&mut input_str);
    let mut sha256 = Sha256::default();
    sha256.update(&input_str);
    let expect = sha256.finalize().to_vec();

    let circuit = Sha256Circuit {
        data: input_str,
        expect,
    };

    type GrothSetup = Groth16<Bls12_381>;
    let mut test_rng = test_rng();
    let (pk, vk) = GrothSetup::circuit_specific_setup(circuit.clone(), &mut test_rng).unwrap();
    let start = ark_std::time::Instant::now();
    let proof = GrothSetup::prove(&pk, circuit, &mut test_rng).unwrap();
    println!(
        "per-constraint proving time for sha256: {} ms",
        start.elapsed().as_millis()
    );
    let start = ark_std::time::Instant::now();
    let res = GrothSetup::verify(&vk, &vec![], &proof).unwrap();
    println!(
        "verifying time for sha256: {} ms",
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
