use rand_core::impls::fill_bytes_via_next;
use rand_core::le::read_u64_into;
use rand_core::{Error, RngCore, SeedableRng};

const GOLDEN_GAMMA: u64 = 0x9e3779b97f4a7c15;

/// SplitMix generator state
///
/// SplitMix is a splittable pseudorandom number generator (PRNG) that is quite fast.
///
/// Guy L. Steele, Jr., Doug Lea, and Christine H. Flood. 2014. Fast splittable pseudorandom number
/// generators. In Proceedings of the 2014 ACM International Conference on Object Oriented Programming
/// Systems Languages & Applications (OOPSLA '14). ACM, New York, NY, USA, 453-472.
/// [DOI](https://doi.org/10.1145/2660193.2660195)
///
/// The paper describes a new algorithm SplitMix for splittable pseudorandom number generator that
/// is quite fast: 9 64 bit arithmetic/logical operations per 64 bits generated.
///
/// This **should not be used for cryptographic or security applications**, because generated sequences
/// of pseudorandom values are too predictable (the mixing functions are easily inverted, and two
/// successive outputs suffice to reconstruct the internal state).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SMGen {
    seed: u64,
    gamma: u64,
}

impl SMGen {
    /// Split a generator into two uncorrelated generators
    pub fn split(&mut self) -> Self {
        self.seed = self.seed.wrapping_add(self.gamma);
        SMGen {
            seed: mix64(self.seed),
            gamma: {
                self.seed = self.seed.wrapping_add(self.gamma);
                mix_gamma(self.seed)
            },
        }
    }
}

impl RngCore for SMGen {
    fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.seed = self.seed.wrapping_add(self.gamma);
        self.seed
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        fill_bytes_via_next(self, dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl SeedableRng for SMGen {
    type Seed = [u8; 8];

    fn from_seed(seed: Self::Seed) -> Self {
        let mut dst: [u64; 1] = [1];
        read_u64_into(&seed, &mut dst);
        SeedableRng::seed_from_u64(dst[0])
    }

    fn seed_from_u64(state: u64) -> Self {
        SMGen {
            seed: mix64(state),
            gamma: mix_gamma(state.wrapping_add(GOLDEN_GAMMA)),
        }
    }
}

fn mix64(z: u64) -> u64 {
    let z = shift_xor_mult(33, 0xff51afd7ed558ccd, z);
    let z = shift_xor_mult(33, 0xc4ceb9fe1a85ec53, z);
    let z = shift_xor(31, z);
    z
}

fn mix64_variant_13(z: u64) -> u64 {
    let z = shift_xor_mult(30, 0xbf58476d1ce4e5b9, z);
    let z = shift_xor_mult(27, 0x94d049bb133111eb, z);
    let z = shift_xor(31, z);
    z
}

fn mix_gamma(z: u64) -> u64 {
    let z = mix64_variant_13(z) | 1;
    let n = shift_xor(z, 1).count_ones();
    if n >= 24 {
        z
    } else {
        z ^ 0xaaaaaaaaaaaaaaaa
    }
}

fn shift_xor(w: u64, n: u64) -> u64 {
    w ^ (w >> n)
}

fn shift_xor_mult(n: u64, k: u64, w: u64) -> u64 {
    shift_xor(w, n).wrapping_mul(k)
}
