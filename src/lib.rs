//! An impelemtnation of the SplitMix algorithm
mod splitmix64;

pub use rand_core::{RngCore, SeedableRng};
pub use splitmix64::SMGen;
