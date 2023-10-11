use core::hash::Hasher;
use tiny_keccak::{Hasher as CoreHasher, Keccak};

pub struct Keccak256Hasher {
    keccak: Keccak,
}

impl Keccak256Hasher {
    pub fn new() -> Self {
        Self {
            keccak: Keccak::v256(),
        }
    }
}

impl Hasher for Keccak256Hasher {
    fn finish(&self) -> u64 {
        let mut output = [0u8; 32];
        self.keccak.clone().finalize(&mut output);
        u64::from_be_bytes([
            output[0], output[1], output[2], output[3], output[4], output[5], output[6], output[7],
        ])
    }

    fn write(&mut self, bytes: &[u8]) {
        self.keccak.update(bytes);
    }
}

impl Default for Keccak256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Default, Debug, Clone, PartialEq)]
pub struct KeccakHasher;

impl hash_db::Hasher for KeccakHasher {
    type Out = [u8; 32];
    const LENGTH: usize = 32;

    fn hash(x: &[u8]) -> Self::Out {
        let mut keccak_256: Keccak = Keccak::v256();
        let mut output = [0u8; 32];

        keccak_256.update(x);
        keccak_256.finalize(&mut output);

        output
    }

    type StdHasher = Keccak256Hasher;
}
