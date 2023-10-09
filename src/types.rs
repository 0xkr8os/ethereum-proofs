use core::hash::Hasher;
use alloy_primitives::{B256, U256};
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

pub struct KeccakHasher;

impl hash_db::Hasher for KeccakHasher {
    type Out = B256;
    const LENGTH: usize = 32;

    fn hash(x: &[u8]) -> Self::Out {
        let mut keccak_256: Keccak = Keccak::v256();
        let mut output = [0u8; 32];

        keccak_256.update(x);
        keccak_256.finalize(&mut output);

        output.into()
    }

    type StdHasher = Keccak256Hasher;
}

// Trie layout for EIP-1186 state proof nodes.

pub struct AccountState {
    pub nonce: u64,
    pub balance: U256,
    pub storage_hash: B256,
    pub code_hash: B256,
}

// impl AccountState {
//     pub fn rlp_encode(&self) -> Vec<u8> {
//         let mut stream = RlpStream::new_list(4);
//         stream.append(&self.nonce);
//         stream.append(&self.balance);
//         stream.append(&self.storage_hash.as_slice());
//         stream.append(&self.code_hash.as_slice());
//         stream.out().to_vec()
//     }
// }
