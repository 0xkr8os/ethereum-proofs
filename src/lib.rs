#![cfg_attr(not(feature = "std"), no_std)]

pub mod eip1186;
pub mod node_codec;
pub mod types;
pub mod utils;

#[cfg(feature = "std")]
mod rstd {
    pub use core::fmt::Debug;
    pub use std::error::Error;
    pub use std::format;
    pub use std::{collections::BTreeMap, result, vec};
}

#[cfg(not(feature = "std"))]
mod rstd {
    extern crate alloc;
    extern crate trie_db;
    pub use alloc::collections::BTreeMap;
    pub use alloc::format;
    pub use alloc::string::ToString;
    pub use alloc::vec;
    pub use core::result;

    pub trait Error {}
    impl<T> Error for T {}
}

use core::panic;

use hash_db::HashDBRef;
use rstd::{vec::Vec, BTreeMap};
use trie_db::{DBValue, Result, Result as TrieResult, TrieHash, CError, TrieLayout, HashDB, Hasher, TrieDBBuilder, Recorder, Trie, TrieDB};


use alloy_primitives::{Address, B256, U256};

use eip1186::{_verify_proof, EIP1186Layout};
use types::KeccakHasher;
pub type StateProofsInput = BTreeMap<Address, Vec<Vec<u8>>>;
pub type StorageProofsInput = BTreeMap<Address, BTreeMap<U256, Vec<Vec<u8>>>>;

pub type EIP1186TrieDB<'a> = TrieDB<'a, 'a, EIP1186Layout>;

pub fn verify_proof(root: &B256, proofs: &Vec<Vec<u8>>, key: &[u8], value: Option<&[u8]>) {
    let res = _verify_proof::<EIP1186Layout>(root, proofs, key, value);

    match &res {
        Ok(_) => return,
        Err(eip1186::VerifyError::NonExistingValue(_e)) => {
            panic!("Non existing value for given key")
        }
        Err(eip1186::VerifyError::HashDecodeError(e)) => panic!("Hash decode error: {:?}", e),
        Err(eip1186::VerifyError::HashMismatch(e)) => panic!("hash mismatch: {:?}", e),
        Err(eip1186::VerifyError::IncompleteProof) => panic!("Incomplete proof"),
        Err(eip1186::VerifyError::ValueMismatch(e)) => panic!("Value mismatch: {:?}", e),
        _ => panic!("Unknown error"),
    }
}

/// Generate an eip-1186 compatible proof for key-value pairs in a trie given a key.
pub fn generate_proof(
  db: &dyn HashDBRef<KeccakHasher, DBValue>,
  root: &B256,
  key: &[u8],
) -> TrieResult<(Vec<Vec<u8>>, Option<Vec<u8>>), TrieHash<EIP1186Layout>, CError<EIP1186Layout>>

{
  let mut recorder = Recorder::<EIP1186Layout>::new();

  let item = {
      let trie = TrieDBBuilder::<EIP1186Layout>::new(db, root)
          .with_recorder(&mut recorder)
          .build();
      trie.get(key)?
  };

  let proof: Vec<Vec<u8>> = recorder.drain().into_iter().map(|r| r.data).collect();
  Ok((proof, item))
}
