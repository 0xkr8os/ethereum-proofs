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
use trie_db::{DBValue, Result as TrieResult, TrieHash, CError, TrieLayout, HashDB, Hasher, TrieDBBuilder, Recorder, Trie, TrieDB, NibbleSlice};


use alloy_primitives::{Address, B256, U256};

pub use eip1186::{EIP1186Layout, VerifyError, process_node};
pub use types::KeccakHasher;
pub type StateProofsInput = BTreeMap<Address, Vec<Vec<u8>>>;
pub type StorageProofsInput = BTreeMap<Address, BTreeMap<U256, Vec<Vec<u8>>>>;

pub type EIP1186TrieDB<'a, H> = trie_db::TrieDBBuilder<'a, 'a, EIP1186Layout<H>>;

/// Verify a compact proof for key-value pairs in a trie given a root hash.
pub fn verify_proof<'a, L>(
  root: &<L::Hash as Hasher>::Out,
  proof: &'a [Vec<u8>],
  raw_key: &'a [u8],
  expected_value: Option<&[u8]>,
) -> Result<(), VerifyError<'a, TrieHash<L>, CError<L>>>
where
  L: TrieLayout,
{
  if proof.is_empty() {
      return Err(VerifyError::IncompleteProof);
  }
  let key = NibbleSlice::new(raw_key);
  process_node::<L>(Some(root), &proof[0], key, expected_value, &proof[1..])
}

/// Generate an eip-1186 compatible proof for key-value pairs in a trie given a key.
pub fn generate_proof<L>(
  db: &dyn HashDBRef<L::Hash, DBValue>,
  root: &TrieHash<L>,
  key: &[u8],
) -> TrieResult<(Vec<Vec<u8>>, Option<Vec<u8>>), TrieHash<L>, CError<L>>
where
  L: TrieLayout,
{
  let mut recorder = Recorder::<L>::new();

  let item = {
      let trie = TrieDBBuilder::<L>::new(db, root)
          .with_recorder(&mut recorder)
          .build();
      trie.get(key)?
  };

  let proof: Vec<Vec<u8>> = recorder.drain().into_iter().map(|r| r.data).collect();
  Ok((proof, item))
}

