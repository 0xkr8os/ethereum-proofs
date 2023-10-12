#![cfg_attr(not(feature = "std"), no_std)]

pub mod eip1186;
pub mod node_codec;
pub mod hasher;

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

pub use eip1186::{RlpTrieLayout, VerifyError};
pub use hasher::KeccakHasher;

use hash_db::{HashDBRef, Hasher};
use node_codec::NULL_NODE;
use rstd::vec::Vec;
use trie_db::{DBValue, Result as TrieResult, TrieHash, CError, TrieLayout, TrieDBBuilder, Recorder, Trie, NibbleSlice};
use memory_db::{MemoryDB, HashKey};
use eip1186::process_node;

pub type EthereumLayout = RlpTrieLayout<KeccakHasher>;

pub type EthereumMemoryDB =
    MemoryDB<<RlpTrieLayout<KeccakHasher> as TrieLayout>::Hash, HashKey<<RlpTrieLayout<KeccakHasher> as TrieLayout>::Hash>, DBValue>;

pub fn empty_db() -> EthereumMemoryDB {
  EthereumMemoryDB::new(&NULL_NODE)
}

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
		let trie = TrieDBBuilder::<L>::new(db, root).with_recorder(&mut recorder).build();
		trie.get(<L::Hash>::hash(key).as_ref())?
	};

	let proof: Vec<Vec<u8>> = recorder.drain().into_iter().map(|r| r.data).collect();

	Ok((proof, item))
}

/// Verify a compact proof for key-value pairs in a trie given a root hash.
pub fn verify_proof<'a, L>(
  root: &<L::Hash as Hasher>::Out,
  proof: &'a [Vec<u8>],
  raw_key: &'a [u8],
  expected_value: Option<&[u8]>,
) -> Result<(), VerifyError<'a, TrieHash<L>, CError<L>>>
where
  L: TrieLayout,
  <L::Hash as Hasher>::Out: 'a,
{
  if proof.is_empty() {
      return Err(VerifyError::IncompleteProof);
  }

  let key = NibbleSlice::new(raw_key);
  process_node::<L>(Some(root), &proof[0], key, expected_value, &proof[1..])
}

#[cfg(test)]
mod tests {
    use super::*;

    use trie_db::{TrieLayout, SecTrieDBMut, TrieMut};
    use hash_db::Hasher;

      fn test_entries() -> Vec<(&'static [u8], &'static [u8])> {
        vec![
          // "alfa" is at a hash-referenced leaf node.
          (b"alfa", &[0; 32]),
          // "bravo" is at an inline leaf node.
          (b"bravo", b"bravo"),
          // "do" is at a hash-referenced branch node.
          (b"do", b"verb"),
          // "dog" is at a hash-referenced branch node.
          (b"dog", b"puppy"),
          // "doge" is at a hash-referenced leaf node.
          (b"doge", &[0; 32]),
          // extension node "o" (plus nibble) to next branch.
          (b"horse", b"stallion"),
          (b"house", b"building"),
        ]
      }

      #[test]
      fn it_should_generate_verifiable_proof(){
        let entries = test_entries();
        let key = entries[0].0;
        let value = entries[0].1;

        let (root, proof, item) = test_generate_proof::<EthereumLayout>(entries, key);
        assert!(item.is_some());

        let test = [0; 32];
        println!("test: {:?}", test.len());

        verify_proof::<EthereumLayout>(&root, &proof, &KeccakHasher::hash(key), Some(value)).expect("Failed to verify generated proof");
      }

      fn test_generate_proof<L: TrieLayout>(
        entries: Vec<(&[u8], &[u8])>,
        key: &[u8],
      ) -> (<L::Hash as Hasher>::Out, Vec<Vec<u8>>, Option<Vec<u8>>) {
        // Populate DB with full trie from entries.
        
        let (db, root) = {
          //let mut db = <MemoryDB<_, HashKey<_>, DBValue>>::default();
          let mut db = <MemoryDB<_, HashKey<_>, DBValue>>::new(&NULL_NODE);
          let mut root = Default::default();
          {
            let mut trie = <SecTrieDBMut<L>>::new(&mut db, &mut root);
            for (key, value) in entries.iter() {
              trie.insert(key, value).unwrap();
            }
          }
          (db, root)
        };
        // Generate proof for the given keys..
        let (proof, item) = generate_proof::<L>(&db, &root, key).unwrap();
        (root, proof, item)
      }
}
