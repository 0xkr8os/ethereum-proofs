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

pub use hash_db::{HashDBRef, HashDB, Hasher};
use rstd::{vec::Vec, BTreeMap};
use tiny_keccak::Keccak;
use trie_db::{DBValue, Result as TrieResult, TrieHash, CError, TrieLayout, TrieDBBuilder, Recorder, Trie, TrieDB, NibbleSlice};

use memory_db::{MemoryDB, HashKey};
use alloy_primitives::{Address, B256, U256};

pub use eip1186::{EIP1186Layout, VerifyError, process_node};
pub use types::KeccakHasher;
pub type StateProofsInput = BTreeMap<Address, Vec<Vec<u8>>>;
pub type StorageProofsInput = BTreeMap<Address, BTreeMap<U256, Vec<Vec<u8>>>>;

pub type EthereumLayout = EIP1186Layout<KeccakHasher>;
pub type EthereumTrieDB<'db,> = trie_db::TrieDBMut<'db, EthereumLayout>;
pub type EthereumMemoryDB =
    MemoryDB<<EIP1186Layout<KeccakHasher> as TrieLayout>::Hash, HashKey<<EIP1186Layout<KeccakHasher> as TrieLayout>::Hash>, DBValue>;

pub type AsHashDB = Box<dyn HashDB<KeccakHasher, Vec<u8>>>;


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







#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::hex as _hex;
    use hex_literal::hex;

    use alloy_primitives::{ Hasher};
    use alloy_rlp::{encode_list, Encodable};

    pub fn keccak256(x: &[u8]) -> [u8; 32] {
      let mut keccak_256: Keccak = Keccak::v256();
      let mut output = [0u8; 32];

      keccak_256.update(x);
      keccak_256.finalize(&mut output);

      output.into()
}
    pub fn rlp_encode_storage_value(value: &U256) -> Vec<u8> {
      let bytes = value.to_be_bytes_trimmed_vec().to_vec();
      let value = bytes.as_slice();

      rlp::encode(&value).to_vec()
    }

    pub fn rlp_encode_account(
      nonce: &u64,
      balance: &U256,
      storage_root: &B256,
      code_hash: &B256,
    ) -> Vec<u8> {
      let mut out = Vec::new();
      let enc: [&dyn Encodable; 4] = [nonce, balance, storage_root, code_hash];
      encode_list::<_, dyn Encodable>(&enc, &mut out);

      out
    }


    #[test]
    fn it_should_verify_account_proof() {
        let root: B256 =
            hex!["16a116384acc08d85d4e0304a4323304205d1f1eb49457bd15d83362d81a2d44"].into();
        let proofs = vec![
            hex!["f90191a04ee3e3e347aa43e222f335c125ce7a53483937255c7322169c496a3b4786d073a0db1a623f9f10dec7562e917d58eb725aa6f2c220449e39eeacf590f21b1726d48080a01a697e814758281972fcd13bc9707dbcd2f195986b05463d7b78426508445a04a0b5d7a91be5ee273cce27e2ad9a160d2faadd5a6ba518d384019b68728a4f62f4a044f530463c3b2dac3f15ee6d28344d825a3a40abf56c4a5c355c52eb5aa9b546a02824a2fe241af59fa35916eee31d3d37c00212976ab30c8db08e107fb0d127aca02e0d86c3befd177f574a20ac63804532889077e955320c9361cd10b7cc6f580980a069d23df84497ca940e02eaa9757fea8a1577f7daf96accd56ab8418c19b99e8fa00d36a5d7f054674fb48fa97bda72d0ce025405f86004a08a9082364238fd0e6980a01b7779e149cadf24d4ffb77ca7e11314b8db7097e4d70b2a173493153ca2e5a0a08d3664496b4b84236a2517d04dc89893572e47c31030138cef0d471ab7beeb2fa05ce88616c70a5d589938b1e2b2d51d024c7620597bf2681c2b71b22bdeda4ea080"].to_vec(),
            hex!["f85180a0e5df80f44e6c4599c36a09d1ec718be17203bc9cdbaf0db6113d7dea9c05e71ba0cd98600c2a36ee1ce4f34c87021d5861d625ab11abfaf0b9d15c4388052fa9c88080808080808080808080808080"].to_vec(),
            hex!["f869a020b4fa5fe5d393d6638e53df95194f06fa0d91e64b51aa8020078f16924f2303b846f8440180a00f460850d9716af3371839ff600d3d57ce12da330e95ac16f91da485fd8bd6c6a01e1706bdc2b9de10c4075b84a6181920bb73d94a161cb8044fc5d1c800030627"].to_vec()
        ];
        let key: [u8; 32] = keccak256(&hex!["3b2385025073625199d9edcf0612670f5b01fa6d"]);

        let nonce = 1u64;
        let balance = U256::from(0);
        let storage_root: B256 =
            "0x0f460850d9716af3371839ff600d3d57ce12da330e95ac16f91da485fd8bd6c6"
                .parse()
                .unwrap();
        let code_hash: B256 = "0x1e1706bdc2b9de10c4075b84a6181920bb73d94a161cb8044fc5d1c800030627"
            .parse()
            .unwrap();

        let value = rlp_encode_account(&nonce, &balance, &storage_root, &code_hash);

        verify_proof::<EthereumLayout>(&root, &proofs, &key, Some(&value)).unwrap();
    }

    #[test]
    fn it_should_verify_slot_0_storage_proof() {
        let root: B256 = "0x83eb79e0951b8edc05faa71c2c08ddc5ec9a957ceca902514d6b936302198742"
            .parse()
            .unwrap();
        let proofs: Vec<Vec<u8>> = vec![
          hex!["f8518080a0da83746f514f45db4d13a3cc40db52be81b39ea03b585fe72994970738dc33c38080808080808080a0f4984a11f61a2921456141df88de6e1a710d28681b91af794c5a721e47839cd78080808080"].to_vec(),
          hex!["f7a0390decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e56395949f27993a07acac99ef1503695235bd02151f028f"].to_vec(),
        ];
        let key: [u8; 32] = keccak256(B256::ZERO.as_slice());
        let storage_value = U256::from_be_bytes(hex![
            "0000000000000000000000009f27993a07acac99ef1503695235bd02151f028f"
        ]);

        let value = rlp_encode_storage_value(&storage_value);

        verify_proof::<EthereumLayout>(&root, &proofs, &key, Some(&value)).unwrap();
    }

    #[test]
    fn it_should_verify_slot_non_zero_storage_proof() {
        let root: B256 = "0x0f460850d9716af3371839ff600d3d57ce12da330e95ac16f91da485fd8bd6c6"
            .parse()
            .unwrap();
        let proofs: Vec<Vec<u8>> = vec![
          hex!["f8518080a043fe571ea299e8089ef0f3eca756a25d57d13960146985b2b7ff01c569eeaf408080808080808080a0f4984a11f61a2921456141df88de6e1a710d28681b91af794c5a721e47839cd78080808080"].to_vec(),
          hex!["e2a0310e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf601"].to_vec(),
        ];
        let key = keccak256(&hex![
            "0000000000000000000000000000000000000000000000000000000000000001"
        ]);

        let storage_value = U256::from_be_bytes(hex![
            "0000000000000000000000000000000000000000000000000000000000000001"
        ]);
        let value = rlp_encode_storage_value(&storage_value);
        verify_proof::<EthereumLayout>(&root, &proofs, &key, Some(&value)).unwrap();
    }

    #[test]
    #[ignore = "TODO: Verify null address"]
    fn it_should_verify_null_address() {
        let root: B256 =
            hex!["3e14b2562f5658e1830b998405079719fc49749f704d36947ec776edd219fbab"].into();
        let proofs = vec![
            hex!["f90171a08ccf977cd70e8ca253f97f8da412b725de8df232c11e6febea759503f6445898a0ab8cdb808c8303bb61fb48e276217be9770fa83ecf3f90f2234d558885f5abf18080a01a697e814758281972fcd13bc9707dbcd2f195986b05463d7b78426508445a04a0b5d7a91be5ee273cce27e2ad9a160d2faadd5a6ba518d384019b68728a4f62f4a0c2c799b60a0cd6acd42c1015512872e86c186bcf196e85061e76842f3b7cf86080a02e0d86c3befd177f574a20ac63804532889077e955320c9361cd10b7cc6f580980a06301b39b2ea8a44df8b0356120db64b788e71f52e1d7a6309d0d2e5b86fee7cba097513f6ff1aed75a2b79dc73c665ad65778e0e1af94080c84c5772e98a667a8880a01b7779e149cadf24d4ffb77ca7e11314b8db7097e4d70b2a173493153ca2e5a0a066a7662811491b3d352e969506b420d269e8b51a224f574b3b38b3463f43f009a05e7361cb5ce31a00aaaab9510a505efaf9e38e89d8801107ae5dae83157cacdd80"].to_vec(),
            hex!["f869a03b70e80538acdabd6137353b0f9d8d149f4dba91e8be2e7946e409bfdbe685b9b846f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"].to_vec(),
        ];
        let null_address: [u8; 32] = [0; 32];
        let key = keccak256(&null_address);

        let nonce = 0u64;
        let balance = U256::from(0);
        let storage_root: B256 =
            "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
                .parse()
                .unwrap();
        let code_hash: B256 = "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
            .parse()
            .unwrap();

        let value = rlp_encode_account(&nonce, &balance, &storage_root, &code_hash);
        println!("value: {:?}", _hex::encode(&value));

        verify_proof::<EthereumLayout>(&root, &proofs, &key, Some(&value)).unwrap();
    }

    #[test]
      fn it_should_generate_proof(){
        
      }
}
