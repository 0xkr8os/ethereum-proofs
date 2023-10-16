// Copyright 2015-2020 Parity Technologies (UK) Ltd.
// This file is part of OpenEthereum.

// OpenEthereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// OpenEthereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with OpenEthereum.  If not, see <http://www.gnu.org/licenses/>.

//! `NodeCodec` implementation for Rlp

use crate::rstd::vec::Vec;
use core::{borrow::Borrow, marker::PhantomData, ops::Range};
use hash_db::Hasher;

#[cfg(feature = "std")]
mod rstd {
    pub use std::error::Error;
}

use rlp::{DecoderError, Prototype, Rlp, RlpStream};

use trie_db::{
    node::{NibbleSlicePlan, NodeHandlePlan, NodePlan, Value, ValuePlan},
    ChildReference, NodeCodec,
};
use log::trace;

/// Concrete implementation of a `NodeCodec` with Rlp encoding, generic over the `Hasher`
#[derive(Default, Clone)]
pub struct RlpNodeCodec<H>(PhantomData<H>);

// rlp of empty string
pub const NULL_NODE: [u8; 1] = [0x80];
pub const HASHED_NULL_NODE: [u8; 32] = [
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
];

impl<H: Hasher> NodeCodec for RlpNodeCodec<H>
{
    type Error = DecoderError;
    type HashOut = H::Out;

    fn hashed_null_node() -> H::Out {
        H::hash(<Self as NodeCodec>::empty_node())
    }

    fn decode_plan(data: &[u8]) -> Result<NodePlan, Self::Error> {
      if data == &HASHED_NULL_NODE {
        // early return if this is == keccak(rlp(null)), aka empty trie root
        // source: https://ethereum.github.io/execution-specs/diffs/frontier_homestead/trie/index.html#empty-trie-root
        return Ok(NodePlan::Empty);
      }

    let r = Rlp::new(data);
   
    match r.prototype()? {
        // either leaf or extension - decode first item with NibbleSlice::???
        // and use is_leaf return to figure out which.
        // if leaf, second item is a value (is_data())
        // if extension, second item is a node (either SHA3 to be looked up and
        // fed back into this function or inline RLP which can be fed back into this function).
        Prototype::List(2) => {
            let (rlp, offset) = r.at_with_offset(0)?;
            let (data, i) = (rlp.data()?, rlp.payload_info()?);
            trace!("Decoding rlp partial: {:?}", data);
            let node_plan = match (
                NibbleSlicePlan::new(
                    (offset + i.header_len)..(offset + i.header_len + i.value_len),
                    if data[0] & 16 == 16 { 1 } else { 2 },
                ),
                data[0] & 32 == 32,
            ) {
                (slice, true) => Ok(NodePlan::Leaf {
                    partial: slice,
                    value: {
                        let (item, offset) = r.at_with_offset(1)?;
                        let i = item.payload_info()?;
                        ValuePlan::Inline(
                            (offset + i.header_len)..(offset + i.header_len + i.value_len),
                        )
                    },
                }),
                (slice, false) => Ok(NodePlan::Extension {
                    partial: slice,
                    child: {
                        let (item, offset) = r.at_with_offset(1)?;
                        let i = item.payload_info()?;
                        NodeHandlePlan::Hash(
                            (offset + i.header_len)..(offset + i.header_len + i.value_len),
                        )
                    },
                }),
            };
            trace!("Decoded leaf or extension node: {:?}", node_plan);
            node_plan
        }
        // branch - first 16 are nodes, 17th is a value (or empty).
        Prototype::List(17) => {
            trace!("Decoding branch node");
            let mut nodes = [
                None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None,
            ];

            for index in 0..16 {
                let (item, offset) = r.at_with_offset(index)?;
                let i = item.payload_info()?;
                if item.is_empty() {
                    nodes[index] = None;
                } else {
                    nodes[index] = Some(NodeHandlePlan::Hash(
                        (offset + i.header_len)..(offset + i.header_len + i.value_len),
                    ));
                }
            }

            Ok(NodePlan::Branch {
                children: nodes,
                value: {
                    let (item, offset) = r.at_with_offset(16)?;
                    let i = item.payload_info()?;
                    if item.is_empty() {
                        None
                    } else {
                        Some(ValuePlan::Inline(
                            (offset + i.header_len)..(offset + i.header_len + i.value_len),
                        ))
                    }
                },
            })
        }
        // an empty branch index.
        Prototype::Data(0) => Ok(NodePlan::Empty),
        // something went wrong.
        _ => Err(DecoderError::Custom("Rlp is not valid.")),
      }
    }
  
    fn is_empty_node(data: &[u8]) -> bool {
        data == <Self as NodeCodec>::empty_node()
    }

    fn empty_node() -> &'static [u8] {
        &NULL_NODE
    }


  fn leaf_node(
      partial: impl Iterator<Item = u8>,
      _number_nibble: usize,
      value: Value,
  ) -> Vec<u8> {
      let mut stream = RlpStream::new_list(2);
      let partial = partial.collect::<Vec<_>>();
      trace!("Encoding leaf node, partial: {:?}, nibble: {:?}", partial, _number_nibble);
      let encoded_partial = compact_encode_leaf(partial);
      stream.append(&encoded_partial);
  
      let value = match value {
          Value::Node(bytes) => bytes,
          Value::Inline(bytes) => bytes,
      };
      stream.append(&value);
      stream.out().to_vec()
  }
  
  fn extension_node(
      partial: impl Iterator<Item = u8>,
      _number_nibble: usize,
      child_ref: ChildReference<Self::HashOut>,
  ) -> Vec<u8> {
      let mut stream = RlpStream::new_list(2);
      let partial = partial.collect::<Vec<_>>();
      trace!("Encoding extension node, partial: {:?}, nibble: {:?}", partial, _number_nibble);
  
      let key = compact_encode_extension(partial);
      stream.append(&key);
  
      match child_ref {
          ChildReference::Hash(h) => stream.append(&h.as_ref()),
          ChildReference::Inline(inline_data, len) => {
              let bytes = &AsRef::<[u8]>::as_ref(&inline_data)[..len];
              stream.append_raw(bytes, 1)
          }
      };
      stream.out().to_vec()
  }

    fn branch_node(
        children: impl Iterator<Item = impl Borrow<Option<ChildReference<Self::HashOut>>>>,
        value: Option<Value>,
    ) -> Vec<u8> {
        trace!("Encoding branch node");
        let mut stream = RlpStream::new_list(17);
        for child_ref in children {
            match child_ref.borrow() {
                Some(c) => match c {
                    ChildReference::Hash(h) => stream.append(&h.as_ref()),
                    ChildReference::Inline(inline_data, len) => {
                        let bytes = &inline_data.as_ref()[..*len];
                        stream.append_raw(bytes, 1)
                    }
                },
                None => stream.append_empty_data(),
            };
        }
        if let Some(value) = value {
            let value = match value {
                Value::Node(bytes) => bytes,
                Value::Inline(bytes) => bytes,
            };
            stream.append(&value);
        } else {
            stream.append_empty_data();
        }
        stream.out().to_vec()
    }

    fn branch_node_nibbled(
        _partial: impl Iterator<Item = u8>,
        _number_nibble: usize,
        _children: impl Iterator<Item = impl Borrow<Option<ChildReference<Self::HashOut>>>>,
        _value: Option<Value>,
    ) -> Vec<u8> {
        unimplemented!("Ethereum branch nodes do not have partial key; qed")
    }
}

fn compact_encode_leaf(partial: Vec<u8>) -> Vec<u8> {
  let mut encoded = Vec::new();

    if partial.len() % 2 == 1 {
        encoded.push(0x3 * 16 + partial[0]); // Prefix with 0x3 and take the first nibble
        encoded.extend_from_slice(&partial[1..]);
    } else {
        encoded.push(0x2 * 16); // Prefix with 0x2
        encoded.extend_from_slice(&partial);
    }

    encoded
}

fn compact_encode_extension(partial: Vec<u8>) -> Vec<u8> {
  let mut encoded = Vec::new();

    if partial.len() % 2 == 1 {
        encoded.push(0x1 * 16 + partial[0]); // Prefix with 0x1 and take the first nibble
        encoded.extend_from_slice(&partial[1..]);
    } else {
        encoded.push(0x0 * 16); // Prefix with 0x0
        encoded.extend_from_slice(&partial);
    }

    encoded
}

fn decode_compact(encoded: &[u8]) -> Vec<u8> {
  // Decode the compact encoding for the Ethereum MPT.
  let is_odd = encoded[0] & 0x01 == 0x01;
  let is_leaf = encoded[0] & 0x02 == 0x02;

  let mut nibbles = vec![];
  if is_odd {
      nibbles.push(encoded[0] >> 2);
  }

  for byte in &encoded[1..] {
      nibbles.push(byte >> 4);
      nibbles.push(byte & 0x0F);
  }

  if is_leaf {
      nibbles.insert(0, 0x02);
  } else { 
      nibbles.insert(0, 0x00);
  }

  nibbles
}

fn encode_compact(decoded: &[u8], is_leaf: bool) -> Vec<u8> {
  // Encode the compact encoding for the Ethereum MPT.
  let mut encoded = vec![];
  let first_nibble = if is_leaf { 0x02 } else { 0x00 } | if decoded.len() % 2 == 1 { 0x01 } else { 0x00 };
  encoded.push(first_nibble);

  for i in (0..decoded.len()).step_by(2) {
      let byte = (decoded[i] << 4) | decoded[i + 1];
      encoded.push(byte);
  }

  encoded
}
