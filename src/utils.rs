use crate::rstd::vec::Vec;
use alloy_primitives::U256;
use primitive_types::{H160, H256};
use tiny_keccak::{Hasher, Keccak};

pub fn calculate_storage_key(address: &H160, slot_index: &H256) -> H256 {
    if *slot_index == H256::zero() {
        // if 0x0 slot index, return 0x0
        return H256::zero();
    }
    let padded_address: H256 = H256::from(*address);

    // Concatenate the address and slot index
    let mut path = Vec::new();
    path.extend_from_slice(&padded_address.to_fixed_bytes());
    path.extend_from_slice(&slot_index.to_fixed_bytes());

    H256::from(keccak256(&path))
}

pub fn rlp_encode_storage_value(value: &U256) -> Vec<u8> {
    let bytes = value.to_be_bytes_trimmed_vec().to_vec();
    let value = bytes.as_slice();

    rlp::encode(&value).to_vec()
}

pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];

    hasher.update(bytes);
    hasher.finalize(&mut output);

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_should_calculate_storage_path() {
        let address: H160 = "0x30dc1376aa206a26aca073a8367edbe3e34d511c"
            .parse()
            .unwrap();
        let slot_index: H256 = "0x0000000000000000000000000000000000000000000000000000000000000001"
            .parse()
            .unwrap();

        let storage_path = calculate_storage_key(&address, &slot_index);
        assert_eq!(
            storage_path,
            "0xeaccf00f4a3fbd973a2f5419d670f736a573a4c8ffafb434a67927c98d436fb1"
                .parse()
                .unwrap()
        )
    }

    #[test]
    fn it_rlp_encodes_storage_value() {
        let value: U256 = "0x0000000000000000000000009f27993a07acac99ef1503695235bd02151f028f"
            .parse()
            .unwrap();

        let storage_value = rlp_encode_storage_value(&value);
        assert_eq!(
            storage_value,
            [
                148, 159, 39, 153, 58, 7, 172, 172, 153, 239, 21, 3, 105, 82, 53, 189, 2, 21, 31,
                2, 143
            ]
        );
    }
}
