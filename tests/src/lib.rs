use serde::de::DeserializeOwned;
use std::{fs::File, io::BufReader};

pub fn read_json_file<T: DeserializeOwned>(
    file_path: &str,
) -> Result<T, Box<dyn std::error::Error>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let u: T = serde_json::from_reader(reader)?;
    Ok(u)
}

#[cfg(test)]
mod tests {
    use crate::read_json_file;
    use drosera_core::primitives::{AccountInfoAll, TraceAccountState};
    use drosera_core::{alloy_primitives::hex, utils::str_to_revm_address};
    use drosera_prover::utils;
    use ethers::types::EIP1186ProofResponse;
    use std::collections::{BTreeMap, HashMap};

    use drosera_ethereum_proofs::verify_proofs;

    #[test]
    fn it_verifies_proofs() {
        let trace_data: HashMap<String, TraceAccountState> =
            read_json_file("./data/trace_data.json").expect("Failed to read trace data");

        // Build state tree from trace data for zkevm
        let mut state_tree = BTreeMap::new();
        trace_data.into_iter().for_each(|(address, state)| {
            let value: AccountInfoAll = state.into();
            let key = str_to_revm_address(address.as_str());
            state_tree.insert(key, value);
        });

        let proofs: EIP1186ProofResponse =
            read_json_file("./data/proof_data.json").expect("Failed to read proofs");

        let (state_proof_input, storage_proof_input) = utils::parse_proof_inputs(vec![proofs]);

        let state_root = verify_proofs(&state_tree, state_proof_input, storage_proof_input);

        assert_eq!(
            state_root,
            hex!["16a116384acc08d85d4e0304a4323304205d1f1eb49457bd15d83362d81a2d44"]
        );
    }
}
