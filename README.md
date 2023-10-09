# ethereum-proofs

This crate provides a Rust implementation of the [EIP-1186](https://eips.ethereum.org/EIPS/eip-1186) state and storage proofs. It can be used to verify inclusion of state data against a set of provided proofs.

## Usage

```rust
let mut state_tree: BTreeMap<H160, MemoryAccount> = ...
        
let proofs: EIP1186ProofResponse = ...

let (state_proof_input, storage_proof_input) = 
  drosera_ethereum_proofs::utils::parse_proof_inputs(vec![proofs]);

let state_root: H256 = verify_proofs(&state_tree, state_proof_input, storage_proof_input);
```

## Feature flags

The following feature flags are present in one or more of the crates listed above:

| Feature  | Target(s)         | Implies    | Description                           |
| -------- | ----------------- | ---------- | ------------------------------------------------------------------------------------|
| `default`| all               |   `std`    | Default features enabled              | 
| `std`    | all               |            | Enables `std` support.                |
