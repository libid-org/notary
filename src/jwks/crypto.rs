use alloy_sol_types::SolValue;
use libid_crypto::keccak256;

/// Digest verified by `JwksOracle._notaryDigest`.
pub fn notary_digest(
    domain_hash: [u8; 32],
    client_random: [u8; 32],
    server_random: [u8; 32],
    server_ephemeral_key: &[u8],
    transcript_root: [u8; 32],
    timestamp: u64,
) -> [u8; 32] {
    let encoded = (
        alloy_primitives::B256::from(domain_hash),
        alloy_primitives::B256::from(client_random),
        alloy_primitives::B256::from(server_random),
        alloy_primitives::B256::from(keccak256(server_ephemeral_key)),
        alloy_primitives::B256::from(transcript_root),
        alloy_primitives::U256::from(timestamp),
    )
        .abi_encode_params();
    keccak256(&encoded)
}

pub(super) fn double_hash_leaf(prefix: &str, value: &[u8]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(prefix.len() + value.len());
    bytes.extend_from_slice(prefix.as_bytes());
    bytes.extend_from_slice(value);
    keccak256(&keccak256(&bytes))
}

fn hash_pair(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let (left, right) = if a < b { (a, b) } else { (b, a) };
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&left);
    bytes[32..].copy_from_slice(&right);
    keccak256(&bytes)
}

pub(super) fn build_merkle_tree(leaves: &[[u8; 32]]) -> [u8; 32] {
    let mut layer = leaves.to_vec();
    while layer.len() > 1 {
        layer = layer
            .chunks(2)
            .map(|pair| match pair {
                [a, b] => hash_pair(*a, *b),
                [a] => *a,
                _ => unreachable!(),
            })
            .collect();
    }
    layer.first().copied().unwrap_or_default()
}

pub(super) fn merkle_proof(leaves: &[[u8; 32]], mut index: usize) -> Vec<[u8; 32]> {
    assert!(index < leaves.len(), "index out of range");
    let mut proof = Vec::new();
    let mut layer = leaves.to_vec();
    while layer.len() > 1 {
        let sibling = if index.is_multiple_of(2) {
            layer.get(index + 1)
        } else {
            layer.get(index - 1)
        };
        proof.extend(sibling);
        layer = layer
            .chunks(2)
            .map(|pair| match pair {
                [a, b] => hash_pair(*a, *b),
                [a] => *a,
                _ => unreachable!(),
            })
            .collect();
        index /= 2;
    }
    proof
}

#[cfg(test)]
pub(super) fn merkle_verify(proof: &[[u8; 32]], root: [u8; 32], leaf: [u8; 32]) -> bool {
    proof
        .iter()
        .fold(leaf, |node, sibling| hash_pair(node, *sibling))
        == root
}
