// Binary Merkle tree over SHA-256 content hashes.
//
// Tree construction:
//   - Leaves: sha256(content_hash_hex_bytes)
//   - Internal nodes: sha256(left_child_bytes || right_child_bytes)
//   - Odd number of leaves: last leaf is duplicated.
//
// All hashes are stored and exposed as lowercase hex strings.

use sha2::{Digest, Sha256};

/// A single sibling entry in a Merkle inclusion proof.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProofNode {
    /// "left" or "right" — which side this sibling is on.
    pub side: String,
    /// SHA-256 hash of the sibling node as lowercase hex.
    pub hash: String,
}

/// Inclusion proof for one leaf in the tree.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MerkleProof {
    /// Zero-based index of the proven leaf.
    pub leaf_index: usize,
    /// Sibling path from leaf up to (but not including) the root.
    pub path: Vec<ProofNode>,
}

/// A fully-built binary Merkle tree stored as layers.
/// `layers[0]` = leaf layer, `layers[last]` = root (single element).
pub struct MerkleTree {
    /// Each layer is a list of hex-encoded SHA-256 hashes.
    layers: Vec<Vec<String>>,
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn combine(left: &str, right: &str) -> String {
    let l = hex::decode(left).unwrap_or_default();
    let r = hex::decode(right).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&l);
    hasher.update(&r);
    hex::encode(hasher.finalize())
}

/// Build a Merkle tree from a slice of content-hash hex strings.
/// Returns an empty tree (no root) if `hashes` is empty.
pub fn build_merkle_tree(hashes: &[&str]) -> MerkleTree {
    if hashes.is_empty() {
        return MerkleTree { layers: vec![] };
    }

    // Leaf layer: sha256(content_hash_bytes).
    let leaves: Vec<String> = hashes
        .iter()
        .map(|h| sha256_hex(h.as_bytes()))
        .collect();

    let mut layers: Vec<Vec<String>> = vec![leaves];

    while layers.last().map_or(0, |l| l.len()) > 1 {
        let current = layers.last().unwrap();
        let mut next: Vec<String> = Vec::with_capacity((current.len() + 1) / 2);
        let mut i = 0;
        while i < current.len() {
            let left = &current[i];
            let right = if i + 1 < current.len() {
                &current[i + 1]
            } else {
                // Duplicate the last leaf for odd-length layers.
                left
            };
            next.push(combine(left, right));
            i += 2;
        }
        layers.push(next);
    }

    MerkleTree { layers }
}

/// Returns the Merkle root as a lowercase hex string, or an empty string for an empty tree.
pub fn root(tree: &MerkleTree) -> String {
    tree.layers
        .last()
        .and_then(|l| l.first())
        .cloned()
        .unwrap_or_default()
}

/// Generates an inclusion proof for the leaf at `leaf_idx`.
/// Panics if the tree is empty or `leaf_idx` is out of range.
pub fn proof(tree: &MerkleTree, leaf_idx: usize) -> MerkleProof {
    assert!(!tree.layers.is_empty(), "cannot generate proof on empty tree");
    let leaf_count = tree.layers[0].len();
    assert!(leaf_idx < leaf_count, "leaf_idx out of range");

    let mut path: Vec<ProofNode> = Vec::new();
    let mut idx = leaf_idx;

    // Walk up from the leaf layer to the root layer (exclusive — root has no sibling).
    for layer in &tree.layers[..tree.layers.len().saturating_sub(1)] {
        let sibling_idx = if idx % 2 == 0 {
            // idx is left child; sibling is to the right (or duplicate of idx if it doesn't exist)
            (idx + 1).min(layer.len() - 1)
        } else {
            // idx is right child; sibling is to the left
            idx - 1
        };
        let side = if idx % 2 == 0 { "right" } else { "left" };
        path.push(ProofNode {
            side: side.to_string(),
            hash: layer[sibling_idx].clone(),
        });
        idx /= 2;
    }

    MerkleProof { leaf_index: leaf_idx, path }
}

/// Verifies that `leaf_content_hash` (a raw content_hash string, not yet SHA-256'd) is
/// included in the Merkle tree whose root is `root_hex`.
///
/// Returns `true` if the proof is valid.
pub fn verify_proof(root_hex: &str, leaf_content_hash: &str, merkle_proof: &MerkleProof) -> bool {
    // Re-derive the leaf hash the same way the builder did.
    let mut current = sha256_hex(leaf_content_hash.as_bytes());

    for node in &merkle_proof.path {
        current = match node.side.as_str() {
            "left" => combine(&node.hash, &current),
            "right" => combine(&current, &node.hash),
            _ => return false,
        };
    }

    current == root_hex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_leaf() {
        let tree = build_merkle_tree(&["abc123"]);
        let r = root(&tree);
        assert!(!r.is_empty());
        let p = proof(&tree, 0);
        assert!(verify_proof(&r, "abc123", &p));
    }

    #[test]
    fn test_even_leaves() {
        let hashes = ["a", "b", "c", "d"];
        let tree = build_merkle_tree(&hashes);
        let r = root(&tree);
        for (i, h) in hashes.iter().enumerate() {
            let p = proof(&tree, i);
            assert!(verify_proof(&r, h, &p), "proof failed for leaf {}", i);
        }
    }

    #[test]
    fn test_odd_leaves() {
        let hashes = ["a", "b", "c"];
        let tree = build_merkle_tree(&hashes);
        let r = root(&tree);
        for (i, h) in hashes.iter().enumerate() {
            let p = proof(&tree, i);
            assert!(verify_proof(&r, h, &p), "proof failed for leaf {}", i);
        }
    }

    #[test]
    fn test_invalid_proof() {
        let tree = build_merkle_tree(&["real_hash"]);
        let r = root(&tree);
        let p = proof(&tree, 0);
        assert!(!verify_proof(&r, "wrong_hash", &p));
    }

    #[test]
    fn test_empty_tree() {
        let tree = build_merkle_tree(&[]);
        assert_eq!(root(&tree), "");
    }
}
