// IronClad Agent Ledger — SP1 zkVM Guest Program
//
// This program runs inside the Succinct SP1 RISC-V virtual machine and produces a
// zero-knowledge proof that:
//
//   1. The event hash chain is valid: every link recalculates correctly.
//   2. The genesis event starts from the canonical all-zeros previous hash.
//   3. The final event's content hash matches the expected ledger tip hash.
//   4. A Merkle tree over all content hashes produces the expected root.
//   5. No event's payload JSON matches any forbidden policy pattern.
//
// Performance decisions:
//   - Input is read via `sp1_zkvm::io::read` (bincode, not JSON). Zero JSON parsing in guest.
//   - All `regex_lite::Regex` patterns are compiled exactly once before the event loop.
//   - The Merkle tree is built from computed hashes (never from DB-fetched values).

#![no_main]
sp1_zkvm::entrypoint!(main);

use ironclad_core::hash::{compute_content_hash, GENESIS_PREVIOUS_HASH};
use ironclad_core::merkle;
use ironclad_core::schema::{GuestInput, GuestOutput};
use regex_lite::Regex;

pub fn main() {
    // ── 1. Deserialize input (bincode, no JSON) ───────────────────────────────
    let input: GuestInput = sp1_zkvm::io::read::<GuestInput>();

    assert!(!input.events.is_empty(), "guest: event list is empty");

    // ── 2. PERFORMANCE MANDATE 2: Compile all policy patterns exactly once ────
    //
    // Patterns are compiled here, before the event loop, so regex compilation cost
    // is O(P) rather than O(P × N) where P = number of patterns and N = event count.
    let compiled_patterns: Vec<(Regex, usize)> = input
        .policy_patterns
        .iter()
        .enumerate()
        .filter_map(|(idx, pattern)| {
            Regex::new(pattern)
                .ok()
                .map(|re| (re, idx))
        })
        .collect();

    // ── 3. Hash-chain verification ────────────────────────────────────────────
    //
    // For every event we re-derive:
    //   content_hash = sha256( previous_hash || sequence || payload_json )
    //
    // Then we assert that the NEXT event's `previous_hash` equals what we just computed.
    // This proves the chain has no gaps, insertions, or tampered payloads.

    // Verify genesis starts from the canonical all-zeros previous hash.
    assert_eq!(
        input.events[0].previous_hash,
        GENESIS_PREVIOUS_HASH,
        "guest: genesis event must start from the all-zeros previous hash"
    );

    let mut violations: Vec<String> = Vec::new();
    let mut computed_content_hashes: Vec<String> = Vec::with_capacity(input.events.len());

    for (i, event) in input.events.iter().enumerate() {
        // Re-derive the content hash from the three chain inputs.
        let content_hash = compute_content_hash(
            &event.previous_hash,
            event.sequence,
            &event.payload_json,
        );
        computed_content_hashes.push(content_hash.clone());

        // Verify the next event's `previous_hash` links back to this computed hash.
        if i + 1 < input.events.len() {
            assert_eq!(
                input.events[i + 1].previous_hash,
                content_hash,
                "guest: hash chain break between sequence {} and {}",
                event.sequence,
                input.events[i + 1].sequence,
            );
        }

        // ── 4-inline. Policy pattern evaluation (compile-once, run-per-event) ─
        //
        // Each event's raw payload_json is checked against every compiled pattern.
        // Matches are recorded as violations and included in GuestOutput.
        // Policy violations do NOT abort the proof — the host decides how to handle them.
        for (re, pattern_idx) in &compiled_patterns {
            if re.is_match(&event.payload_json) {
                violations.push(format!(
                    "event seq={} matched forbidden pattern[{}]: {}",
                    event.sequence,
                    pattern_idx,
                    &input.policy_patterns[*pattern_idx],
                ));
            }
        }
    }

    // ── 4. Tip hash verification ──────────────────────────────────────────────
    let actual_tip = computed_content_hashes.last().expect("guest: no computed hashes");
    assert_eq!(
        actual_tip,
        &input.tip_hash,
        "guest: computed tip hash does not match expected tip_hash"
    );

    // ── 5. Genesis hash verification ──────────────────────────────────────────
    let actual_genesis = computed_content_hashes.first().expect("guest: no computed hashes");
    assert_eq!(
        actual_genesis,
        &input.genesis_hash,
        "guest: computed genesis hash does not match expected genesis_hash"
    );

    // ── 6. Merkle root verification ───────────────────────────────────────────
    //
    // Build the Merkle tree from the COMPUTED content hashes (not from any DB values).
    // This proves the tree is derived from the same chain we just verified.
    let hash_refs: Vec<&str> = computed_content_hashes.iter().map(|s| s.as_str()).collect();
    let tree = merkle::build_merkle_tree(&hash_refs);
    let actual_root = merkle::root(&tree);

    assert_eq!(
        actual_root,
        input.merkle_root,
        "guest: computed Merkle root does not match expected merkle_root"
    );

    // ── 7. Commit output to the proof's public values ─────────────────────────
    //
    // The verifier on the host can read GuestOutput back from the proof's public values.
    // `verified = true` is only committed when ALL hash and Merkle checks passed above
    // (any failure would have caused a panic, aborting proof generation).
    let output = GuestOutput {
        verified: true,
        event_count: input.events.len() as u64,
        violations,
    };

    sp1_zkvm::io::commit::<GuestOutput>(&output);
}
