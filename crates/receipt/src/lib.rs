//! Every call leaves a receipt.
//!
//! - [`sign`] is `receipt.sign`: middleware any cell can add. It checks the caller's ce-net capability
//!   chain, runs the call, and appends a receipt signed by the node that ran it. Each receipt names the
//!   hash of the previous receipt from the same node, so a node's receipts form a hash-linked chain.
//! - [`verify`] is `receipt.verify`: checks a file of receipts offline. The one-file Python verifier in
//!   ce-net-capability-verify (`verify.py`) runs the same checks and prints the same report.
//!
//! A receipt is one JSON object per line. What the node signs is [`Receipt::signed_bytes`]:
//!
//! ```text
//! ce-receipt/1
//! node=<hex32>  seq=<u64>  prev=<hex32>  ts=<u64>  cell=<name>  caller=<hex32>
//! cap=<hex32>   input=<hex32>  output=<hex32>  status=<ok | refused: why | error: why>
//! ```
//!
//! one `key=value` line per field in that order, each ending in `\n`. `prev` is the SHA-256 of the
//! previous receipt's signed bytes from the same node (all zeros for seq 0), `cap` is the id of the
//! leaf of the capability chain the caller presented (`chain`, hex), and `input`/`output` are SHA-256
//! of the call's bytes. The signature is pure Ed25519 by `node` over the signed bytes.

pub mod sign;
pub mod verify;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The signed-bytes domain line.
pub const DOMAIN: &str = "ce-receipt/1";
/// `prev` of a node's first receipt.
pub const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// One call's receipt, as it appears on a line of `receipts.jsonl`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub node: String,
    pub seq: u64,
    pub prev: String,
    pub ts: u64,
    pub cell: String,
    pub caller: String,
    pub cap: String,
    pub input: String,
    pub output: String,
    pub status: String,
    /// The capability chain the caller presented (ce-net-proto token, hex).
    pub chain: String,
    pub sig: String,
}

impl Receipt {
    /// The exact bytes the node signs and the next receipt's `prev` hashes.
    pub fn signed_bytes(&self) -> Vec<u8> {
        let fields: [(&str, String); 10] = [
            ("node", self.node.clone()),
            ("seq", self.seq.to_string()),
            ("prev", self.prev.clone()),
            ("ts", self.ts.to_string()),
            ("cell", self.cell.clone()),
            ("caller", self.caller.clone()),
            ("cap", self.cap.clone()),
            ("input", self.input.clone()),
            ("output", self.output.clone()),
            ("status", self.status.clone()),
        ];
        let mut s = format!("{DOMAIN}\n");
        for (k, v) in fields {
            s.push_str(&format!("{k}={v}\n"));
        }
        s.into_bytes()
    }

    /// SHA-256 of [`Self::signed_bytes`], hex: what the next receipt on this node names as `prev`.
    pub fn hash(&self) -> String {
        hex::encode(Sha256::digest(self.signed_bytes()))
    }

    /// The receipt as one JSON line (no trailing newline).
    pub fn to_line(&self) -> String {
        serde_json::to_string(self).expect("a receipt always serializes")
    }
}

/// SHA-256 hex of some bytes.
pub fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
