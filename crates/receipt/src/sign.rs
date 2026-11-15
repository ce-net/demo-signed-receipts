//! `receipt.sign`: wrap any [`Cell`] so every call through it leaves a signed, hash-linked receipt.
//!
//! ```ignore
//! let log = NodeLog::new(node_identity);            // one per node, shared by the cells it runs
//! let mut put = WithReceipts::new(KvPut::default(), log.clone(), root_key);
//! let (result, receipt) = put.call(Call { caller, chain: &chain, input: b"k=v", ts });
//! ```

use std::cell::RefCell;
use std::rc::Rc;

use ce_net_proto::{ability_covers, encode_chain, verify_chain, Identity, NodeId, SignedCapability};

use crate::{sha256_hex, Receipt, ZERO};

/// A cell: a named function from input bytes to output bytes.
pub trait Cell {
    /// The cell's name; a caller needs the ability `cell:<name>`.
    fn name(&self) -> &str;
    /// Run one call.
    fn call(&mut self, input: &[u8]) -> Result<Vec<u8>, String>;
}

/// One node's receipt log: its signing key, the next sequence number, and the hash of its last receipt.
pub struct NodeLog {
    id: Identity,
    seq: u64,
    prev: String,
    /// Every receipt this node has signed, in order.
    pub receipts: Vec<Receipt>,
}

/// A node log shared by all the cells running on that node.
pub type Log = Rc<RefCell<NodeLog>>;

impl NodeLog {
    /// A fresh log for the node with this key.
    pub fn new(id: Identity) -> Log {
        Rc::new(RefCell::new(NodeLog { id, seq: 0, prev: ZERO.to_string(), receipts: Vec::new() }))
    }

    /// The node's public key, hex.
    pub fn node_hex(&self) -> String {
        self.id.node_id_hex()
    }

    /// Fill in node, seq and prev, sign, append, and return the receipt.
    fn append(&mut self, mut r: Receipt) -> Receipt {
        r.node = self.node_hex();
        r.seq = self.seq;
        r.prev = self.prev.clone();
        r.sig = hex::encode(self.id.sign(&r.signed_bytes()));
        self.seq += 1;
        self.prev = r.hash();
        self.receipts.push(r.clone());
        r
    }
}

/// One incoming call.
pub struct Call<'a> {
    /// The key making the call; it must hold the leaf of `chain`.
    pub caller: NodeId,
    /// The capability chain the caller presents, root first.
    pub chain: &'a [SignedCapability],
    /// The call's input bytes.
    pub input: &'a [u8],
    /// Unix seconds of the call (capabilities are checked at this time).
    pub ts: u64,
}

/// The middleware: a cell that checks capabilities and leaves a receipt for every call, refused or not.
pub struct WithReceipts<C: Cell> {
    inner: C,
    log: Log,
    root: NodeId,
}

fn one_line(s: &str) -> String {
    s.replace(['\n', '\r'], " ")
}

impl<C: Cell> WithReceipts<C> {
    /// Wrap `inner`, signing into `log`, trusting capability chains that root at `root`.
    pub fn new(inner: C, log: Log, root: NodeId) -> Self {
        WithReceipts { inner, log, root }
    }

    /// The wrapped cell's name.
    pub fn name(&self) -> &str {
        self.inner.name()
    }

    /// Authorize, run, sign. The receipt is returned with the result, and appended to the node log.
    pub fn call(&mut self, call: Call<'_>) -> (Result<Vec<u8>, String>, Receipt) {
        let needed = format!("cell:{}", self.inner.name());
        let authorized = verify_chain(call.chain, &self.root, call.ts, &|_, _| false).and_then(|v| {
            if v.holder != call.caller {
                Err("the chain is not held by the caller".to_string())
            } else if !v.abilities.iter().any(|g| ability_covers(g, &needed)) {
                Err(format!("does not grant {needed}"))
            } else {
                Ok(v)
            }
        });
        let (result, status) = match authorized {
            Err(e) => (Err(e.clone()), format!("refused: {}", one_line(&e))),
            Ok(_) => match self.inner.call(call.input) {
                Ok(out) => (Ok(out), "ok".to_string()),
                Err(e) => (Err(e.clone()), format!("error: {}", one_line(&e))),
            },
        };
        let leaf = call.chain.last().map(|c| hex::encode(c.id())).unwrap_or_else(|| ZERO.to_string());
        let receipt = self.log.borrow_mut().append(Receipt {
            node: String::new(),
            seq: 0,
            prev: String::new(),
            ts: call.ts,
            cell: self.inner.name().to_string(),
            caller: hex::encode(call.caller),
            cap: leaf,
            input: sha256_hex(call.input),
            output: sha256_hex(result.as_deref().unwrap_or(b"")),
            status,
            chain: encode_chain(call.chain),
            sig: String::new(),
        });
        (result, receipt)
    }
}
