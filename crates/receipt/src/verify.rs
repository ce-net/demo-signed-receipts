//! `receipt.verify`: check a file of receipts offline. Same checks and same report as `verify.py`.
//!
//! Each receipt on its own: every field present and well formed, the node's Ed25519 signature over
//! the signed bytes, and (for `ok` calls) the capability chain: it decodes, its leaf id is `cap`, it is
//! valid at `ts` and roots at the trusted root, its holder is `caller`, and it grants `cell:<cell>`.
//! Then each node's chain: seq starts at 0 and counts up by one, and every `prev` is the hash of the
//! previous receipt from that node. A dropped receipt shows as a gap, an edited one as a broken link.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use ce_net_proto::{ability_covers, decode_chain, identity, verify_chain, NodeId};
use serde_json::Value;

use crate::{Receipt, ZERO};

const FIELDS: [&str; 10] = ["node", "seq", "prev", "ts", "cell", "caller", "cap", "input", "output", "status"];

fn is_hex(v: Option<&Value>, n: usize) -> bool {
    matches!(v, Some(Value::String(s)) if s.len() == n && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)))
}

fn short(s: &str) -> &str {
    &s[..s.len().min(8)]
}

fn hex32(s: &str) -> NodeId {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).expect("checked hex");
    out
}

/// Parse one receipt line.
pub fn parse_line(line: &str) -> Result<Receipt, String> {
    serde_json::from_str(line).map_err(|e| format!("not a receipt ({e})"))
}

/// Verify one receipt on its own. Returns the hex root of its capability chain (`None` for a receipt
/// of a refused or failed call), or why it is not valid.
pub fn check_receipt(
    v: &Value,
    root: Option<&str>,
    nodes: Option<&BTreeSet<String>>,
) -> Result<Option<String>, String> {
    for k in FIELDS.iter().chain(["chain", "sig"].iter()) {
        if v.get(k).is_none() {
            return Err(format!("missing field {k}"));
        }
    }
    for k in ["node", "prev", "caller", "cap", "input", "output"] {
        if !is_hex(v.get(k), 64) {
            return Err(format!("{k} is not 32 bytes of lowercase hex"));
        }
    }
    for k in ["seq", "ts"] {
        if v[k].as_u64().is_none() {
            return Err(format!("{k} is not a non-negative integer"));
        }
    }
    for k in ["cell", "status"] {
        match v[k].as_str() {
            Some(s) if !s.is_empty() && !s.contains('\n') => {}
            _ => return Err(format!("{k} is not a one-line string")),
        }
    }
    if !is_hex(v.get("sig"), 128) {
        return Err("sig is not 64 bytes of lowercase hex".into());
    }
    let r: Receipt = serde_json::from_value(v.clone()).map_err(|e| format!("not a receipt ({e})"))?;
    if let Some(nodes) = nodes {
        if !nodes.contains(&r.node) {
            return Err(format!("signed by node {}, which is not a pinned node", short(&r.node)));
        }
    }
    let mut sig = [0u8; 64];
    hex::decode_to_slice(&r.sig, &mut sig).expect("checked hex");
    if identity::verify(&hex32(&r.node), &r.signed_bytes(), &sig).is_err() {
        return Err(format!("invalid signature: these fields are not what node {} signed", short(&r.node)));
    }
    if r.status != "ok" {
        return Ok(None);
    }
    let chain = decode_chain(&r.chain).map_err(|e| format!("capability chain does not decode ({e})"))?;
    let Some(leaf) = chain.last() else {
        return Err("capability: no capability presented".into());
    };
    if hex::encode(leaf.id()) != r.cap {
        return Err("cap is not the id of the chain's leaf".into());
    }
    let trusted = root.map(hex32).unwrap_or(chain[0].cap.issuer);
    let ok = verify_chain(&chain, &trusted, r.ts, &|_, _| false).map_err(|e| format!("capability: {e}"))?;
    if hex::encode(ok.holder) != r.caller {
        return Err("capability: the chain is not held by the caller".into());
    }
    let needed = format!("cell:{}", r.cell);
    if !ok.abilities.iter().any(|g| ability_covers(g, &needed)) {
        return Err(format!("capability: does not grant {needed}"));
    }
    Ok(Some(hex::encode(chain[0].cap.issuer)))
}

#[derive(Default)]
struct NodeStats {
    cells: BTreeSet<String>,
    receipts: usize,
    valid: usize,
    first: u64,
    last: u64,
    breaks: usize,
}

fn field_str(v: &Value, k: &str) -> String {
    match v.get(k) {
        None => "?".into(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

/// Verify the lines of a receipts file. Returns the report (one string per line) and whether it is all valid.
pub fn verify_receipts(lines: &[&str], root: Option<&str>, nodes: Option<&BTreeSet<String>>) -> (Vec<String>, bool) {
    let mut bad: BTreeMap<usize, String> = BTreeMap::new();
    let mut roots: BTreeSet<String> = BTreeSet::new();
    let mut per: BTreeMap<String, NodeStats> = BTreeMap::new();
    let mut last: HashMap<String, (usize, u64, Option<String>)> = HashMap::new();
    let mut breaks: Vec<(String, String)> = Vec::new();
    let mut total = 0usize;
    for (i, text) in lines.iter().enumerate() {
        let ln = i + 1;
        if text.trim().is_empty() {
            continue;
        }
        total += 1;
        let v: Value = match serde_json::from_str(text) {
            Ok(v @ Value::Object(_)) => v,
            Ok(_) => {
                bad.insert(ln, format!("line {ln}: not a receipt (not a JSON object)"));
                continue;
            }
            Err(e) => {
                bad.insert(ln, format!("line {ln}: not a receipt ({e})"));
                continue;
            }
        };
        let node = field_str(&v, "node");
        let label = format!("line {ln} ({} seq {} on node {})", field_str(&v, "cell"), field_str(&v, "seq"), short(&node));
        match check_receipt(&v, root, nodes) {
            Ok(Some(r)) => {
                roots.insert(r);
            }
            Ok(None) => {}
            Err(e) => {
                bad.insert(ln, format!("{label}: {e}"));
            }
        }
        let (Some(seq), true, true) = (v["seq"].as_u64(), is_hex(v.get("node"), 64), is_hex(v.get("prev"), 64)) else {
            continue;
        };
        let prev_field = v["prev"].as_str().unwrap_or_default().to_string();
        let s = per.entry(node.clone()).or_insert_with(|| NodeStats { first: seq, ..Default::default() });
        s.cells.insert(field_str(&v, "cell"));
        s.receipts += 1;
        s.valid += usize::from(!bad.contains_key(&ln));
        s.last = seq;
        let h = serde_json::from_value::<Receipt>(v.clone()).ok().map(|r| r.hash());
        let n8 = short(&node).to_string();
        match last.get(&node) {
            None => {
                if seq != 0 || prev_field != ZERO {
                    breaks.push((node.clone(), format!("chain {n8}: starts at seq {seq} (line {ln}), not seq 0: the first {seq} receipt(s) are missing")));
                }
            }
            Some((pln, pseq, ph)) => {
                let (pln, pseq) = (*pln, *pseq);
                if seq <= pseq {
                    breaks.push((node.clone(), format!("chain {n8}: line {ln} has seq {seq} after seq {pseq} (line {pln}): reordered or duplicated")));
                } else if seq > pseq + 1 {
                    let k = seq - pseq - 1;
                    let tail = if ph.as_deref() != Some(prev_field.as_str()) { "" } else { ", yet the link matches" };
                    breaks.push((node.clone(), format!("chain {n8}: gap: {k} receipt(s) missing between seq {pseq} (line {pln}) and seq {seq} (line {ln}){tail}")));
                } else if ph.as_deref() != Some(prev_field.as_str()) {
                    let why = if bad.contains_key(&pln) { "which was altered after it was signed" } else { "the chain was rewritten here" };
                    breaks.push((node.clone(), format!("chain {n8}: line {ln} (seq {seq}) does not link to line {pln} (seq {pseq}), {why}")));
                }
            }
        }
        last.insert(node, (ln, seq, h));
    }
    if root.is_none() && roots.len() > 1 {
        bad.insert(0, format!("receipts use {} different capability roots; pin one with --root", roots.len()));
    }
    for (n, _) in &breaks {
        if let Some(s) = per.get_mut(n) {
            s.breaks += 1;
        }
    }
    let valid = total - bad.keys().filter(|k| **k != 0).count();
    let shown_root = root.map(str::to_string).or_else(|| roots.iter().next().cloned()).unwrap_or_else(|| "?".into());
    let mut out = vec![format!(
        "{total} receipts from {} node(s), capability root {}{}",
        per.len(),
        &shown_root[..shown_root.len().min(16)],
        if root.is_some() { "" } else { " (pin it with --root)" }
    )];
    out.push(format!("  {:9} {:>8} {:>6}  {:24} cells", "node", "receipts", "valid", "chain"));
    for (n, s) in &per {
        let chain = if s.breaks == 0 { "intact".to_string() } else { format!("{} break(s)", s.breaks) };
        let chain = format!("{chain} seq {}..{}", s.first, s.last);
        let cells: Vec<&str> = s.cells.iter().map(String::as_str).collect();
        out.push(format!("  {:9} {:>8} {:>6}  {:24} {}", short(n), s.receipts, s.valid, chain, cells.join(" ")));
    }
    out.extend(bad.values().map(|m| format!("FAIL {m}")));
    out.extend(breaks.iter().map(|(_, m)| format!("FAIL {m}")));
    let ok = bad.is_empty() && breaks.is_empty();
    out.push(format!(
        "{}: {valid} of {total} receipts valid{}",
        if ok { "VALID" } else { "INVALID" },
        if breaks.is_empty() { String::new() } else { format!(", {} chain break(s)", breaks.len()) }
    ));
    (out, ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::{Call, Cell, NodeLog, WithReceipts};
    use ce_net_proto::{Caveats, Identity, Resource, SignedCapability};

    struct Echo;
    impl Cell for Echo {
        fn name(&self) -> &str {
            "echo"
        }
        fn call(&mut self, input: &[u8]) -> Result<Vec<u8>, String> {
            Ok(input.to_vec())
        }
    }

    fn id(n: u8) -> Identity {
        Identity::from_secret_bytes(&[n; 32])
    }

    fn setup(abilities: &[&str]) -> (Identity, Identity, Vec<SignedCapability>) {
        let (root, caller) = (id(1), id(2));
        let cav = Caveats { not_before: 0, not_after: 2_000, ..Default::default() };
        let chain = vec![SignedCapability::issue(&root, caller.node_id(), abilities.iter().map(|s| s.to_string()).collect(), Resource::Any, cav, 7, None)];
        (root, caller, chain)
    }

    fn run(abilities: &[&str], n: usize, ts: u64) -> (String, Vec<String>) {
        let (root, caller, chain) = setup(abilities);
        let log = NodeLog::new(id(3));
        let mut cell = WithReceipts::new(Echo, log.clone(), root.node_id());
        for i in 0..n {
            let _ = cell.call(Call { caller: caller.node_id(), chain: &chain, input: format!("{i}").as_bytes(), ts });
        }
        let lines = log.borrow().receipts.iter().map(|r| r.to_line()).collect();
        (root.node_id_hex(), lines)
    }

    fn check(lines: &[String], root: &str) -> (Vec<String>, bool) {
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        verify_receipts(&refs, Some(root), None)
    }

    #[test]
    fn honest_receipts_verify_and_link() {
        let (root, lines) = run(&["cell:*"], 5, 100);
        let (report, ok) = check(&lines, &root);
        assert!(ok, "{report:?}");
        assert_eq!(report.last().unwrap(), "VALID: 5 of 5 receipts valid");
    }

    #[test]
    fn an_edited_output_is_named() {
        let (root, mut lines) = run(&["cell:echo"], 5, 100);
        let mut r = parse_line(&lines[2]).unwrap();
        r.output = crate::sha256_hex(b"x");
        lines[2] = r.to_line();
        let (report, ok) = check(&lines, &root);
        assert!(!ok);
        assert!(report.iter().any(|l| l.starts_with("FAIL line 3 (echo seq 2") && l.contains("invalid signature")), "{report:?}");
        assert!(report.iter().any(|l| l.contains("does not link to line 3") && l.contains("altered")), "{report:?}");
    }

    #[test]
    fn a_dropped_receipt_is_a_gap() {
        let (root, mut lines) = run(&["cell:echo"], 5, 100);
        lines.remove(2);
        let (report, ok) = check(&lines, &root);
        assert!(!ok);
        assert!(report.iter().any(|l| l.contains("gap: 1 receipt(s) missing between seq 1 (line 2) and seq 3 (line 3)")), "{report:?}");
    }

    #[test]
    fn refusals_leave_a_receipt_too() {
        // the chain grants a different cell, and a second call comes after expiry
        let (root, lines) = run(&["cell:other"], 1, 100);
        let r = parse_line(&lines[0]).unwrap();
        assert_eq!(r.status, "refused: does not grant cell:echo");
        assert!(check(&lines, &root).1, "a receipt of a refusal is itself valid");
        let (_, late) = run(&["cell:echo"], 1, 3_000);
        assert!(parse_line(&late[0]).unwrap().status.starts_with("refused: link 0: capability has expired"));
    }

    #[test]
    fn a_wrong_root_is_refused() {
        let (_, lines) = run(&["cell:echo"], 2, 100);
        let (report, ok) = check(&lines, &id(9).node_id_hex());
        assert!(!ok);
        assert!(report.iter().any(|l| l.contains("capability: capability chain does not root at an accepted authority")), "{report:?}");
    }
}
