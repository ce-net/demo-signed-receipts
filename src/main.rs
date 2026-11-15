//! Every call leaves a receipt.
//!
//!   cargo run -- workload [OUT_DIR]               200 calls across four cells; writes OUT_DIR (default out/)
//!   cargo run -- sim [SIM_DIR] [OUT_DIR]          the same middleware on ce-net-local-dev-sim (default ../ce-net-local-dev-sim)
//!   cargo run -- verify FILE [--root HEX] [--nodes HEX,HEX...]   the Rust receipt.verify; same report as verify.py

mod sim;

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::ExitCode;
use std::rc::Rc;

use ce_net_proto::{Caveats, Identity, NodeId, Resource, SignedCapability};
use receipt::sign::{Call, Cell, NodeLog, WithReceipts};
use receipt::verify::verify_receipts;
use sha2::{Digest, Sha256};

/// 2025-11-15 00:00 UTC: the workload's clock starts here so every run produces the same bytes.
const T0: u64 = 1_763_164_800;
const CALLS: usize = 200;
/// Which receipt the tampered fixture edits, and which one the gapped fixture drops (1-based lines).
const TAMPER_LINE: usize = 42;
const DROP_LINE: usize = 100;

/// Demo keys, derived from public labels so anyone can reproduce the file. Never do this for real keys.
fn key(label: &str) -> Identity {
    Identity::from_secret_bytes(&Sha256::digest(format!("demo-signed-receipts/{label}")).into())
}

struct KvPut(Rc<RefCell<BTreeMap<String, String>>>);
struct KvGet(Rc<RefCell<BTreeMap<String, String>>>);
struct Upper;
struct Sum;

impl Cell for KvPut {
    fn name(&self) -> &str {
        "kv.put"
    }
    fn call(&mut self, input: &[u8]) -> Result<Vec<u8>, String> {
        let s = String::from_utf8_lossy(input);
        let (k, v) = s.split_once('=').ok_or("expected key=value")?;
        self.0.borrow_mut().insert(k.to_string(), v.to_string());
        Ok(format!("stored {k}").into_bytes())
    }
}

impl Cell for KvGet {
    fn name(&self) -> &str {
        "kv.get"
    }
    fn call(&mut self, input: &[u8]) -> Result<Vec<u8>, String> {
        let k = String::from_utf8_lossy(input).to_string();
        self.0.borrow().get(&k).map(|v| v.clone().into_bytes()).ok_or_else(|| format!("no key {k}"))
    }
}

impl Cell for Upper {
    fn name(&self) -> &str {
        "text.upper"
    }
    fn call(&mut self, input: &[u8]) -> Result<Vec<u8>, String> {
        Ok(String::from_utf8_lossy(input).to_uppercase().into_bytes())
    }
}

impl Cell for Sum {
    fn name(&self) -> &str {
        "sum"
    }
    fn call(&mut self, input: &[u8]) -> Result<Vec<u8>, String> {
        let s = String::from_utf8_lossy(input);
        let mut t: i64 = 0;
        for x in s.split(',') {
            t += x.trim().parse::<i64>().map_err(|e| format!("{x}: {e}"))?;
        }
        Ok(t.to_string().into_bytes())
    }
}

enum AnyCell {
    Put(WithReceipts<KvPut>),
    Get(WithReceipts<KvGet>),
    Upper(WithReceipts<Upper>),
    Sum(WithReceipts<Sum>),
}

impl AnyCell {
    fn call(&mut self, c: Call<'_>) -> (Result<Vec<u8>, String>, receipt::Receipt) {
        match self {
            AnyCell::Put(x) => x.call(c),
            AnyCell::Get(x) => x.call(c),
            AnyCell::Upper(x) => x.call(c),
            AnyCell::Sum(x) => x.call(c),
        }
    }
}

fn grant(issuer: &Identity, to: NodeId, abilities: &[&str], nonce: u64, parent: Option<&SignedCapability>) -> SignedCapability {
    let caveats = Caveats { not_before: T0, not_after: T0 + 86_400, ..Default::default() };
    SignedCapability::issue(
        issuer,
        to,
        abilities.iter().map(|s| s.to_string()).collect(),
        Resource::Any,
        caveats,
        nonce,
        parent.map(|p| p.id()),
    )
}

fn workload(out: &Path) -> Result<bool, String> {
    let root = key("root");
    let operator = key("operator");
    let app = key("caller/app");
    let batch = key("caller/batch");
    // root -> operator (cell:*) -> app (kv) / batch (compute): two-link chains, each narrower than its parent.
    let op_link = grant(&root, operator.node_id(), &["cell:*"], 1, None);
    let app_chain = vec![op_link.clone(), grant(&operator, app.node_id(), &["cell:kv.put", "cell:kv.get"], 2, Some(&op_link))];
    let batch_chain = vec![op_link.clone(), grant(&operator, batch.node_id(), &["cell:text.upper", "cell:sum"], 3, Some(&op_link))];

    let nodes = [("store", key("node/store")), ("edge", key("node/edge")), ("compute", key("node/compute"))];
    let logs: Vec<_> = nodes.iter().map(|(_, id)| NodeLog::new(Identity::from_secret_bytes(&id.secret_bytes()))).collect();
    let kv = Rc::new(RefCell::new(BTreeMap::new()));
    let r = root.node_id();
    let mut cells = [
        AnyCell::Put(WithReceipts::new(KvPut(kv.clone()), logs[0].clone(), r)),
        AnyCell::Get(WithReceipts::new(KvGet(kv.clone()), logs[0].clone(), r)),
        AnyCell::Upper(WithReceipts::new(Upper, logs[1].clone(), r)),
        AnyCell::Sum(WithReceipts::new(Sum, logs[2].clone(), r)),
    ];

    let mut lines = Vec::new();
    let mut rng: u64 = 0x5eed;
    let mut puts = 0usize;
    let mut per_cell: BTreeMap<&str, usize> = BTreeMap::new();
    for i in 0..CALLS {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let pick = if puts == 0 { 0 } else { ((rng >> 33) % 4) as usize };
        let n = (rng >> 40) % 1000;
        let (input, caller, chain) = match pick {
            0 => {
                puts += 1;
                (format!("item{}={}", puts, n), app.node_id(), &app_chain)
            }
            1 => (format!("item{}", 1 + (n as usize) % puts), app.node_id(), &app_chain),
            2 => (format!("receipt number {i}, value {n}"), batch.node_id(), &batch_chain),
            _ => (format!("{},{},{}", n, i, n % 7), batch.node_id(), &batch_chain),
        };
        let (result, rec) = cells[pick].call(Call { caller, chain, input: input.as_bytes(), ts: T0 + 3 * i as u64 });
        result.map_err(|e| format!("call {i} failed: {e}"))?;
        *per_cell.entry(["kv.put", "kv.get", "text.upper", "sum"][pick]).or_default() += 1;
        lines.push(rec.to_line());
    }

    std::fs::create_dir_all(out).map_err(|e| e.to_string())?;
    let write = |name: &str, ls: &[String]| {
        std::fs::write(out.join(name), ls.iter().map(|l| format!("{l}\n")).collect::<String>()).map_err(|e| e.to_string())
    };
    write("receipts.jsonl", &lines)?;
    // tampered: one output hash changed after signing.
    let mut tampered = lines.clone();
    let mut rec = receipt::verify::parse_line(&tampered[TAMPER_LINE - 1])?;
    rec.output = receipt::sha256_hex(b"a different answer");
    tampered[TAMPER_LINE - 1] = rec.to_line();
    write("tampered.jsonl", &tampered)?;
    // gapped: one receipt dropped from the middle.
    let mut gapped = lines.clone();
    gapped.remove(DROP_LINE - 1);
    write("gapped.jsonl", &gapped)?;
    let mut keys = String::from("{\n");
    keys += &format!("  \"root\": \"{}\",\n", root.node_id_hex());
    for (i, (name, id)) in nodes.iter().enumerate() {
        keys += &format!("  \"node/{name}\": \"{}\"{}\n", id.node_id_hex(), if i + 1 < nodes.len() { "," } else { "" });
    }
    keys += "}\n";
    std::fs::write(out.join("keys.json"), keys).map_err(|e| e.to_string())?;

    println!("{CALLS} calls across {} cells on {} nodes:", per_cell.len(), nodes.len());
    for (cell, n) in &per_cell {
        println!("  {cell:11} {n:>4}");
    }
    for ((name, id), log) in nodes.iter().zip(&logs) {
        println!("  node {name:8} {}  {} receipts", &id.node_id_hex()[..8], log.borrow().receipts.len());
    }
    println!("wrote {0}/receipts.jsonl, {0}/tampered.jsonl, {0}/gapped.jsonl, {0}/keys.json\n", out.display());
    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    let (report, ok) = verify_receipts(&refs, Some(&root.node_id_hex()), None);
    println!("receipt.verify (Rust) on receipts.jsonl:\n{}", report.join("\n"));
    Ok(ok)
}

fn run_sim(sim_dir: &Path, out: &Path) -> Result<bool, String> {
    let (root, operator, caller) = (key("root"), key("operator"), key("caller/sim"));
    let op_link = grant(&root, operator.node_id(), &["cell:*"], 1, None);
    let chain = vec![op_link.clone(), grant(&operator, caller.node_id(), &["cell:mcp.echo"], 4, Some(&op_link))];
    let lines = sim::run(sim_dir, root.node_id(), caller.node_id(), &chain, key("node/sim"), T0)?;
    std::fs::create_dir_all(out).map_err(|e| e.to_string())?;
    std::fs::write(out.join("sim-receipts.jsonl"), lines.iter().map(|l| format!("{l}\n")).collect::<String>()).map_err(|e| e.to_string())?;
    println!("{} calls through the local ce-net sim (join, publish, discover, mcp_use -> echo) -> {}/sim-receipts.jsonl\n", lines.len(), out.display());
    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    let (report, ok) = verify_receipts(&refs, Some(&root.node_id_hex()), None);
    println!("{}", report.join("\n"));
    Ok(ok)
}

fn verify(args: &[String]) -> Result<bool, String> {
    let (file, mut rest) = args.split_first().ok_or("usage: verify FILE [--root HEX] [--nodes HEX,HEX...]")?;
    let (mut root, mut nodes) = (None, None);
    while let Some((flag, tail)) = rest.split_first() {
        let (val, tail) = tail.split_first().ok_or(format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--root" => root = Some(val.to_lowercase()),
            "--nodes" => nodes = Some(val.to_lowercase().split(',').map(str::to_string).collect::<BTreeSet<_>>()),
            _ => return Err(format!("unknown flag {flag}")),
        }
        rest = tail;
    }
    let text = std::fs::read_to_string(file).map_err(|e| format!("{file}: {e}"))?;
    let lines: Vec<&str> = text.lines().collect();
    let (report, ok) = verify_receipts(&lines, root.as_deref(), nodes.as_ref());
    println!("{}", report.join("\n"));
    Ok(ok)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let res = match args.first().map(String::as_str) {
        Some("workload") => workload(Path::new(args.get(1).map(String::as_str).unwrap_or("out"))),
        Some("verify") => verify(&args[1..]),
        Some("sim") => run_sim(
            Path::new(args.get(1).map(String::as_str).unwrap_or("../ce-net-local-dev-sim")),
            Path::new(args.get(2).map(String::as_str).unwrap_or("out")),
        ),
        _ => Err("usage: cargo run -- workload [OUT_DIR] | sim [SIM_DIR] [OUT_DIR] | verify FILE [--root HEX] [--nodes HEX,...]".into()),
    };
    match res {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(2)
        }
    }
}
