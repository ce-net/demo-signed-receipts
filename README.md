# Every call leaves a receipt

A small workload makes 200 calls across four cells on three nodes. Every call leaves a receipt, signed
by the node that ran it and hash-linked to that node's previous receipt. Download `receipts.jsonl` and
check it on any machine, with no network and no packages:

```
200 receipts from 3 node(s), capability root 86f9f18295a18b9d (pin it with --root)
  node      receipts  valid  chain                    cells
  3fa01cf2       106    106  intact seq 0..105        kv.get kv.put
  9cb9533e        43     43  intact seq 0..42         text.upper
  e849da40        51     51  intact seq 0..50         sum
VALID: 200 of 200 receipts valid
```

Change one output hash and the verifier names the receipt and says why it failed. Drop a receipt from
the middle and the hash-linked chain shows the gap.

## Run it (under 5 minutes)

Needs git, Rust 1.85+ and Python 3.9+. Everything it uses is public.

```sh
git clone https://github.com/ce-net/demo-demo-signed-receipts && cd demo-demo-signed-receipts
git clone https://github.com/ce-net/ce-net-capability-verify ../ce-net-capability-verify
cargo run -- workload
python3 ../ce-net-capability-verify/verify.py out/receipts.jsonl
```

`cargo run -- workload` takes about 30 seconds the first time. It prints the calls per cell, then the
Rust verifier's report. `verify.py` is one Python file that uses only the standard library. Copy it
and `receipts.jsonl` to any machine and run it there offline.

The edited file and the gapped file:

```sh
python3 ../ce-net-capability-verify/verify.py out/tampered.jsonl
```

```
FAIL line 42 (text.upper seq 9 on node 9cb9533e): invalid signature: these fields are not what node 9cb9533e signed
FAIL chain 9cb9533e: line 43 (seq 10) does not link to line 42 (seq 9), which was altered after it was signed
INVALID: 199 of 200 receipts valid, 1 chain break(s)
```

```sh
python3 ../ce-net-capability-verify/verify.py out/gapped.jsonl
```

```
FAIL chain e849da40: gap: 1 receipt(s) missing between seq 25 (line 98) and seq 27 (line 104)
INVALID: 199 of 199 receipts valid, 1 chain break(s)
```

Every receipt in the gapped file is still valid on its own. The chain is what shows that one is
missing. Both commands exit 1. Try your own edits too: change a `seq`, swap two lines, or replay a
receipt.

Pin the keys you trust, so that a file re-signed with other keys is refused. The keys are in
`out/keys.json`:

```sh
python3 ../ce-net-capability-verify/verify.py out/receipts.jsonl --root 86f9f18295a18b9d604ef9a56a9047a0cc2e69f200e5f84d9b1f3cd267c6e40f \
  --nodes 3fa01cf2aa3c89abe3878a202f981458fc3149f9c7c844dca25919101db5573c,9cb9533e668d7075ce5beee77c475fa81d904e187a7d9c831d5559871fe00e36,e849da4053d75e2f046984101098ba8c2c5f56e04df8bb6aa6a1c57ffc342f69
```

## The same middleware on the local ce-net sim

```sh
git clone https://github.com/ce-net/ce-net-local-dev-sim ../ce-net-local-dev-sim
cargo run -- sim ../ce-net-local-dev-sim
python3 ../ce-net-capability-verify/verify.py out/sim-receipts.jsonl
```

This starts [ce-net-local-dev-sim](https://github.com/ce-net/ce-net-local-dev-sim), the in-memory mock
of the ce-net MCP server. It joins, publishes the echo app, finds it, and makes 20 `mcp_use` calls to it
through `receipt.sign`: 20 of 20 valid.

## The reusable cells

- **`receipt.sign`** (`crates/receipt/src/sign.rs`) is middleware that any cell can add. Wrap a cell in
  `WithReceipts::new(cell, node_log, root_key)`. Each call then checks the caller's ce-net capability
  chain ([ce-net-proto](https://github.com/ce-net/ce-net-proto)): it must be valid at the call time, held
  by the caller, and grant `cell:<name>`. The wrapper then runs the call and appends a signed receipt.
  Refused and failed calls get a receipt too, with status `refused: ...` or `error: ...`.
- **`receipt.verify`** comes in two versions that print the same report. The Rust one is
  `crates/receipt/src/verify.rs` (`cargo run -- verify FILE`). The Python one is the single file
  `verify.py` in [ce-net-capability-verify](https://github.com/ce-net/ce-net-capability-verify), which
  verifies the capability chain inside each receipt.

## The receipt format

There is one JSON object per line. The node signs these bytes with Ed25519:

```
ce-receipt/1
node=<hex32>
seq=<per-node counter, from 0>
prev=<sha256 of the previous receipt's signed bytes on this node; zeros for seq 0>
ts=<unix seconds>
cell=<cell name>
caller=<hex32>
cap=<id of the leaf of the caller's capability chain>
input=<sha256 of the input>
output=<sha256 of the output>
status=<ok | refused: why | error: why>
```

Each line ends in `\n`. The JSON adds `chain` (the capability token, hex) and `sig`. The verifier checks
every receipt on its own: fields, the node's signature, and for `ok` calls the capability chain. Then it
walks each node's chain. `seq` must count up by one and each `prev` must match the hash of the receipt
before it, so a missing, edited, reordered or replayed receipt shows up.

## Proof

`proof/` holds the committed receipts (`receipts.jsonl`, 200 calls), the tampered and gapped fixtures,
the sim receipts, the keys, and the expected verifier report for each (`*.expected.txt`). The demo keys
come from public labels, and the workload clock is fixed, so every run writes the same bytes. CI checks:

- `cargo run -- workload` and `cargo run -- sim` reproduce `proof/` byte for byte.
- The Rust verifier matches every expected report (`crates/receipt/tests/proof.rs`) and exit code.
- `verify.py` runs on a clean runner in a `python:3.12-alpine` container with `--network none` and no
  packages. CI first checks that the container cannot reach the network. The verifier must return the
  expected report for all four fixtures: the tampered and gapped ones fail, the others pass.

## Limits

- A receipt proves that a node key signed this call record. It does not prove that the node computed
  the output honestly. For that, re-run the call or use a verified-result certificate.
- Without `--root` and `--nodes`, the verifier only checks that the file is consistent with itself.
  Pin the keys you trust.
- Dropping the newest receipts from the end of a node's chain leaves no gap. Compare the last `seq`
  per node with a count that you know from elsewhere.
- The demo keys come from public strings so anyone can reproduce the file. Real nodes use their own keys.

## License

Apache-2.0
