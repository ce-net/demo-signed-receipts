//! The committed fixtures in proof/ give exactly the expected report and verdict.

use receipt::verify::verify_receipts;

fn check(name: &str, want_ok: bool) {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../proof");
    let text = std::fs::read_to_string(format!("{dir}/{name}.jsonl")).unwrap();
    let want = std::fs::read_to_string(format!("{dir}/{name}.expected.txt")).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let (report, ok) = verify_receipts(&lines, None, None);
    assert_eq!(ok, want_ok, "{name}");
    assert_eq!(report.join("\n") + "\n", want, "{name}");
}

#[test]
fn honest_receipts() {
    check("receipts", true);
}

#[test]
fn tampered_output_hash() {
    check("tampered", false);
}

#[test]
fn gap_in_the_chain() {
    check("gapped", false);
}

#[test]
fn sim_receipts() {
    check("sim-receipts", true);
}
