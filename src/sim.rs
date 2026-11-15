//! The same middleware on ce-net-local-dev-sim: start the mock ce-net MCP server, join, publish the echo
//! app, discover it, and make 20 calls to it through `mcp_use`, each wrapped in `receipt.sign`.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};

use ce_net_proto::{NodeId, SignedCapability};
use receipt::sign::{Call, Cell, NodeLog, WithReceipts};
use serde_json::{json, Value};

const CALLS: usize = 20;

/// The mock server process, stopped when dropped.
struct Mock(Child);
impl Drop for Mock {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn post(port: u16, path: &str, body: &Value) -> Result<Value, String> {
    let body = body.to_string();
    let mut s = TcpStream::connect(("127.0.0.1", port)).map_err(|e| format!("connect: {e}"))?;
    write!(s, "POST {path} HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len())
        .map_err(|e| e.to_string())?;
    let mut resp = String::new();
    s.read_to_string(&mut resp).map_err(|e| e.to_string())?;
    let (_, body) = resp.split_once("\r\n\r\n").ok_or("bad HTTP response")?;
    serde_json::from_str(body).map_err(|e| format!("bad JSON from the sim: {e}"))
}

fn tool(port: u16, name: &str, args: Value) -> Result<Value, String> {
    let res = post(port, "/mcp", &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}}))?;
    let res = &res["result"];
    if res["isError"].as_bool() == Some(true) {
        return Err(format!("{name}: {}", res["content"][0]["text"]));
    }
    Ok(res["structuredContent"].clone())
}

/// The cell: one `mcp_use` call to the echo app, through the mock network.
struct McpEcho {
    port: u16,
    key: String,
    url: String,
}

impl Cell for McpEcho {
    fn name(&self) -> &str {
        "mcp.echo"
    }
    fn call(&mut self, input: &[u8]) -> Result<Vec<u8>, String> {
        let text = String::from_utf8_lossy(input);
        let out = tool(self.port, "mcp_use", json!({"key": self.key, "url": self.url, "tool": "echo", "arguments": {"text": text}}))?;
        out["answer"]["content"][0]["text"].as_str().map(|s| s.as_bytes().to_vec()).ok_or_else(|| "no answer".into())
    }
}

/// Run the 20 calls; returns the receipt lines.
pub fn run(sim_dir: &Path, root: NodeId, caller: NodeId, chain: &[SignedCapability], node: ce_net_proto::Identity, t0: u64) -> Result<Vec<String>, String> {
    let script = sim_dir.join("cenet_mock.py");
    if !script.is_file() {
        return Err(format!("{} not found: git clone https://github.com/ce-net/ce-net-local-dev-sim {}", script.display(), sim_dir.display()));
    }
    let mut child = Command::new("python3").arg(&script).arg("0").stdout(Stdio::piped()).spawn().map_err(|e| format!("python3: {e}"))?;
    let stdout = child.stdout.take().ok_or("no stdout")?;
    let _mock = Mock(child);
    let mut line = String::new();
    BufReader::new(stdout).read_line(&mut line).map_err(|e| e.to_string())?;
    // "cenet-mock on http://127.0.0.1:PORT/mcp"
    let port: u16 = line
        .trim()
        .rsplit(':')
        .next()
        .and_then(|p| p.trim_end_matches("/mcp").parse().ok())
        .ok_or_else(|| format!("unexpected sim banner: {line:?}"))?;

    let key = tool(port, "agent_join", json!({"name": "receipts demo", "about": "signed receipts on the local sim"}))?["key"]
        .as_str()
        .ok_or("no key")?
        .to_string();
    let base = format!("http://127.0.0.1:{port}");
    tool(port, "app_publish", json!({"key": key, "name": "echo", "url": format!("{base}/echo"), "what": "echoes text back"}))?;
    let apps = tool(port, "apps_search", json!({"q": "echo"}))?;
    let url = apps["apps"][0]["url"].as_str().ok_or("echo app not found")?.to_string();

    let log = NodeLog::new(node);
    let mut cell = WithReceipts::new(McpEcho { port, key, url }, log.clone(), root);
    for i in 0..CALLS {
        let input = format!("hello {i}");
        let (out, r) = cell.call(Call { caller, chain, input: input.as_bytes(), ts: t0 + 3 * i as u64 });
        if out.as_deref() != Ok(input.as_bytes()) || r.status != "ok" {
            return Err(format!("sim call {i}: {}", r.status));
        }
    }
    let lines = log.borrow().receipts.iter().map(|r| r.to_line()).collect();
    Ok(lines)
}
