//! stdio MCP transport: spawns the server as a subprocess and speaks JSON-RPC over its
//! stdin/stdout.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{Value, json};

use crate::fuzzer::{Transport, TransportError};

/// An MCP server spawned as a child process and driven over stdio.
///
/// The child is killed when the transport is dropped.
pub struct StdioTransport {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    request_id: u64,
}

impl StdioTransport {
    /// Spawn `command` and perform the MCP initialize handshake.
    ///
    /// `command` is the program followed by its arguments, e.g.
    /// `["npx", "-y", "@modelcontextprotocol/server-memory"]`.
    pub fn spawn(command: &[String]) -> Result<Self, TransportError> {
        let (program, args) = command
            .split_first()
            .ok_or_else(|| TransportError::Protocol("empty server command".to_owned()))?;

        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| TransportError::Protocol("failed to capture stdin".to_owned()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| TransportError::Protocol("failed to capture stdout".to_owned()))?;

        let mut transport = Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            request_id: 0,
        };
        transport.initialize()?;
        Ok(transport)
    }

    fn initialize(&mut self) -> Result<(), TransportError> {
        self.send(
            "initialize",
            Some(json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "mcp-guard", "version": crate::VERSION },
            })),
        )?;
        self.notify("notifications/initialized", None)
    }

    /// List the tools the server exposes.
    pub fn list_tools(&mut self) -> Result<Vec<Value>, TransportError> {
        let result = self.send("tools/list", None)?;
        Ok(result
            .get("tools")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default())
    }

    fn send(&mut self, method: &str, params: Option<Value>) -> Result<Value, TransportError> {
        self.request_id += 1;
        let mut request = json!({ "jsonrpc": "2.0", "id": self.request_id, "method": method });
        if let Some(params) = params {
            request["params"] = params;
        }
        self.write_message(&request)?;
        self.read_response()
    }

    fn notify(&mut self, method: &str, params: Option<Value>) -> Result<(), TransportError> {
        let mut notification = json!({ "jsonrpc": "2.0", "method": method });
        if let Some(params) = params {
            notification["params"] = params;
        }
        self.write_message(&notification)
    }

    fn write_message(&mut self, message: &Value) -> Result<(), TransportError> {
        let line =
            serde_json::to_string(message).map_err(|e| TransportError::Protocol(e.to_string()))?;
        self.stdin
            .write_all(line.as_bytes())
            .and_then(|()| self.stdin.write_all(b"\n"))
            .and_then(|()| self.stdin.flush())
            .map_err(|_| TransportError::ConnectionLost)
    }

    fn read_response(&mut self) -> Result<Value, TransportError> {
        loop {
            let mut line = String::new();
            let read = self
                .stdout
                .read_line(&mut line)
                .map_err(|_| TransportError::ConnectionLost)?;
            if read == 0 {
                return Err(TransportError::ConnectionLost);
            }
            let Ok(message) = serde_json::from_str::<Value>(line.trim()) else {
                continue; // skip non-JSON log lines
            };
            // Skip notifications (a method with no id).
            if message.get("method").is_some() && message.get("id").is_none() {
                continue;
            }
            if let Some(error) = message.get("error") {
                return Err(TransportError::Protocol(error.to_string()));
            }
            return Ok(message.get("result").cloned().unwrap_or_else(|| json!({})));
        }
    }
}

impl Transport for StdioTransport {
    fn call_tool(&mut self, tool_name: &str, arguments: Value) -> Result<Value, TransportError> {
        self.send(
            "tools/call",
            Some(json!({ "name": tool_name, "arguments": arguments })),
        )
    }
}

impl Drop for StdioTransport {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
