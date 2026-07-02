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
    command: Vec<String>,
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
        let (child, stdin, stdout) = Self::spawn_process(command)?;
        let mut transport = Self {
            command: command.to_vec(),
            child,
            stdin,
            stdout,
            request_id: 0,
        };
        transport.initialize()?;
        Ok(transport)
    }

    fn spawn_process(
        command: &[String],
    ) -> Result<(Child, ChildStdin, BufReader<ChildStdout>), TransportError> {
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

        Ok((child, stdin, BufReader::new(stdout)))
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

    fn list_tools(&mut self) -> Result<Vec<Value>, TransportError> {
        let result = self.send("tools/list", None)?;
        Ok(result
            .get("tools")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default())
    }

    fn reconnect(&mut self) -> Result<(), TransportError> {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let (child, stdin, stdout) = Self::spawn_process(&self.command)?;
        self.child = child;
        self.stdin = stdin;
        self.stdout = stdout;
        self.request_id = 0;
        self.initialize()
    }
}

impl Drop for StdioTransport {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A streamable-HTTP MCP transport (available with the `http` feature).
///
/// Each JSON-RPC message is sent by HTTP POST to a single endpoint; responses arrive as either
/// `application/json` or an SSE (`text/event-stream`) body. A server-issued `Mcp-Session-Id`
/// is captured and echoed on subsequent requests.
#[cfg(feature = "http")]
pub struct HttpTransport {
    agent: ureq::Agent,
    url: String,
    extra_headers: Vec<(String, String)>,
    session_id: Option<String>,
    request_id: u64,
}

#[cfg(feature = "http")]
impl HttpTransport {
    /// Connect to `url` and perform the MCP initialize handshake.
    ///
    /// `extra_headers` are sent on every request (e.g. `Authorization`). `timeout` bounds each
    /// request.
    pub fn connect(
        url: String,
        extra_headers: Vec<(String, String)>,
        timeout: std::time::Duration,
    ) -> Result<Self, TransportError> {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            .http_status_as_error(false)
            .build()
            .into();
        let mut transport = Self {
            agent,
            url,
            extra_headers,
            session_id: None,
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

    fn send(&mut self, method: &str, params: Option<Value>) -> Result<Value, TransportError> {
        self.request_id += 1;
        let mut message = json!({ "jsonrpc": "2.0", "id": self.request_id, "method": method });
        if let Some(params) = params {
            message["params"] = params;
        }
        self.post(&message)?
            .ok_or_else(|| TransportError::Protocol("empty response from server".to_owned()))
    }

    fn notify(&mut self, method: &str, params: Option<Value>) -> Result<(), TransportError> {
        let mut message = json!({ "jsonrpc": "2.0", "method": method });
        if let Some(params) = params {
            message["params"] = params;
        }
        // A notification expects no JSON-RPC response body (HTTP 202).
        self.post_raw(&message).map(|_| ())
    }

    /// POST a request and return the parsed JSON-RPC `result` (or `None` if the body is empty).
    fn post(&mut self, message: &Value) -> Result<Option<Value>, TransportError> {
        let (content_type, body) = self.post_raw(message)?;
        if body.trim().is_empty() {
            return Ok(None);
        }
        let response = if content_type.contains("text/event-stream") {
            crate::net::parse_sse_messages(&body)
                .into_iter()
                .find(|m| m.get("id").is_some())
                .ok_or_else(|| {
                    TransportError::Protocol("no JSON-RPC message in SSE stream".to_owned())
                })?
        } else {
            serde_json::from_str::<Value>(&body)
                .map_err(|e| TransportError::Protocol(format!("invalid JSON response: {e}")))?
        };
        if let Some(error) = response.get("error") {
            return Err(TransportError::Protocol(error.to_string()));
        }
        Ok(Some(
            response.get("result").cloned().unwrap_or_else(|| json!({})),
        ))
    }

    /// POST a message and return `(content_type, body)`, capturing any session id.
    fn post_raw(&mut self, message: &Value) -> Result<(String, String), TransportError> {
        let body =
            serde_json::to_string(message).map_err(|e| TransportError::Protocol(e.to_string()))?;

        let mut request = self
            .agent
            .post(&self.url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream");
        if let Some(session) = &self.session_id {
            request = request.header("Mcp-Session-Id", session);
        }
        for (name, value) in &self.extra_headers {
            request = request.header(name.as_str(), value.as_str());
        }

        let mut response = request
            .send(body)
            .map_err(|_| TransportError::ConnectionLost)?;

        if let Some(session) = response
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
        {
            self.session_id = Some(session.to_owned());
        }
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let text = response
            .body_mut()
            .read_to_string()
            .map_err(|_| TransportError::ConnectionLost)?;
        Ok((content_type, text))
    }
}

#[cfg(feature = "http")]
impl Transport for HttpTransport {
    fn call_tool(&mut self, tool_name: &str, arguments: Value) -> Result<Value, TransportError> {
        self.send(
            "tools/call",
            Some(json!({ "name": tool_name, "arguments": arguments })),
        )
    }

    fn list_tools(&mut self) -> Result<Vec<Value>, TransportError> {
        let result = self.send("tools/list", None)?;
        Ok(result
            .get("tools")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default())
    }

    fn reconnect(&mut self) -> Result<(), TransportError> {
        self.session_id = None;
        self.request_id = 0;
        self.initialize()
    }
}
