//! End-to-end test of the HTTP transport against an in-process stub MCP server.
//!
//! Only built with the `http` feature: `cargo test --features http --test http_transport`.
#![cfg(feature = "http")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};

use mcp_guard::fuzzer::{FuzzEngine, ResultCategory, Transport};
use mcp_guard::transport::HttpTransport;

/// Start a minimal streamable-HTTP MCP stub on a loopback port; returns its URL.
///
/// `initialize`/`tools/list` reply as `application/json`; `tools/call` replies as an SSE
/// (`text/event-stream`) body, exercising both response paths. Every response sends
/// `Connection: close`, so each request is its own connection.
fn spawn_stub() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let _ = handle_connection(stream);
        }
    });
    format!("http://127.0.0.1:{port}/mcp")
}

fn handle_connection(mut stream: TcpStream) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Ok(()); // client closed
        }
        if line == "\r\n" {
            break; // end of headers
        }
        if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body)?;
    let msg: Value = serde_json::from_slice(&body).unwrap_or_else(|_| json!({}));
    let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
    let id = msg.get("id").cloned();

    if id.is_none() {
        // Notification (e.g. notifications/initialized): 202, no body.
        return stream
            .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    }

    let response = match method {
        "initialize" => json!({"jsonrpc":"2.0","id":id,"result":{"protocolVersion":"2024-11-05"}}),
        "tools/list" => json!({"jsonrpc":"2.0","id":id,"result":{"tools":[
            {"name":"echo","inputSchema":{"type":"object",
                "properties":{"q":{"type":"string"}},"required":["q"]}}
        ]}}),
        _ => json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":"ok"}]}}),
    };

    if method == "tools/call" {
        let payload = format!("event: message\ndata: {response}\n\n");
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nMcp-Session-Id: s1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        )
    } else {
        let payload = serde_json::to_string(&response).unwrap();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nMcp-Session-Id: s1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        )
    }
}

#[test]
fn http_transport_fuzzes_a_stub_server() {
    let url = spawn_stub();
    let mut transport = HttpTransport::connect(url, Vec::new(), Duration::from_secs(5))
        .expect("handshake should succeed");

    let tools = transport.list_tools().expect("tools/list over JSON");
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["name"], "echo");

    // tools/call replies come back over SSE — the transport must parse them.
    let results = FuzzEngine::new(0).fuzz_tool(&mut transport, &tools[0]);
    assert!(!results.is_empty());
    assert!(
        results
            .iter()
            .all(|r| r.category == ResultCategory::Accepted)
    );
    assert!(results.iter().all(|r| r.category != ResultCategory::Crash));
}
