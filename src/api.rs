//! A tiny read-only HTTP API on its own thread, for the services that use
//! the relay (e.g. Strom asks it for the public address to hand out).
//! Meant for the internal network only: never expose it publicly.
//!
//! - `GET /v1/info`  -> `{"version":"…","public":"host:port"|null,"srt_port":9000}`
//! - `GET /healthz`  -> `ok`

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

pub struct Info {
    pub public: Option<String>,
    pub srt_port: u16,
}

pub fn spawn(listen: &str, info: Info) -> std::io::Result<()> {
    let listener = TcpListener::bind(listen)?;
    std::thread::Builder::new()
        .name("api".into())
        .spawn(move || {
            for stream in listener.incoming().flatten() {
                let _ = handle(stream, &info);
            }
        })?;
    Ok(())
}

fn handle(mut stream: TcpStream, info: &Info) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut line = String::new();
    BufReader::new(&stream).take_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let (status, ctype, body) = match (method, path.split('?').next().unwrap_or("")) {
        ("GET", "/v1/info") => ("200 OK", "application/json", info_json(info)),
        ("GET", "/healthz") => ("200 OK", "text/plain", "ok\n".to_string()),
        ("GET", _) => ("404 Not Found", "text/plain", "not found\n".to_string()),
        _ => (
            "405 Method Not Allowed",
            "text/plain",
            "method not allowed\n".to_string(),
        ),
    };
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// Reads the request line only; the rest of the request is ignored.
trait TakeLine {
    fn take_line(self, out: &mut String) -> std::io::Result<usize>;
}

impl<R: std::io::Read> TakeLine for BufReader<R> {
    fn take_line(mut self, out: &mut String) -> std::io::Result<usize> {
        // Bound the line, so a client cannot make us buffer without end.
        let mut limited = BufReader::new(std::io::Read::take(&mut self, 8192));
        limited.read_line(out)
    }
}

fn info_json(info: &Info) -> String {
    let public = match &info.public {
        Some(p) => format!("\"{}\"", json_escape(p)),
        None => "null".into(),
    };
    format!(
        "{{\"version\":\"{}\",\"public\":{public},\"srt_port\":{}}}\n",
        env!("CARGO_PKG_VERSION"),
        info.srt_port
    )
}

fn json_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_json_shape() {
        let j = info_json(&Info {
            public: Some("srt.example.com:9000".into()),
            srt_port: 9000,
        });
        assert!(j.contains("\"public\":\"srt.example.com:9000\""));
        assert!(j.contains("\"srt_port\":9000"));
        let j = info_json(&Info {
            public: None,
            srt_port: 9000,
        });
        assert!(j.contains("\"public\":null"));
        assert_eq!(json_escape("a\"b\\c\n"), "a\\\"b\\\\c\\u000a");
    }
}
