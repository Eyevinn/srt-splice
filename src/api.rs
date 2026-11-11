//! A tiny read-only HTTP API, for the services that use the relay (e.g.
//! Strom asks it for the public address to hand out). Meant for the
//! internal network only: never expose it publicly.
//!
//! - `GET /v1/info`  -> `{"version":"…","public":"host:port"|null,"srt_port":9000}`
//! - `GET /healthz`  -> `ok`
//!
//! Each connection gets its own short-lived thread and at most `DEADLINE`
//! in total, so a slow or idle client cannot hold up a health probe.

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Connections handled at once; more are closed right away.
const MAX_CONNS: usize = 32;
/// Total time a connection gets to send its request and read the answer.
const DEADLINE: Duration = Duration::from_secs(1);
/// The request line and headers may not be longer than this.
const MAX_HEAD: usize = 8192;
/// Pause after a failed accept (e.g. out of file descriptors).
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

pub struct Info {
    pub public: Option<String>,
    pub srt_port: u16,
}

/// Binds `listen` and serves the API on background threads. Returns the
/// bound address.
pub fn spawn(listen: &str, info: Info) -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind(listen)?;
    let addr = listener.local_addr()?;
    let info = Arc::new(info);
    std::thread::Builder::new()
        .name("api".into())
        .spawn(move || serve(listener, info))?;
    Ok(addr)
}

/// Decrements the connection count when a connection is done (or its
/// thread could not be started).
struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn serve(listener: TcpListener, info: Arc<Info>) {
    let active = Arc::new(AtomicUsize::new(0));
    let mut failing = false;
    loop {
        let stream = match listener.accept() {
            Ok((s, _)) => {
                failing = false;
                s
            }
            Err(e) => {
                if !failing {
                    eprintln!("api: accept: {e}");
                    failing = true;
                }
                std::thread::sleep(ACCEPT_BACKOFF);
                continue;
            }
        };
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNS {
            active.fetch_sub(1, Ordering::SeqCst);
            continue; // dropped: closed
        }
        let slot = Slot(active.clone());
        let info = info.clone();
        // If the thread cannot start, the closure (and with it the slot and
        // the stream) is dropped.
        let _ = std::thread::Builder::new()
            .name("api-conn".into())
            .spawn(move || {
                let _slot = slot;
                let _ = handle(stream, &info);
            });
    }
}

fn handle(mut stream: TcpStream, info: &Info) -> std::io::Result<()> {
    let deadline = Instant::now() + DEADLINE;
    let (status, ctype, body) = match read_head(&mut stream, deadline)? {
        Some(head) => route(&head, info),
        None => bad_request(),
    };
    stream.set_write_timeout(Some(remaining(deadline)?))?;
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    stream.flush()
}

fn remaining(deadline: Instant) -> std::io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| ErrorKind::TimedOut.into())
}

/// Reads the request head up to and including the blank line, so that
/// closing the connection after the answer does not reset it away. Returns
/// `None` if the head is longer than `MAX_HEAD`. A client that closes its
/// side early gets an answer to what it sent.
fn read_head(stream: &mut TcpStream, deadline: Instant) -> std::io::Result<Option<Vec<u8>>> {
    let mut head = Vec::with_capacity(1024);
    let mut buf = [0u8; 1024];
    while head_end(&head).is_none() {
        if head.len() >= MAX_HEAD {
            return Ok(None);
        }
        // One deadline for the whole request, not per read.
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        let want = buf.len().min(MAX_HEAD - head.len());
        match stream.read(&mut buf[..want]) {
            Ok(0) => break,
            Ok(n) => head.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(Some(head))
}

/// Where the head ends (after the blank line), if it is complete.
fn head_end(b: &[u8]) -> Option<usize> {
    (0..b.len()).find_map(|i| {
        if b[i..].starts_with(b"\r\n\r\n") {
            Some(i + 4)
        } else if b[i..].starts_with(b"\n\n") {
            Some(i + 2)
        } else {
            None
        }
    })
}

type Response = (&'static str, &'static str, String);

fn bad_request() -> Response {
    ("400 Bad Request", "text/plain", "bad request\n".into())
}

/// The answer to a request head: (status, content type, body).
fn route(head: &[u8], info: &Info) -> Response {
    let line = head.split(|&b| b == b'\n').next().unwrap_or_default();
    let Ok(line) = std::str::from_utf8(line) else {
        return bad_request();
    };
    let mut parts = line.split_whitespace();
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return bad_request();
    };
    if !version.starts_with("HTTP/1.") || !target.starts_with('/') {
        return bad_request();
    }
    let path = target.split('?').next().unwrap_or_default();
    match (method, path) {
        ("GET", "/v1/info") => ("200 OK", "application/json", info_json(info)),
        ("GET", "/healthz") => ("200 OK", "text/plain", "ok\n".into()),
        ("GET", _) => ("404 Not Found", "text/plain", "not found\n".into()),
        _ => (
            "405 Method Not Allowed",
            "text/plain",
            "method not allowed\n".into(),
        ),
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

    fn info() -> Info {
        Info {
            public: Some("srt.example.com:9000".into()),
            srt_port: 9000,
        }
    }

    #[test]
    fn info_json_shape() {
        let j = info_json(&info());
        assert!(j.contains("\"public\":\"srt.example.com:9000\""));
        assert!(j.contains("\"srt_port\":9000"));
        let j = info_json(&Info {
            public: None,
            srt_port: 9000,
        });
        assert!(j.contains("\"public\":null"));
        assert_eq!(json_escape("a\"b\\c\n"), "a\\\"b\\\\c\\u000a");
    }

    #[test]
    fn routes() {
        let status = |head: &[u8]| route(head, &info()).0;
        assert_eq!(
            status(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n"),
            "200 OK"
        );
        assert_eq!(status(b"GET /v1/info?x=1 HTTP/1.0\n\n"), "200 OK");
        assert_eq!(status(b"GET /nope HTTP/1.1\r\n\r\n"), "404 Not Found");
        assert_eq!(
            status(b"POST /healthz HTTP/1.1\r\n\r\n"),
            "405 Method Not Allowed"
        );
        assert_eq!(status(b"GET /healthz\r\n\r\n"), "400 Bad Request");
        assert_eq!(status(b"GET \xff HTTP/1.1\r\n\r\n"), "400 Bad Request");
        assert_eq!(status(b"\r\n\r\n"), "400 Bad Request");
        assert_eq!(status(b"hello world foo\r\n\r\n"), "400 Bad Request");
    }

    #[test]
    fn head_end_finds_the_blank_line() {
        assert_eq!(head_end(b"GET / HTTP/1.1\r\nHost: x\r\n"), None);
        assert_eq!(head_end(b"GET / HTTP/1.1\r\n\r\nbody"), Some(18));
        assert_eq!(head_end(b"GET / HTTP/1.1\n\n"), Some(16));
    }

    fn get(addr: SocketAddr, req: &[u8]) -> String {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        s.write_all(req).unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        out
    }

    #[test]
    fn idle_clients_do_not_block_healthz() {
        let addr = spawn("127.0.0.1:0", info()).unwrap();
        // Idle connections and one that sends half a request.
        let idle: Vec<_> = (0..4).map(|_| TcpStream::connect(addr).unwrap()).collect();
        let mut half = TcpStream::connect(addr).unwrap();
        half.write_all(b"GET /healthz HTTP/1.1\r\n").unwrap();
        let t = Instant::now();
        let r = get(addr, b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(r.starts_with("HTTP/1.1 200 OK\r\n"), "{r}");
        assert!(r.ends_with("\r\n\r\nok\n"), "{r}");
        assert!(t.elapsed() < Duration::from_millis(500));
        let r = get(addr, b"\xff\xfe HTTP/1.1\r\n\r\n");
        assert!(r.starts_with("HTTP/1.1 400 "), "{r}");
        drop(idle);
    }
}
