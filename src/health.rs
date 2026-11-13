//! A tiny HTTP health endpoint for orchestrators (readiness/liveness
//! probes): `GET /healthz` -> `ok`. Nothing else is served. Meant for the
//! internal network only.
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

/// Binds `listen` and serves the health endpoint on background threads.
/// Returns the bound address.
pub fn spawn(listen: &str) -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind(listen)?;
    let addr = listener.local_addr()?;
    std::thread::Builder::new()
        .name("health".into())
        .spawn(move || serve(listener))?;
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

fn serve(listener: TcpListener) {
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
                    eprintln!("health: accept: {e}");
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
        // If the thread cannot start, the closure (and with it the slot and
        // the stream) is dropped.
        let _ = std::thread::Builder::new()
            .name("health-conn".into())
            .spawn(move || {
                let _slot = slot;
                let _ = handle(stream);
            });
    }
}

fn handle(mut stream: TcpStream) -> std::io::Result<()> {
    let deadline = Instant::now() + DEADLINE;
    let (status, body) = match read_head(&mut stream, deadline)? {
        Some(head) => route(&head),
        None => bad_request(),
    };
    stream.set_write_timeout(Some(remaining(deadline)?))?;
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
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
        let want = buf.len().min(MAX_HEAD.saturating_sub(head.len()));
        match stream.read(buf.get_mut(..want).unwrap_or_default()) {
            Ok(0) => break,
            Ok(n) => head.extend_from_slice(buf.get(..n).unwrap_or_default()),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(Some(head))
}

/// Where the head ends (after the blank line), if it is complete.
fn head_end(b: &[u8]) -> Option<usize> {
    (0..b.len()).find_map(|i| {
        let rest = b.get(i..)?;
        if rest.starts_with(b"\r\n\r\n") {
            Some(i + 4)
        } else if rest.starts_with(b"\n\n") {
            Some(i + 2)
        } else {
            None
        }
    })
}

type Response = (&'static str, &'static str);

fn bad_request() -> Response {
    ("400 Bad Request", "bad request\n")
}

/// The answer to a request head: (status, plain-text body).
fn route(head: &[u8]) -> Response {
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
        ("GET", "/healthz") => ("200 OK", "ok\n"),
        ("GET", _) => ("404 Not Found", "not found\n"),
        _ => ("405 Method Not Allowed", "method not allowed\n"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes() {
        let status = |head: &[u8]| route(head).0;
        assert_eq!(
            status(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n"),
            "200 OK"
        );
        assert_eq!(status(b"GET /healthz?x=1 HTTP/1.0\n\n"), "200 OK");
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
        let addr = spawn("127.0.0.1:0").unwrap();
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
