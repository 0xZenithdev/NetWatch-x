//! The HTTP server: a handful of routes, no framework, no dependencies.
//!
//! It is deliberately small. A monitor should not need a web stack, and every
//! line here is a line that has to keep working on a headless box at three in
//! the morning.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::api;
use crate::devices;
use crate::state::{State, now_unix};
use crate::store;

pub const DASHBOARD: &str = include_str!("../assets/index.html");
pub const STYLE: &str = include_str!("../assets/app.css");
pub const SCRIPT: &str = include_str!("../assets/app.js");
pub const GLOSSARY: &str = include_str!("../assets/glossary.json");

/// A body larger than this is not an edit, it is an attack or a mistake.
const MAX_BODY: usize = 8 * 1024;
/// A client that cannot finish a request in this long is not a client.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Query parameters, kept as pairs because there are never enough of them to
/// justify a hash map.
pub struct Query {
    pairs: Vec<(String, String)>,
}

impl Query {
    #[must_use]
    pub fn parse(target: &str) -> Self {
        let pairs = target
            .split_once('?')
            .map(|(_, rest)| {
                rest.split('&')
                    .filter_map(|pair| pair.split_once('='))
                    .map(|(k, v)| (decode(k), decode(v)))
                    .collect()
            })
            .unwrap_or_default();
        Self { pairs }
    }

    /// Build a query from known-good pairs, for internal callers.
    #[must_use]
    pub fn of(pairs: &[(&str, &str)]) -> Self {
        Self {
            pairs: pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        }
    }

    #[must_use]
    pub fn get(&self, key: &str) -> Option<String> {
        self.pairs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .filter(|v| !v.is_empty())
    }

    #[must_use]
    pub fn get_usize(&self, key: &str) -> Option<usize> {
        self.get(key).and_then(|v| v.parse().ok())
    }
}

/// Percent-decoding, because a search box will eventually contain a space.
fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    out.push(byte);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

struct Request {
    method: String,
    path: String,
    query: Query,
    body: String,
}

struct Response {
    code: &'static str,
    ctype: &'static str,
    body: String,
    /// Extra headers, e.g. the download filename for an export.
    extra: String,
}

impl Response {
    fn ok(ctype: &'static str, body: String) -> Self {
        Self {
            code: "200 OK",
            ctype,
            body,
            extra: String::new(),
        }
    }
    fn json(body: String) -> Self {
        Self::ok("application/json", body)
    }
    fn not_found() -> Self {
        Self {
            code: "404 Not Found",
            ctype: "text/plain",
            body: "not found\n".into(),
            extra: String::new(),
        }
    }
    fn bad_request(detail: &str) -> Self {
        Self {
            code: "400 Bad Request",
            ctype: "application/json",
            body: serde_json::json!({ "ok": false, "error": detail }).to_string(),
            extra: String::new(),
        }
    }
    /// Something failed on our side. Reported as a 500 rather than a 400,
    /// because the request was fine.
    fn server_error(detail: &str) -> Self {
        Self {
            code: "500 Internal Server Error",
            ctype: "application/json",
            body: serde_json::json!({ "ok": false, "error": detail }).to_string(),
            extra: String::new(),
        }
    }
}

pub fn http_loop(listener: &TcpListener, state: &Arc<Mutex<State>>) {
    // a failed accept is not fatal: skip it and keep serving
    for stream in listener.incoming().flatten() {
        // each connection gets its own handle on the shared state
        let st = state.clone();
        std::thread::spawn(move || handle(stream, &st));
    }
}

fn read_request(stream: &TcpStream) -> Option<Request> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return None;
    }
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let mut length = 0usize;
    loop {
        let mut header = String::new();
        match reader.read_line(&mut header) {
            Ok(0) | Err(_) => break,
            Ok(_) if header == "\r\n" || header == "\n" => break,
            Ok(_) => {
                if let Some(value) = header.to_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap_or(0);
                }
            }
        }
    }
    let mut body = String::new();
    if length > 0 {
        if length > MAX_BODY {
            return None;
        }
        let mut buffer = vec![0u8; length];
        reader.read_exact(&mut buffer).ok()?;
        body = String::from_utf8_lossy(&buffer).to_string();
    }
    let path = target.split('?').next().unwrap_or("/").to_string();
    Some(Request {
        method,
        path,
        query: Query::parse(&target),
        body,
    })
}

fn handle(mut stream: TcpStream, state: &Arc<Mutex<State>>) {
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(READ_TIMEOUT));
    let Some(request) = read_request(&stream) else {
        return;
    };
    let response = route(&request, state);
    let head = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\nConnection: close\r\n{}\r\n",
        response.code,
        response.ctype,
        response.body.len(),
        response.extra
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(response.body.as_bytes());
    let _ = stream.flush();
}

fn route(request: &Request, state: &Arc<Mutex<State>>) -> Response {
    let get = request.method == "GET";
    let some_write = matches!(request.method.as_str(), "PUT" | "POST" | "PATCH");
    match (get, some_write, request.path.as_str()) {
        (true, _, "/" | "/index.html") => {
            Response::ok("text/html; charset=utf-8", DASHBOARD.to_string())
        }
        (true, _, "/app.css") => Response::ok("text/css; charset=utf-8", STYLE.to_string()),
        (true, _, "/app.js") => {
            Response::ok("application/javascript; charset=utf-8", SCRIPT.to_string())
        }
        (true, _, "/healthz") => Response::ok("text/plain", "ok\n".to_string()),
        (true, _, "/favicon.ico") => Response {
            code: "204 No Content",
            ctype: "image/x-icon",
            body: String::new(),
            extra: String::new(),
        },
        (_, _, path) if path.starts_with("/api/") => route_api(request, state),
        _ => Response::not_found(),
    }
}

fn route_api(request: &Request, state: &Arc<Mutex<State>>) -> Response {
    let Ok(s) = state.lock() else {
        return Response::bad_request("state unavailable");
    };
    let now = now_unix();
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/api/summary") => Response::json(api::summary_json(&s, now)),
        ("GET", "/api/stats") => Response::json(api::stats_json(&s, now)),
        ("GET", "/api/devices") => Response::json(api::devices_json(&s, now)),
        ("GET", "/api/flows") => Response::json(api::flows_json(&s, &request.query)),
        ("GET", "/api/alerts") => Response::json(api::alerts_json(&s, &request.query)),
        ("GET", "/api/glossary") => Response::json(api::glossary_json()),
        ("GET", "/api/history") => {
            let days = u64::try_from(request.query.get_usize("days").unwrap_or(30))
                .unwrap_or(30)
                .clamp(1, 400);
            history_response(&s, days, now)
        }
        ("GET", "/api/export") => {
            let (ctype, name, body) = api::export(&s, &request.query, now);
            Response {
                code: "200 OK",
                ctype: leak_ctype(&ctype),
                body,
                extra: format!("Content-Disposition: attachment; filename=\"{name}\"\r\n"),
            }
        }
        ("GET", path) if path.starts_with("/api/devices/") => {
            // The history database is a second lock, taken while the state lock
            // is held. Every path takes them in this order, so there is no way
            // for two threads to disagree about which comes first.
            let hist = s.history.as_ref().and_then(|h| h.lock().ok());
            match api::device_json(&s, &path["/api/devices/".len()..], now, hist.as_deref()) {
                Some(body) => Response::json(body),
                None => Response::not_found(),
            }
        }
        (_, path)
            if path.starts_with("/api/devices/")
                && matches!(request.method.as_str(), "PUT" | "POST" | "PATCH") =>
        {
            drop(s);
            edit_device(state, &path["/api/devices/".len()..], &request.body)
        }
        _ => Response::not_found(),
    }
}

/// Interning the content type keeps [`Response`] free of lifetimes; the set of
/// possible values is tiny and fixed.
fn leak_ctype(ctype: &str) -> &'static str {
    match ctype {
        "application/json" => "application/json",
        _ => "text/csv; charset=utf-8",
    }
}

/// `PUT /api/devices/<mac>` — the operator naming a device.
/// `GET /api/history`, with an honest answer when retention is switched off
/// rather than an empty chart that looks like "nothing ever happened".
fn history_response(s: &State, days: u64, now: u64) -> Response {
    let Some(hist) = &s.history else {
        return Response::json(
            serde_json::json!({
                "ok": true,
                "generated_at": now,
                "window_days": 0,
                "keep_days": 0,
                "file_bytes": 0,
                "file_human": "0 B",
                "off": true,
                "network": [],
                "uptime": [],
            })
            .to_string(),
        );
    };
    match hist.lock() {
        Ok(h) => Response::json(api::history_json(s, &h, days, now)),
        Err(_) => Response::server_error("the history database is unavailable"),
    }
}

fn edit_device(state: &Arc<Mutex<State>>, mac_text: &str, body: &str) -> Response {
    let Some(mac) = devices::parse_mac(mac_text) else {
        return Response::bad_request("that is not a hardware address");
    };
    let Ok(payload) = serde_json::from_str::<serde_json::Value>(body) else {
        return Response::bad_request("the request body is not valid JSON");
    };
    let text = |key: &str| {
        payload
            .get(key)
            .and_then(|v| v.as_str())
            .map(ToString::to_string)
    };
    let edit = devices::Edit {
        name: Some(text("name").unwrap_or_default()),
        kind: text("kind"),
        trust: text("trust"),
        notes: text("notes"),
        quota_gb: text("quota_gb"),
        notify: text("notify"),
    };
    let Ok(mut s) = state.lock() else {
        return Response::bad_request("state unavailable");
    };
    // An empty string means "clear the field", which is different from omitting
    // it — the dashboard sends the whole editable set every time.
    let mut edit = edit;
    if payload.get("name").is_none() {
        edit.name = None;
    }
    if payload.get("notes").is_none() {
        edit.notes = None;
    }
    match devices::apply_edit(&mut s, mac, &edit) {
        Ok(()) => {
            // Write the edit out now rather than waiting for the next periodic
            // save: an operator who renames a device and then restarts the
            // daemon expects the name to still be there, and "you named it four
            // minutes too early" is an unforgivable way to lose it.
            if let Some(path) = s.device_store.clone() {
                match store::save_devices(&path, &s) {
                    Ok(()) => s.dirty = false,
                    // The edit is applied in memory either way; say so rather
                    // than reporting success for a write that failed.
                    Err(e) => eprintln!("could not save the device inventory: {e}"),
                }
            }
            let hist = s.history.as_ref().and_then(|h| h.lock().ok());
            let now = now_unix();
            match api::device_json(&s, mac_text, now, hist.as_deref()) {
                Some(body) => Response::json(body),
                None => Response::not_found(),
            }
        }
        Err(detail) => Response::bad_request(&detail),
    }
}
