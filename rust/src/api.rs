//! Request plumbing and tolerant response parsing shared by the service modules.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde_json::{Map, Value};

use crate::core::{parse_duration, Error, ErrorCode, Method, Result, Secret};

/// Characters kept as-is in a path segment (RFC 3986 unreserved plus `:` and `@`).
const SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~')
    .remove(b':')
    .remove(b'@');

/// Content type required by KV v2 `PATCH`.
pub(crate) const MERGE_PATCH: &str = "application/merge-patch+json";

/// One OpenBao API call; `path` is relative to `/v1/`.
#[derive(Debug, Clone)]
pub(crate) struct ApiRequest {
    pub method: Method,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub body: Option<Value>,
    pub content_type: Option<&'static str>,
    pub op: String,
    /// Sends no `X-Vault-Token` (login and unauthenticated system endpoints).
    pub no_auth: bool,
    /// Overrides the client token for this call (unwrap).
    pub token: Option<Secret>,
    /// Asks the server to wrap the response (`X-Vault-Wrap-TTL`).
    pub wrap_ttl: Option<Duration>,
    /// Statuses returned as responses instead of errors.
    pub ok_statuses: Vec<u16>,
    /// Overrides whether the request may be replayed after an uncertain send.
    pub idempotent: Option<bool>,
}

impl ApiRequest {
    pub fn new(method: Method, path: impl Into<String>, op: impl Into<String>) -> Self {
        ApiRequest {
            method,
            path: path.into(),
            query: Vec::new(),
            body: None,
            content_type: None,
            op: op.into(),
            no_auth: false,
            token: None,
            wrap_ttl: None,
            ok_statuses: Vec::new(),
            idempotent: None,
        }
    }
    pub fn get(path: impl Into<String>, op: impl Into<String>) -> Self {
        Self::new(Method::GET, path, op)
    }
    pub fn post(path: impl Into<String>, op: impl Into<String>) -> Self {
        Self::new(Method::POST, path, op)
    }
    pub fn put(path: impl Into<String>, op: impl Into<String>) -> Self {
        Self::new(Method::PUT, path, op)
    }
    pub fn delete(path: impl Into<String>, op: impl Into<String>) -> Self {
        Self::new(Method::DELETE, path, op)
    }
    pub fn patch(path: impl Into<String>, op: impl Into<String>) -> Self {
        Self::new(Method::PATCH, path, op)
    }
    pub fn json(mut self, body: Value) -> Self {
        self.body = Some(body);
        self
    }
    pub fn content_type(mut self, content_type: &'static str) -> Self {
        self.content_type = Some(content_type);
        self
    }
    pub fn query(mut self, name: &str, value: impl Into<String>) -> Self {
        self.query.push((name.to_owned(), value.into()));
        self
    }
    pub fn no_auth(mut self) -> Self {
        self.no_auth = true;
        self
    }
    pub fn token(mut self, token: Secret) -> Self {
        self.token = Some(token);
        self
    }
    pub fn wrap_ttl(mut self, ttl: Duration) -> Self {
        self.wrap_ttl = Some(ttl);
        self
    }
    pub fn idempotent(mut self, idempotent: bool) -> Self {
        self.idempotent = Some(idempotent);
        self
    }
    pub fn ok_status(mut self, status: u16) -> Self {
        self.ok_statuses.push(status);
        self
    }
}

/// The standard OpenBao response envelope.
#[derive(Debug, Clone, Default)]
pub(crate) struct Envelope {
    pub request_id: String,
    pub lease_id: String,
    pub renewable: bool,
    pub lease_duration: Duration,
    pub data: Value,
    pub wrap_info: Value,
    pub warnings: Vec<String>,
    pub auth: Value,
}

impl Envelope {
    pub fn parse(body: &[u8], op: &str) -> Result<Envelope> {
        if body.iter().all(u8::is_ascii_whitespace) {
            return Ok(Envelope {
                data: Value::Null,
                wrap_info: Value::Null,
                auth: Value::Null,
                ..Envelope::default()
            });
        }
        let v: Value = serde_json::from_slice(body)
            .map_err(|_| Error::unavailable(format!("{op}: response is not valid JSON")))?;
        Ok(Envelope {
            request_id: s(&v, "request_id"),
            lease_id: s(&v, "lease_id"),
            renewable: b(&v, "renewable"),
            lease_duration: secs(&v, "lease_duration"),
            data: v.get("data").cloned().unwrap_or(Value::Null),
            wrap_info: v.get("wrap_info").cloned().unwrap_or(Value::Null),
            warnings: strings(&v, "warnings"),
            auth: v.get("auth").cloned().unwrap_or(Value::Null),
        })
    }
}

/// Applies the OpenBao-specific refinements on top of the SPEC §2.1 status mapping:
///
/// - 403 with the plain `permission denied` body (missing, invalid, expired or revoked token)
///   or a message naming an invalid/missing token is `AUTHENTICATION`; a policy denial
///   (`1 error occurred: * permission denied`) stays `PERMISSION_DENIED`.
/// - 400 `check-and-set parameter did not match` is `CONFLICT`.
/// - 405 (operation not supported on the path, e.g. `PATCH` on KV v1) is `UNSUPPORTED`.
/// - 501 (server not initialised) is `UNAVAILABLE`.
pub(crate) fn map_error(err: Error) -> Error {
    let Some(status) = err.http_status() else {
        return err;
    };
    let msg = err.message().to_ascii_lowercase();
    let code = match status {
        403 if is_auth_failure(&msg) => ErrorCode::Authentication,
        400 if msg.contains("check-and-set parameter did not match") => ErrorCode::Conflict,
        405 => ErrorCode::Unsupported,
        501 => ErrorCode::Unavailable,
        _ => return err,
    };
    recode(&err, code)
}

/// Maps 400/401/403 from a login endpoint to `AUTHENTICATION`: the credentials were
/// rejected (DECISIONS §7, the same in every language).
pub(crate) fn login_error(err: Error) -> Error {
    match err.http_status() {
        Some(400 | 401 | 403) if err.code() != ErrorCode::Authentication => {
            recode(&err, ErrorCode::Authentication)
        }
        _ => err,
    }
}

/// A copy of `err` with another code (status, request id and `Retry-After` kept).
pub(crate) fn recode(err: &Error, code: ErrorCode) -> Error {
    let mut out = Error::new(code, err.message());
    if let Some(status) = err.http_status() {
        out = out.with_status(status);
    }
    if let Some(id) = err.request_id() {
        out = out.with_request_id(id);
    }
    if let Some(ra) = err.retry_after() {
        out = out.with_retry_after(ra);
    }
    out
}

fn is_auth_failure(msg: &str) -> bool {
    const PHRASES: [&str; 4] = [
        "invalid token",
        "token not found",
        "missing client token",
        "bad token",
    ];
    PHRASES.iter().any(|p| msg.contains(p))
        || (msg.ends_with(": permission denied (http 403)") && !msg.contains("error occurred"))
}

/// `VALIDATION` error `"<op>: <reason>"`.
pub(crate) fn invalid(op: &str, reason: &str) -> Error {
    Error::validation(format!("{op}: {reason}"))
}

/// `VALIDATION` error when `value` is blank.
pub(crate) fn require_arg(op: &str, name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(invalid(op, &format!("{name} is required")));
    }
    Ok(())
}

/// Percent-encodes every segment of `path` and keeps `/` separators; empty segments and
/// surrounding slashes are dropped.
pub(crate) fn encode_path(path: &str) -> String {
    path.split('/')
        .filter(|seg| !seg.is_empty())
        .map(|seg| utf8_percent_encode(seg, SEGMENT).to_string())
        .collect::<Vec<_>>()
        .join("/")
}

/// Joins path parts with `/`, dropping empty parts and surrounding slashes (no encoding).
pub(crate) fn join(parts: &[&str]) -> String {
    parts
        .iter()
        .map(|p| p.trim_matches('/'))
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("/")
}

/// `mount` without slashes, or `default` when empty.
pub(crate) fn mount_or(mount: &str, default: &str) -> String {
    match mount.trim_matches('/') {
        "" => default.to_owned(),
        m => m.to_owned(),
    }
}

/// Renders a duration as whole seconds (`"90s"`); sub-second remainders round up.
pub(crate) fn duration_string(d: Duration) -> String {
    let mut secs = d.as_secs();
    if d.subsec_nanos() > 0 {
        secs += 1;
    }
    format!("{secs}s")
}

/// Standard base64.
pub(crate) fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Decodes standard base64 (`UNAVAILABLE` naming `what` when the server sent garbage).
pub(crate) fn unb64(text: &str, op: &str, what: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|_| Error::unavailable(format!("{op}: {what} in the response is not base64")))
}

/// An empty JSON object.
pub(crate) fn obj() -> Map<String, Value> {
    Map::new()
}

// --- tolerant field readers -------------------------------------------------

/// String field (numbers and booleans are rendered; missing/null → `""`).
pub(crate) fn s(v: &Value, key: &str) -> String {
    match v.get(key) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

/// Unsigned integer field (numbers or numeric strings; otherwise 0).
pub(crate) fn u(v: &Value, key: &str) -> u64 {
    match v.get(key) {
        Some(Value::Number(n)) => n
            .as_u64()
            .or_else(|| n.as_f64().filter(|f| *f >= 0.0).map(|f| f as u64))
            .unwrap_or(0),
        Some(Value::String(s)) => s.trim().parse().unwrap_or(0),
        _ => 0,
    }
}

/// Boolean field (`true` or the string `"true"`).
pub(crate) fn b(v: &Value, key: &str) -> bool {
    match v.get(key) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

/// List of strings (non-strings skipped; missing/null → empty). A single string is split
/// on commas (OpenBao echoes some list fields as comma text).
pub(crate) fn strings(v: &Value, key: &str) -> Vec<String> {
    match v.get(key) {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|i| i.as_str().map(str::to_owned))
            .collect(),
        Some(Value::String(s)) if !s.is_empty() => s.split(',').map(str::to_owned).collect(),
        _ => Vec::new(),
    }
}

/// Map of strings (non-string values JSON-encoded, null → `""`; missing → empty).
pub(crate) fn smap(v: &Value, key: &str) -> BTreeMap<String, String> {
    match v.get(key) {
        Some(Value::Object(m)) => m
            .iter()
            .map(|(k, v)| {
                let text = match v {
                    Value::String(s) => s.clone(),
                    Value::Null => String::new(),
                    other => other.to_string(),
                };
                (k.clone(), text)
            })
            .collect(),
        _ => BTreeMap::new(),
    }
}

/// Duration field: integer seconds or a Go duration string (`"720h0m0s"`).
pub(crate) fn secs(v: &Value, key: &str) -> Duration {
    match v.get(key) {
        Some(Value::Number(n)) => Duration::from_secs(n.as_u64().unwrap_or(0)),
        Some(Value::String(s)) => {
            let t = s.trim();
            if t.bytes().all(|c| c.is_ascii_digit()) && !t.is_empty() {
                Duration::from_secs(t.parse().unwrap_or(0))
            } else {
                parse_duration(t).unwrap_or_default()
            }
        }
        _ => Duration::ZERO,
    }
}

/// Timestamp field: RFC 3339 text or unix seconds; empty, `0` and null → `None`.
pub(crate) fn time(v: &Value, key: &str) -> Option<SystemTime> {
    match v.get(key)? {
        Value::Number(n) => {
            let secs = n.as_u64().filter(|s| *s > 0)?;
            Some(UNIX_EPOCH + Duration::from_secs(secs))
        }
        Value::String(s) => {
            let t = s.trim();
            if t.is_empty() || t == "0" {
                return None;
            }
            if t.bytes().all(|c| c.is_ascii_digit()) {
                return Some(UNIX_EPOCH + Duration::from_secs(t.parse().ok()?));
            }
            parse_rfc3339(t)
        }
        _ => None,
    }
}

/// Parses an RFC 3339 timestamp (`2026-11-18T19:30:00.123456789Z`, offsets allowed).
pub(crate) fn parse_rfc3339(text: &str) -> Option<SystemTime> {
    let bytes = text.as_bytes();
    if bytes.len() < 20 || bytes[4] != b'-' || bytes[7] != b'-' || bytes[13] != b':' {
        return None;
    }
    let num = |a: usize, b: usize| -> Option<i64> { text.get(a..b)?.parse().ok() };
    let (year, month, day) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (hour, min, sec) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    let mut rest = &text[19..];
    let mut nanos: u64 = 0;
    if let Some(frac) = rest.strip_prefix('.') {
        let digits = frac.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        let mut scaled = frac[..digits.min(9)].to_owned();
        while scaled.len() < 9 {
            scaled.push('0');
        }
        nanos = scaled.parse().ok()?;
        rest = &frac[digits..];
    }
    let offset_secs: i64 = match rest {
        "Z" | "z" => 0,
        _ if rest.len() == 6 && (rest.starts_with('+') || rest.starts_with('-')) => {
            let h: i64 = rest.get(1..3)?.parse().ok()?;
            let m: i64 = rest.get(4..6)?.parse().ok()?;
            let sign = if rest.starts_with('-') { -1 } else { 1 };
            sign * (h * 3600 + m * 60)
        }
        _ => return None,
    };
    // Days from civil (Howard Hinnant).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let total = days * 86_400 + hour * 3600 + min * 60 + sec - offset_secs;
    if total < 0 {
        return None;
    }
    Some(UNIX_EPOCH + Duration::from_secs(total as u64) + Duration::from_nanos(nanos))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rfc3339_parsing() {
        let t = parse_rfc3339("1970-01-02T00:00:01.5Z").unwrap();
        assert_eq!(
            t.duration_since(UNIX_EPOCH).unwrap(),
            Duration::from_millis(86_401_500)
        );
        let t = parse_rfc3339("2026-11-18T19:30:00.123456789123+01:00").unwrap();
        let z = parse_rfc3339("2026-11-18T18:30:00.123456789Z").unwrap();
        assert_eq!(t, z);
        let neg = parse_rfc3339("2026-11-18T18:30:00-00:30").unwrap();
        assert_eq!(neg.duration_since(z).unwrap().as_secs(), 1799);
        for bad in [
            "",
            "2026-11-18",
            "2026/11/18T18:30:00Z",
            "2026-13-18T18:30:00Z",
            "2026-11-18T18:30:00.Z",
            "2026-11-18T18:30:00+0100",
            "2026-11-18T18:30:00",
            "1900-01-01T00:00:00Z",
        ] {
            assert!(parse_rfc3339(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn field_readers() {
        let v = json!({
            "s": "x", "n": 5, "f": 2.7, "neg": -1.0, "t": true, "ts": "TRUE", "ns": "7",
            "list": ["a", 1, "b"], "csv": "a,b", "m": {"a": "1", "b": 2, "c": null},
            "d1": 30, "d2": "720h0m0s", "d3": "45", "d4": "bogus",
            "t1": 86400, "t2": "1970-01-02T00:00:00Z", "t3": "", "t4": "0", "t5": "86400", "t6": 0
        });
        assert_eq!(s(&v, "s"), "x");
        assert_eq!(s(&v, "n"), "5");
        assert_eq!(s(&v, "t"), "true");
        assert_eq!(s(&v, "missing"), "");
        assert_eq!(u(&v, "n"), 5);
        assert_eq!(u(&v, "f"), 2);
        assert_eq!(u(&v, "neg"), 0);
        assert_eq!(u(&v, "ns"), 7);
        assert_eq!(u(&v, "t"), 0);
        assert!(b(&v, "t") && b(&v, "ts") && !b(&v, "n"));
        assert_eq!(strings(&v, "list"), vec!["a", "b"]);
        assert_eq!(strings(&v, "csv"), vec!["a", "b"]);
        assert!(strings(&v, "n").is_empty());
        let m = smap(&v, "m");
        assert_eq!(
            (m["a"].as_str(), m["b"].as_str(), m["c"].as_str()),
            ("1", "2", "")
        );
        assert!(smap(&v, "s").is_empty());
        assert_eq!(secs(&v, "d1"), Duration::from_secs(30));
        assert_eq!(secs(&v, "d2"), Duration::from_secs(720 * 3600));
        assert_eq!(secs(&v, "d3"), Duration::from_secs(45));
        assert_eq!(secs(&v, "d4"), Duration::ZERO);
        assert_eq!(secs(&v, "t"), Duration::ZERO);
        let day = UNIX_EPOCH + Duration::from_secs(86_400);
        assert_eq!(time(&v, "t1"), Some(day));
        assert_eq!(time(&v, "t2"), Some(day));
        assert_eq!(time(&v, "t3"), None);
        assert_eq!(time(&v, "t4"), None);
        assert_eq!(time(&v, "t5"), Some(day));
        assert_eq!(time(&v, "t6"), None);
        assert_eq!(time(&v, "t"), None);
    }

    #[test]
    fn helpers() {
        assert_eq!(
            encode_path("/a b//c?d/%/aa:bb@x"),
            "a%20b/c%3Fd/%25/aa:bb@x"
        );
        assert_eq!(join(&["/m/", "", "data", "x/y/"]), "m/data/x/y");
        assert_eq!(mount_or("/", "kv"), "kv");
        assert_eq!(mount_or("/x/", "kv"), "x");
        assert_eq!(duration_string(Duration::from_millis(1500)), "2s");
        assert_eq!(duration_string(Duration::from_secs(60)), "60s");
        assert_eq!(unb64(&b64(b"hi"), "op", "x").unwrap(), b"hi");
        assert_eq!(
            unb64("!!", "op", "x").unwrap_err().code(),
            ErrorCode::Unavailable
        );
        assert!(require_arg("op", "name", " ").is_err());
        assert!(require_arg("op", "name", "x").is_ok());
        assert!(obj().is_empty());
        let e = Envelope::parse(b"  ", "op").unwrap();
        assert!(e.data.is_null() && e.auth.is_null());
        assert_eq!(
            Envelope::parse(b"{", "op").unwrap_err().code(),
            ErrorCode::Unavailable
        );
    }

    #[test]
    fn error_mapping() {
        let plain = Error::from_status(403, "x: permission denied: permission denied (HTTP 403)")
            .with_request_id("r1")
            .with_retry_after(Duration::from_secs(1));
        let mapped = map_error(plain);
        assert_eq!(mapped.code(), ErrorCode::Authentication);
        assert_eq!(mapped.http_status(), Some(403));
        assert_eq!(mapped.request_id(), Some("r1"));
        assert_eq!(mapped.retry_after(), Some(Duration::from_secs(1)));
        let wrapped = Error::from_status(
            403,
            "x: permission denied: 1 error occurred: * permission denied (HTTP 403)",
        );
        assert_eq!(map_error(wrapped).code(), ErrorCode::PermissionDenied);
        let named = Error::from_status(403, "x: permission denied: invalid token (HTTP 403)");
        assert_eq!(map_error(named).code(), ErrorCode::Authentication);
        let cas = Error::from_status(
            400,
            "x: invalid request: check-and-set parameter did not match the current version (HTTP 400)",
        );
        assert_eq!(map_error(cas).code(), ErrorCode::Conflict);
        let other400 = Error::from_status(400, "x: invalid request: nope (HTTP 400)");
        assert_eq!(map_error(other400).code(), ErrorCode::Validation);
        assert_eq!(
            map_error(Error::from_status(405, "x")).code(),
            ErrorCode::Unsupported
        );
        let login = login_error(Error::from_status(
            400,
            "x: invalid role or secret ID (HTTP 400)",
        ));
        assert_eq!(login.code(), ErrorCode::Authentication);
        assert_eq!(login.http_status(), Some(400));
        assert_eq!(
            login_error(Error::from_status(401, "x")).code(),
            ErrorCode::Authentication
        );
        let wrapped403 = login_error(Error::from_status(
            403,
            "x: permission denied: 1 error occurred: * permission denied (HTTP 403)",
        ));
        assert_eq!(wrapped403.code(), ErrorCode::Authentication);
        assert_eq!(
            login_error(Error::from_status(500, "x")).code(),
            ErrorCode::Unavailable
        );
        assert_eq!(login_error(Error::timeout("t")).code(), ErrorCode::Timeout);
        let e501 = map_error(Error::from_status(501, "x"));
        assert_eq!(e501.code(), ErrorCode::Unavailable);
        assert!(e501.is_retryable());
        assert_eq!(
            map_error(Error::from_status(404, "x")).code(),
            ErrorCode::NotFound
        );
        assert_eq!(map_error(Error::timeout("t")).code(), ErrorCode::Timeout);
    }
}
