//! VideoVault staff lock (hq#595): only staff may start a connection to a peer.
//!
//! A staff client puts a token from Central in the `token` field of PunchHoleRequest and
//! RequestRelay (stock RustDesk fills it from the local option `access_token`):
//!
//!   vvst1.<exp_unix>.<who>.<hex hmac_sha256(key = S, msg = "vvst1.<exp_unix>.<who>")>
//!
//! S is the shared staff secret (64 hex chars, used as ASCII bytes), `who` matches
//! [a-z0-9@._-]{1,64}, and the token is valid while now < exp <= now + 12 h.
//!
//! Environment: VV_STAFF_MODE = off | log | enforce (default off), VV_STAFF_SECRET = S.
//! `log` checks and logs every request but lets it through; `enforce` refuses a request
//! without a valid token the way hbbs answers for an offline peer. Peers registering and
//! accepting are never checked.

use hbb_common::log;
use once_cell::sync::Lazy;
use sodiumoxide::crypto::hash::sha256;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

const PREFIX: &str = "vvst1";
/// A token may live at most 12 hours.
pub const MAX_TTL_SECS: u64 = 43_200;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Off,
    Log,
    Enforce,
}

impl Mode {
    fn parse(v: &str) -> Mode {
        match v.trim().to_ascii_lowercase().as_str() {
            "" | "off" => Mode::Off,
            "log" => Mode::Log,
            "enforce" => Mode::Enforce,
            // A typo must not open the server: anything else locks it.
            _ => Mode::Enforce,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Mode::Off => "off",
            Mode::Log => "log",
            Mode::Enforce => "enforce",
        }
    }
}

struct Settings {
    mode: Mode,
    secret: Vec<u8>,
}

static SETTINGS: Lazy<Settings> = Lazy::new(|| Settings {
    mode: Mode::parse(&std::env::var("VV_STAFF_MODE").unwrap_or_default()),
    secret: std::env::var("VV_STAFF_SECRET")
        .unwrap_or_default()
        .trim()
        .as_bytes()
        .to_vec(),
});

/// Logs the mode once at start, and whether a secret is set (never the secret).
pub fn announce() {
    let s = &*SETTINGS;
    // Worded without "secret=" or "token=", which log viewers mask (ssh-nas, logs gateway).
    log::info!(
        "staff-lock: mode={}, staff secret {}",
        s.mode.name(),
        if s.secret.is_empty() { "missing" } else { "present" }
    );
    if s.mode != Mode::Off && s.secret.len() < 32 {
        log::error!(
            "staff-lock: VV_STAFF_SECRET is missing or shorter than 32 characters; every token is invalid"
        );
    }
}

/// HMAC-SHA256 (RFC 2104) on libsodium's SHA-256, for any key length.
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&sha256::hash(key).0);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(BLOCK + msg.len());
    inner.extend(k.iter().map(|b| b ^ 0x36));
    inner.extend_from_slice(msg);
    let ih = sha256::hash(&inner).0;
    let mut outer = Vec::with_capacity(BLOCK + 32);
    outer.extend(k.iter().map(|b| b ^ 0x5c));
    outer.extend_from_slice(&ih);
    sha256::hash(&outer).0
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn valid_who(who: &str) -> bool {
    !who.is_empty()
        && who.len() <= 64
        && who
            .bytes()
            .all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'@' | b'.' | b'_' | b'-'))
}

/// Checks a token. Ok(who) when valid, otherwise a short reason (safe to log).
pub fn verify(token: &str, secret: &[u8], now: u64) -> Result<String, &'static str> {
    if token.is_empty() {
        return Err("no token");
    }
    if secret.len() < 32 {
        return Err("no secret on server");
    }
    let rest = token
        .strip_prefix(PREFIX)
        .and_then(|r| r.strip_prefix('.'))
        .ok_or("bad format")?;
    // `who` may contain dots, so the exp is up to the first dot and the MAC after the last.
    let (exp, rest) = rest.split_once('.').ok_or("bad format")?;
    let (who, mac) = rest.rsplit_once('.').ok_or("bad format")?;
    if exp.is_empty() || exp.len() > 12 || !exp.bytes().all(|c| c.is_ascii_digit()) {
        return Err("bad format");
    }
    if !valid_who(who) {
        return Err("bad who");
    }
    if mac.len() != 64 {
        return Err("bad format");
    }
    let signed = &token[..token.len() - mac.len() - 1];
    let want = to_hex(&hmac_sha256(secret, signed.as_bytes()));
    if !ct_eq(want.as_bytes(), mac.to_ascii_lowercase().as_bytes()) {
        return Err("bad signature");
    }
    let exp: u64 = exp.parse().map_err(|_| "bad format")?;
    if exp <= now {
        return Err("expired");
    }
    if exp > now.saturating_add(MAX_TTL_SECS) {
        return Err("expiry too far ahead");
    }
    Ok(who.to_owned())
}

/// The `who` a token claims, for the log only (shown only when it is well formed).
fn claimed_who(token: &str) -> &str {
    token
        .strip_prefix("vvst1.")
        .and_then(|r| r.split_once('.'))
        .and_then(|(_, r)| r.rsplit_once('.'))
        .map(|(w, _)| w)
        .filter(|w| valid_who(w))
        .unwrap_or("-")
}

/// Decides whether a request from `addr` to start a connection to `peer_id` may go on,
/// and logs it. `kind` names the request (punch or relay). Never logs the token itself.
pub fn allow(kind: &str, addr: SocketAddr, peer_id: &str, token: &str) -> bool {
    let s = &*SETTINGS;
    if s.mode == Mode::Off {
        return true;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let peer: String = peer_id.chars().take(32).collect();
    match verify(token, &s.secret, now) {
        Ok(who) => {
            log::info!(
                "staff-lock: {} from {} to peer {} who={} check=ok mode={} -> allowed",
                kind, addr, peer, who, s.mode.name()
            );
            true
        }
        Err(reason) => {
            let allowed = s.mode == Mode::Log;
            log::warn!(
                "staff-lock: {} from {} to peer {} who={} check=failed ({}) mode={} -> {}",
                kind,
                addr,
                peer,
                claimed_who(token),
                reason,
                s.mode.name(),
                if allowed { "allowed" } else { "refused" }
            );
            allowed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn make(exp: u64, who: &str, secret: &str) -> String {
        let msg = format!("vvst1.{}.{}", exp, who);
        format!("{}.{}", msg, to_hex(&hmac_sha256(secret.as_bytes(), msg.as_bytes())))
    }

    #[test]
    fn hmac_rfc4231() {
        // RFC 4231 test case 1
        assert_eq!(
            to_hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        // RFC 4231 test case 6 (key longer than one block)
        assert_eq!(
            to_hex(&hmac_sha256(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn known_token_from_python() {
        // python3: hmac.new(S.encode(), b"vvst1.1800000000.claude@rnd", "sha256").hexdigest()
        let t = "vvst1.1800000000.claude@rnd.13a69b1100e438bda938b83c69c45b8ac06cc1da7c6c3accad74d3529ca0507c";
        assert_eq!(make(1_800_000_000, "claude@rnd", S), t);
        assert_eq!(verify(t, S.as_bytes(), 1_800_000_000 - 60), Ok("claude@rnd".into()));
    }

    #[test]
    fn valid_and_who_with_dots() {
        let now = 1_000_000;
        let t = make(now + 3600, "first.last@videovault.tech", S);
        assert_eq!(verify(&t, S.as_bytes(), now), Ok("first.last@videovault.tech".into()));
        // uppercase hex is the same MAC
        let (head, mac) = t.rsplit_once('.').unwrap();
        let upper = format!("{}.{}", head, mac.to_ascii_uppercase());
        assert!(verify(&upper, S.as_bytes(), now).is_ok());
    }

    #[test]
    fn expiry_window() {
        let now = 1_000_000;
        assert_eq!(verify(&make(now, "a", S), S.as_bytes(), now), Err("expired"));
        assert_eq!(verify(&make(now - 1, "a", S), S.as_bytes(), now), Err("expired"));
        assert!(verify(&make(now + 1, "a", S), S.as_bytes(), now).is_ok());
        assert!(verify(&make(now + MAX_TTL_SECS, "a", S), S.as_bytes(), now).is_ok());
        assert_eq!(
            verify(&make(now + MAX_TTL_SECS + 1, "a", S), S.as_bytes(), now),
            Err("expiry too far ahead")
        );
    }

    #[test]
    fn rejects_forgeries() {
        let now = 1_000_000;
        let other = "f".repeat(64);
        assert_eq!(verify(&make(now + 60, "a", &other), S.as_bytes(), now), Err("bad signature"));
        // changing who or exp breaks the MAC
        let t = make(now + 60, "alice", S);
        assert_eq!(verify(&t.replace("alice", "mallo"), S.as_bytes(), now), Err("bad signature"));
        let t2 = t.replacen(&(now + 60).to_string(), &(now + 61).to_string(), 1);
        assert_eq!(verify(&t2, S.as_bytes(), now), Err("bad signature"));
        assert_eq!(verify("", S.as_bytes(), now), Err("no token"));
        assert_eq!(verify("garbage", S.as_bytes(), now), Err("bad format"));
        assert_eq!(verify("vvst1.x.a.00", S.as_bytes(), now), Err("bad format"));
        assert_eq!(verify(&make(now + 60, "Alice", S), S.as_bytes(), now), Err("bad who"));
        assert_eq!(verify(&make(now + 60, &"a".repeat(65), S), S.as_bytes(), now), Err("bad who"));
        assert_eq!(verify(&make(now + 60, "", S), S.as_bytes(), now), Err("bad who"));
        assert_eq!(verify(&t, b"", now), Err("no secret on server"));
        // a stock RustDesk access token (no vvst1 prefix) is not a staff token
        assert_eq!(verify("eyJhbGciOiJIUzI1NiJ9.e30.x", S.as_bytes(), now), Err("bad format"));
    }

    #[test]
    fn mode_parse() {
        assert_eq!(Mode::parse(""), Mode::Off);
        assert_eq!(Mode::parse("off"), Mode::Off);
        assert_eq!(Mode::parse("LOG"), Mode::Log);
        assert_eq!(Mode::parse("enforce"), Mode::Enforce);
        assert_eq!(Mode::parse("enfroce"), Mode::Enforce);
    }

    #[test]
    fn claimed_who_only_when_well_formed() {
        assert_eq!(claimed_who(&make(1, "bob@x.y", S)), "bob@x.y");
        assert_eq!(claimed_who("vvst1.1.BAD WHO.ff"), "-");
        assert_eq!(claimed_who("junk"), "-");
    }
}
