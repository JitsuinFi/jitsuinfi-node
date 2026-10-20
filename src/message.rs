//! Relay messages from the node (HNK-23.T8): the same `JTSM` plaintext as the web app
//! (jitsuinfi-frontend `src/lib/relay-message.ts`), so a browser reads what the node sends and the
//! other way round.
//!
//! `"JTSM"` | version u8 (1) | header length u32 BE | header JSON | attachment bytes.
//! Signature: Ed25519 over `"JitsuinMsgSig_v1\n"` ‖ canonical JSON of the header without `sig`
//! (keys sorted at every level, no whitespace), by the financier key for the types it must sign.

// Building and signing messages (draft, sign, encode) serves the deal API (HNK-26.T5+).
#![allow(dead_code)]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub const MAGIC: &[u8; 4] = b"JTSM";
pub const VERSION: u8 = 1;
pub const MAX_HEADER: usize = 64 * 1024;
pub const MAX_ATTACHMENT: usize = 2 * 1024 * 1024;
pub const MAX_PLAINTEXT: usize = 9 + MAX_HEADER + 2 * MAX_ATTACHMENT;
const SIG_DOMAIN: &str = "JitsuinMsgSig_v1\n";

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// 10 bytes as 16 base32 characters in groups of 4 (fingerprints, pairing codes).
pub fn base32_groups(bytes: &[u8]) -> String {
    const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut bits, mut value, mut out) = (0u32, 0u32, String::new());
    for b in bytes {
        value = (value << 8) | u32::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((value >> bits) & 31) as usize] as char);
        }
    }
    out.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("-")
}

pub fn unhex<const N: usize>(s: &str) -> Result<[u8; N], String> {
    if s.len() != 2 * N
        || !s
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(format!("expected {} lowercase hex characters", 2 * N));
    }
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

/// JSON with keys sorted at every level and no whitespace, as `canonicalJson` in relay-message.ts.
pub fn canonical(v: &Value) -> String {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .iter()
                .map(|k| format!("{}:{}", Value::String((*k).clone()), canonical(&m[*k])))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(a) => format!(
            "[{}]",
            a.iter().map(canonical).collect::<Vec<_>>().join(",")
        ),
        other => other.to_string(),
    }
}

pub fn signing_bytes(header: &Value) -> Vec<u8> {
    let mut h = header.clone();
    if let Value::Object(m) = &mut h {
        m.remove("sig");
    }
    format!("{SIG_DOMAIN}{}", canonical(&h)).into_bytes()
}

/// Sets `signer` and `sig` on a complete header.
pub fn sign(header: &mut Value, key: &SigningKey) {
    let m = header.as_object_mut().expect("header is an object");
    m.remove("sig");
    m.insert(
        "signer".into(),
        Value::String(hex(&key.verifying_key().to_bytes())),
    );
    let sig = key.sign(&signing_bytes(header));
    header
        .as_object_mut()
        .unwrap()
        .insert("sig".into(), Value::String(hex(&sig.to_bytes())));
}

/// True when `sig` is a valid signature by `signer`, and `signer` is `expected` when given.
pub fn verify(header: &Value, expected: Option<&str>) -> bool {
    let (Some(signer), Some(sig)) = (header["signer"].as_str(), header["sig"].as_str()) else {
        return false;
    };
    if expected.is_some_and(|e| e != signer) {
        return false;
    }
    let (Ok(pk), Ok(sig)) = (unhex::<32>(signer), unhex::<64>(sig)) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
        return false;
    };
    vk.verify(&signing_bytes(header), &Signature::from_bytes(&sig))
        .is_ok()
}

pub struct File {
    pub name: String,
    pub bytes: Vec<u8>,
}

/// Header entries for `files` (name, PDF type, size, SHA-256).
pub fn describe(files: &[File]) -> Value {
    Value::Array(
        files
            .iter()
            .map(|f| serde_json::json!({ "name": f.name, "mime": "application/pdf", "size": f.bytes.len(), "sha256": hex(&Sha256::digest(&f.bytes)) }))
            .collect(),
    )
}

pub fn random_id() -> String {
    let mut b = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut b);
    hex(&b)
}

/// A header with the common fields; add `signer`/`sig` with [`sign`] when the type needs it.
pub fn draft(
    kind: &str,
    from_mailbox_pk: &[u8; 32],
    to_mailbox_pk: &[u8; 32],
    n: Option<&str>,
    body: Value,
    files: &[File],
    sent_at: u64,
) -> Value {
    let mut m = Map::new();
    m.insert("v".into(), 1.into());
    m.insert("id".into(), random_id().into());
    m.insert("type".into(), kind.into());
    m.insert(
        "to".into(),
        hex(&jitsuin_core::mailbox::mailbox_id(to_mailbox_pk)).into(),
    );
    m.insert(
        "from".into(),
        serde_json::json!({ "role": "financier", "mailbox_pk": hex(from_mailbox_pk) }),
    );
    m.insert("sent_at".into(), sent_at.into());
    if let Some(n) = n {
        m.insert("n".into(), n.into());
    }
    m.insert("body".into(), body);
    m.insert("attachments".into(), describe(files));
    Value::Object(m)
}

pub fn encode(header: &Value, files: &[File]) -> Result<Vec<u8>, String> {
    if canonical(&describe(files)) != canonical(&header["attachments"]) {
        return Err("attachments do not match the header".into());
    }
    if files.iter().any(|f| f.bytes.len() > MAX_ATTACHMENT) {
        return Err("an attachment is larger than 2 MiB".into());
    }
    let json = serde_json::to_vec(header).map_err(|e| e.to_string())?;
    if json.len() > MAX_HEADER {
        return Err("message header is larger than 64 KiB".into());
    }
    let mut out = Vec::with_capacity(9 + json.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&(json.len() as u32).to_be_bytes());
    out.extend_from_slice(&json);
    for f in files {
        out.extend_from_slice(&f.bytes);
    }
    Ok(out)
}

pub struct Message {
    pub header: Value,
    pub attachments: Vec<Vec<u8>>,
}

/// Reads a plaintext addressed to `my_mailbox_id`. The type's own fields are checked by the code
/// that handles it.
pub fn decode(bytes: &[u8], my_mailbox_id: &str) -> Result<Message, String> {
    if bytes.len() > MAX_PLAINTEXT {
        return Err("message is larger than the relay allows".into());
    }
    if bytes.len() < 9 || &bytes[..4] != MAGIC {
        return Err("not a JitsuinFi message".into());
    }
    if bytes[4] != VERSION {
        return Err(format!("unsupported message version {}", bytes[4]));
    }
    let len = u32::from_be_bytes(bytes[5..9].try_into().unwrap()) as usize;
    if len == 0 || len > MAX_HEADER || 9 + len > bytes.len() {
        return Err("message header length is not valid".into());
    }
    let header: Value = serde_json::from_slice(&bytes[9..9 + len])
        .map_err(|_| "message header is not valid JSON".to_string())?;
    if header["v"] != 1 || !header["type"].is_string() || !header["from"]["mailbox_pk"].is_string()
    {
        return Err("message header is missing required fields".into());
    }
    if header["to"].as_str() != Some(my_mailbox_id) {
        return Err("message is addressed to another mailbox".into());
    }
    let mut at = 9 + len;
    let mut attachments = Vec::new();
    for a in header["attachments"]
        .as_array()
        .ok_or("attachments must be a list")?
    {
        let size = a["size"].as_u64().ok_or("attachment size missing")? as usize;
        if size > MAX_ATTACHMENT || at + size > bytes.len() {
            return Err("attachment is cut short or too large".into());
        }
        let part = &bytes[at..at + size];
        if Some(hex(&Sha256::digest(part)).as_str()) != a["sha256"].as_str() {
            return Err("attachment does not match its hash".into());
        }
        attachments.push(part.to_vec());
        at += size;
    }
    if at != bytes.len() {
        return Err("message has trailing bytes".into());
    }
    Ok(Message {
        header,
        attachments,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_matches_relay_message_ts() {
        // relay-message.test.ts: canonicalJson({ b: 1, a: [true, null, "x"], c: { z: 0 } })
        let v = serde_json::json!({ "b": 1, "a": [true, null, "x"], "c": { "z": 0 } });
        assert_eq!(canonical(&v), r#"{"a":[true,null,"x"],"b":1,"c":{"z":0}}"#);
    }

    #[test]
    fn signed_message_with_pdf_round_trips_and_resists_change() {
        let key = SigningKey::from_bytes(&[0x42; 32]);
        let me = [1u8; 32];
        let peer_keys = jitsuin_core::mailbox::MailboxKeys::from_prf(&[2; 32]);
        let to = peer_keys.public();
        let files = vec![File {
            name: "letter.pdf".into(),
            bytes: b"%PDF-1.7 TES letter".to_vec(),
        }];
        let mut h = draft(
            "deal.letter",
            &me,
            &to,
            Some(&"ab".repeat(32)),
            serde_json::json!({ "letter": "SlRTQQ" }),
            &files,
            1_792_400_000,
        );
        sign(&mut h, &key);
        assert!(verify(&h, Some(&hex(&key.verifying_key().to_bytes()))));
        let bytes = encode(&h, &files).unwrap();
        let m = decode(&bytes, &hex(&peer_keys.id())).unwrap();
        assert_eq!(m.attachments, vec![files[0].bytes.clone()]);
        assert!(verify(&m.header, None));
        let mut changed = m.header.clone();
        changed["body"]["letter"] = "SlRTQg".into();
        assert!(!verify(&changed, None));
        assert!(
            decode(&bytes, &"00".repeat(32)).is_err(),
            "addressed to another mailbox"
        );
        let mut tampered = bytes.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(decode(&tampered, &hex(&peer_keys.id())).is_err());
        assert!(encode(&h, &[]).is_err(), "attachments must match");
    }

    /// A `deal.letter` encoded and signed by the web app (relay-message.ts `signHeader` +
    /// `encodeMessage`, Ed25519 seed 0x42 x 32): the node reads it, and its own signature over the
    /// same header is byte-for-byte the app's (Ed25519 is deterministic).
    #[test]
    fn reads_and_signs_like_the_web_app() {
        let raw = include_str!("../tests/vectors/jtsm-deal-letter.hex");
        let bytes: Vec<u8> = (0..raw.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).unwrap())
            .collect();
        let m = decode(&bytes, &"22".repeat(32)).unwrap();
        assert_eq!(m.attachments, vec![b"%PDF-1.7 TES letter".to_vec()]);
        let key = SigningKey::from_bytes(&[0x42; 32]);
        let pk = hex(&key.verifying_key().to_bytes());
        assert!(verify(&m.header, Some(&pk)));
        let mut again = m.header.clone();
        sign(&mut again, &key);
        assert_eq!(again["sig"], m.header["sig"]);
    }
}
