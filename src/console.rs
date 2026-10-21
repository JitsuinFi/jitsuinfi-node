//! Console passkey pairing (HNK-26.T2, BL-D21-15, flows F1.34 – F1.37). The operator runs
//! `jitsuin-node pair` on the node (Railway: `railway ssh`), which prints a one-time pairing code
//! valid for 15 minutes; only its SHA-256 is kept (`pairing.json`). On the console page at the
//! node's own origin the operator types the code, the browser runs `create()` for the node's
//! `rp.id`, and the node verifies the attestation (challenge, origin, `rpIdHash`, user
//! verification) with webauthn-rs and stores the credential in D9 (`console-credentials.json`).
//!
//! A code is used up on the first correct try, refused after it expires, and dropped after five
//! wrong tries. Nothing secret is logged.
//!
//! Without a terminal (HNK-26.T20, D-43): the provider of a managed node sets `SETUP_CODE` and
//! sends the financier the invite link `<origin>/console/pair#<code>`. That code pairs the first
//! passkey only; once a passkey is paired it is refused. Five wrong tries lock it for 15 minutes.
//! Further devices get a one-time code from "Add a device" in a signed-in console.
//!
//! Sessions (HNK-26.T3, BL-D21-17, flows F1.39 – F1.43): a one-time challenge (2 minutes) for
//! the paired credentials, an assertion checked for origin, `rpIdHash`, user verification,
//! signature and counter, then a random session token in a `__Host-` cookie (`Secure`,
//! `HttpOnly`, `SameSite=Strict`, 8 hours). The node keeps only the token's SHA-256, in memory:
//! a restart signs everyone out.
//!
//! Payment approvals (HNK-26.T15, BL-D24-09, D-43): a session is not enough to move money. Each
//! advance needs a fresh assertion (user verification) for that payment's intent hash (N, amount,
//! address); the approval is used once, within 5 minutes, and only for that exact intent. An AI
//! agent or malware that holds the session cookie cannot touch the authenticator, so it cannot pay.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Url, Uuid,
    Webauthn, WebauthnBuilder,
};

use crate::message::{base32_groups, hex};

pub const CODE_TTL: Duration = Duration::from_secs(15 * 60);
const CEREMONY_TTL: Duration = Duration::from_secs(5 * 60);
const MAX_TRIES: u32 = 5;
const MAX_CREDENTIALS: usize = 10;
const LOGIN_TTL: Duration = Duration::from_secs(2 * 60);
const APPROVAL_TTL: Duration = Duration::from_secs(5 * 60);
pub const SESSION_TTL: Duration = Duration::from_secs(8 * 60 * 60);
pub const COOKIE: &str = "__Host-jitsuin_console";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Writes `bytes` to `path` through a temporary file, mode 0600.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    let _ = fs::remove_file(&tmp);
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(&tmp)?.write_all(bytes)?;
    fs::rename(&tmp, path)
}

fn code_hash(code: &str) -> String {
    let norm: String = code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_uppercase();
    hex(&Sha256::new()
        .chain_update(b"jitsuin-pairing-v1:")
        .chain_update(norm.as_bytes())
        .finalize())
}

#[derive(Serialize, Deserialize)]
struct Pairing {
    code_sha256: String,
    expires_at: u64,
    tries: u32,
}

/// One stored console credential (D9).
#[derive(Serialize, Deserialize)]
pub struct Stored {
    pub paired_at: u64,
    pub passkey: Passkey,
}

#[derive(Debug, PartialEq)]
pub enum PairError {
    NoCode,
    Expired,
    Wrong,
    Full,
    Ceremony,
    Rejected,
    Store,
    NotPaired,
    LoginGone,
    /// No unused, unexpired approval for this exact payment.
    NotApproved,
    /// Too many wrong setup-code tries; wait.
    Locked,
}

impl PairError {
    pub fn message(&self) -> &'static str {
        match self {
            PairError::NoCode => "no pairing code is waiting; ask your node provider for an invite link, or use Add a device in a signed-in console",
            PairError::Expired => "the pairing code has expired; ask for a new invite link",
            PairError::Wrong => "the pairing code is not correct",
            PairError::Full => "this node already has the most console passkeys it keeps",
            PairError::Ceremony => "this pairing has expired or was already finished; start again",
            PairError::Rejected => "the passkey response did not verify",
            PairError::Store => "the node could not save the passkey",
            PairError::NotPaired => "no passkey is paired with this console yet; pair one first",
            PairError::LoginGone => "this passkey request has expired or was already used; try again",
            PairError::Locked => "too many wrong codes; wait 15 minutes and try again",
            PairError::NotApproved => "this payment has no passkey approval (or it expired, was used, or was for another payment)",
        }
    }
}

pub struct Console {
    webauthn: Webauthn,
    /// SHA-256 of the provider's setup code (first passkey only).
    setup: Option<String>,
    /// Wrong setup-code tries, and the end of a lockout.
    setup_fails: Mutex<(u32, Option<Instant>)>,
    user: Uuid,
    pairing: PathBuf,
    credentials: PathBuf,
    ceremonies: Mutex<HashMap<String, (PasskeyRegistration, Instant)>>,
    logins: Mutex<HashMap<String, (PasskeyAuthentication, Instant)>>,
    /// SHA-256 of each session token, and when the session ends.
    sessions: Mutex<HashMap<String, Instant>>,
    /// Approval ceremonies: state, the intent hash shown to the operator, start time.
    approving: Mutex<HashMap<String, Approving>>,
    /// Granted approvals: intent hash and when granted; removed when used.
    approvals: Mutex<HashMap<String, ([u8; 32], Instant)>>,
    lock: Mutex<()>,
}

/// An approval ceremony: its state, the intent hash shown, its start.
type Approving = (PasskeyAuthentication, [u8; 32], Instant);

fn token_hash(token: &str) -> String {
    hex(&Sha256::digest(token.as_bytes()))
}

fn random_hex<const N: usize>() -> String {
    let mut b = [0u8; N];
    rand::rng().fill_bytes(&mut b);
    hex(&b)
}

/// Makes a pairing code and stores its hash; returns the code to show the operator once.
pub fn new_code(data_dir: &Path) -> std::io::Result<String> {
    let mut raw = [0u8; 10];
    rand::rng().fill_bytes(&mut raw);
    let code = base32_groups(&raw);
    let p = Pairing {
        code_sha256: code_hash(&code),
        expires_at: now() + CODE_TTL.as_secs(),
        tries: 0,
    };
    write_private(
        &data_dir.join("pairing.json"),
        &serde_json::to_vec(&p).expect("json"),
    )?;
    Ok(code)
}

impl Console {
    /// `origin` is the console's own origin (NODE_ORIGIN), e.g. `https://node.example`; its host
    /// is the passkey `rp.id`.
    pub fn new(
        origin: &str,
        data_dir: &Path,
        user: [u8; 16],
        setup_code: Option<&str>,
    ) -> Result<Self, String> {
        if setup_code.is_some_and(|c| c.chars().filter(|c| c.is_ascii_alphanumeric()).count() < 16)
        {
            return Err("SETUP_CODE must have at least 16 letters or digits".into());
        }
        let url = Url::parse(origin).map_err(|e| format!("NODE_ORIGIN: {e}"))?;
        let host = url.host_str().ok_or("NODE_ORIGIN has no host")?.to_string();
        if url.scheme() != "https" && host != "localhost" {
            return Err("NODE_ORIGIN must be https (only localhost may be http)".into());
        }
        let webauthn = WebauthnBuilder::new(&host, &url)
            .and_then(|b| b.rp_name("JitsuinFi financier node").build())
            .map_err(|e| format!("NODE_ORIGIN: {e}"))?;
        Ok(Console {
            webauthn,
            setup: setup_code.map(code_hash),
            setup_fails: Mutex::new((0, None)),
            user: Uuid::from_bytes(user),
            pairing: data_dir.join("pairing.json"),
            credentials: data_dir.join("console-credentials.json"),
            ceremonies: Mutex::new(HashMap::new()),
            logins: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
            approving: Mutex::new(HashMap::new()),
            approvals: Mutex::new(HashMap::new()),
            lock: Mutex::new(()),
        })
    }

    pub fn stored(&self) -> Vec<Stored> {
        fs::read(&self.credentials)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// Checks and uses up the pairing code, then starts `create()`.
    pub fn start(&self, code: &str) -> Result<(String, CreationChallengeResponse), PairError> {
        let _g = self.lock.lock().unwrap();
        if self.setup_matches(code, !self.stored().is_empty())? {
            return self.registration();
        }
        let mut p: Pairing = fs::read(&self.pairing)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .ok_or(PairError::NoCode)?;
        if now() >= p.expires_at {
            let _ = fs::remove_file(&self.pairing);
            return Err(PairError::Expired);
        }
        if code_hash(code) != p.code_sha256 {
            p.tries += 1;
            if p.tries >= MAX_TRIES {
                let _ = fs::remove_file(&self.pairing);
            } else {
                write_private(&self.pairing, &serde_json::to_vec(&p).expect("json"))
                    .map_err(|_| PairError::Store)?;
            }
            return Err(PairError::Wrong);
        }
        fs::remove_file(&self.pairing).map_err(|_| PairError::Store)?;
        self.registration()
    }

    /// True when `code` is the provider's setup code and it may still pair (no passkey yet).
    /// Wrong tries count only while the setup code is the way in (no other code is waiting).
    fn setup_matches(&self, code: &str, paired: bool) -> Result<bool, PairError> {
        let Some(setup) = &self.setup else {
            return Ok(false);
        };
        if paired {
            return Ok(false);
        }
        let mut f = self.setup_fails.lock().unwrap();
        if f.1.is_some_and(|until| Instant::now() < until) {
            return Err(PairError::Locked);
        }
        if code_hash(code) == *setup {
            *f = (0, None);
            return Ok(true);
        }
        if !self.pairing.exists() {
            f.0 += 1;
            if f.0 >= MAX_TRIES {
                *f = (0, Some(Instant::now() + CODE_TTL));
                return Err(PairError::Locked);
            }
            return Err(PairError::Wrong);
        }
        Ok(false)
    }

    /// `create()` options for a new passkey, excluding the ones already paired.
    fn registration(&self) -> Result<(String, CreationChallengeResponse), PairError> {
        let stored = self.stored();
        if stored.len() >= MAX_CREDENTIALS {
            return Err(PairError::Full);
        }
        let exclude = stored
            .iter()
            .map(|s| s.passkey.cred_id().clone())
            .collect::<Vec<_>>();
        let (options, state) = self
            .webauthn
            .start_passkey_registration(self.user, "financier", "Financier console", Some(exclude))
            .map_err(|_| PairError::Rejected)?;
        let mut id = [0u8; 16];
        rand::rng().fill_bytes(&mut id);
        let id = hex(&id);
        let mut c = self.ceremonies.lock().unwrap();
        c.retain(|_, (_, at)| at.elapsed() < CEREMONY_TTL);
        c.insert(id.clone(), (state, Instant::now()));
        Ok((id, options))
    }

    /// Verifies the attestation and stores the credential; returns how many the node keeps.
    pub fn finish(
        &self,
        ceremony: &str,
        credential: &RegisterPublicKeyCredential,
    ) -> Result<usize, PairError> {
        let (state, at) = self
            .ceremonies
            .lock()
            .unwrap()
            .remove(ceremony)
            .ok_or(PairError::Ceremony)?;
        if at.elapsed() >= CEREMONY_TTL {
            return Err(PairError::Ceremony);
        }
        let passkey = self
            .webauthn
            .finish_passkey_registration(credential, &state)
            .map_err(|_| PairError::Rejected)?;
        let _g = self.lock.lock().unwrap();
        let mut stored = self.stored();
        if stored
            .iter()
            .any(|s| s.passkey.cred_id() == passkey.cred_id())
        {
            return Err(PairError::Rejected);
        }
        stored.push(Stored {
            paired_at: now(),
            passkey,
        });
        write_private(
            &self.credentials,
            &serde_json::to_vec(&stored).expect("json"),
        )
        .map_err(|_| PairError::Store)?;
        Ok(stored.len())
    }

    /// A one-time challenge for every paired credential.
    pub fn login_start(&self) -> Result<(String, RequestChallengeResponse), PairError> {
        let passkeys: Vec<Passkey> = self.stored().into_iter().map(|s| s.passkey).collect();
        if passkeys.is_empty() {
            return Err(PairError::NotPaired);
        }
        let (options, state) = self
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|_| PairError::Rejected)?;
        let id = random_hex::<16>();
        let mut l = self.logins.lock().unwrap();
        l.retain(|_, (_, at)| at.elapsed() < LOGIN_TTL);
        l.insert(id.clone(), (state, Instant::now()));
        Ok((id, options))
    }

    /// Checks the assertion against its challenge (used once, whatever the outcome) and opens a
    /// session; returns the session token for the cookie.
    pub fn login_finish(
        &self,
        ceremony: &str,
        credential: &PublicKeyCredential,
    ) -> Result<String, PairError> {
        let (state, at) = self
            .logins
            .lock()
            .unwrap()
            .remove(ceremony)
            .ok_or(PairError::LoginGone)?;
        if at.elapsed() >= LOGIN_TTL {
            return Err(PairError::LoginGone);
        }
        self.verify_assertion(&state, credential)?;
        let token = random_hex::<32>();
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, end| *end > Instant::now());
        sessions.insert(token_hash(&token), Instant::now() + SESSION_TTL);
        Ok(token)
    }

    /// True while `token` names an open session.
    pub fn session(&self, token: &str) -> bool {
        self.sessions
            .lock()
            .unwrap()
            .get(&token_hash(token))
            .is_some_and(|end| *end > Instant::now())
    }

    pub fn logout(&self, token: &str) {
        self.sessions.lock().unwrap().remove(&token_hash(token));
    }

    /// Checks an assertion with user verification against its state and saves the counter.
    fn verify_assertion(
        &self,
        state: &PasskeyAuthentication,
        credential: &PublicKeyCredential,
    ) -> Result<(), PairError> {
        let result = self
            .webauthn
            .finish_passkey_authentication(credential, state)
            .map_err(|_| PairError::Rejected)?;
        if !result.user_verified() {
            return Err(PairError::Rejected);
        }
        let _g = self.lock.lock().unwrap();
        let mut stored = self.stored();
        let mut changed = false;
        for s in &mut stored {
            changed |= s.passkey.update_credential(&result) == Some(true);
        }
        if changed {
            write_private(
                &self.credentials,
                &serde_json::to_vec(&stored).expect("json"),
            )
            .map_err(|_| PairError::Store)?;
        }
        Ok(())
    }

    /// Starts a passkey approval of one payment (its intent hash, see `pay::Intent`).
    pub fn approve_start(
        &self,
        intent: [u8; 32],
    ) -> Result<(String, RequestChallengeResponse), PairError> {
        let passkeys: Vec<Passkey> = self.stored().into_iter().map(|s| s.passkey).collect();
        if passkeys.is_empty() {
            return Err(PairError::NotPaired);
        }
        let (options, state) = self
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|_| PairError::Rejected)?;
        let id = random_hex::<16>();
        let mut a = self.approving.lock().unwrap();
        a.retain(|_, (_, _, at)| at.elapsed() < LOGIN_TTL);
        a.insert(id.clone(), (state, intent, Instant::now()));
        Ok((id, options))
    }

    /// Verifies the operator's assertion and grants a one-time approval of that intent; returns
    /// the approval id the payment must present.
    pub fn approve_finish(
        &self,
        ceremony: &str,
        credential: &PublicKeyCredential,
    ) -> Result<String, PairError> {
        let (state, intent, at) = self
            .approving
            .lock()
            .unwrap()
            .remove(ceremony)
            .ok_or(PairError::LoginGone)?;
        if at.elapsed() >= LOGIN_TTL {
            return Err(PairError::LoginGone);
        }
        self.verify_assertion(&state, credential)?;
        let id = random_hex::<16>();
        let mut g = self.approvals.lock().unwrap();
        g.retain(|_, (_, at)| at.elapsed() < APPROVAL_TTL);
        g.insert(id.clone(), (intent, Instant::now()));
        Ok(id)
    }

    /// Uses up the approval `id` for exactly `intent`. An approval for another intent is left in
    /// place (it may still serve its own payment); an expired one is dropped.
    pub fn take_approval(&self, id: &str, intent: &[u8; 32]) -> Result<(), PairError> {
        let mut g = self.approvals.lock().unwrap();
        match g.get(id) {
            Some((i, at)) if at.elapsed() < APPROVAL_TTL && i == intent => {
                g.remove(id);
                Ok(())
            }
            Some((_, at)) if at.elapsed() >= APPROVAL_TTL => {
                g.remove(id);
                Err(PairError::NotApproved)
            }
            _ => Err(PairError::NotApproved),
        }
    }

    #[cfg(test)]
    fn grant_for_test(&self, intent: [u8; 32], age: Duration) -> String {
        let id = random_hex::<16>();
        let at = Instant::now().checked_sub(age).expect("age fits");
        self.approvals
            .lock()
            .unwrap()
            .insert(id.clone(), (intent, at));
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("jitsuin-node-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn code_is_one_time_and_tolerates_format() {
        let d = dir("once");
        let c = Console::new("http://localhost:8788", &d, [1; 16], None).unwrap();
        assert_eq!(c.start("AAAA-BBBB").unwrap_err(), PairError::NoCode);
        let code = new_code(&d).unwrap();
        assert_eq!(code.len(), 19);
        let (id, options) = c.start(&code.to_lowercase().replace('-', " ")).unwrap();
        assert_eq!(id.len(), 32);
        let o = serde_json::to_value(&options).unwrap();
        assert_eq!(o["publicKey"]["rp"]["id"], "localhost");
        assert_eq!(
            o["publicKey"]["authenticatorSelection"]["userVerification"],
            "required"
        );
        assert_eq!(c.start(&code).unwrap_err(), PairError::NoCode, "used up");
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn wrong_tries_and_expiry_drop_the_code() {
        let d = dir("tries");
        let c = Console::new("http://localhost:8788", &d, [1; 16], None).unwrap();
        let code = new_code(&d).unwrap();
        for _ in 0..MAX_TRIES {
            assert_eq!(c.start("WRONG-CODE").unwrap_err(), PairError::Wrong);
        }
        assert_eq!(
            c.start(&code).unwrap_err(),
            PairError::NoCode,
            "dropped after five wrong tries"
        );
        new_code(&d).unwrap();
        let mut p: Pairing =
            serde_json::from_slice(&fs::read(d.join("pairing.json")).unwrap()).unwrap();
        p.expires_at = now() - 1;
        fs::write(d.join("pairing.json"), serde_json::to_vec(&p).unwrap()).unwrap();
        assert_eq!(c.start("ANY").unwrap_err(), PairError::Expired);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn sign_in_needs_a_paired_passkey_and_a_live_challenge() {
        let d = dir("login");
        let c = Console::new("http://localhost:8788", &d, [1; 16], None).unwrap();
        assert_eq!(c.login_start().unwrap_err(), PairError::NotPaired);
        let cred: PublicKeyCredential = serde_json::from_value(serde_json::json!({
            "id": "AA", "rawId": "AA", "type": "public-key",
            "response": { "authenticatorData": "AA", "clientDataJSON": "AA", "signature": "AA" }
        }))
        .unwrap();
        assert_eq!(
            c.login_finish("nope", &cred).unwrap_err(),
            PairError::LoginGone
        );
        assert!(!c.session("not-a-token"));
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn the_setup_code_pairs_the_first_passkey_only() {
        let d = dir("setup");
        let setup = "SETU-PCOD-EFOR-NODE";
        assert!(Console::new("http://localhost:8788", &d, [1; 16], Some("short")).is_err());
        let c = Console::new("http://localhost:8788", &d, [1; 16], Some(setup)).unwrap();
        // format-tolerant, and usable again until a passkey is actually paired
        c.start(&setup.to_lowercase()).unwrap();
        c.start(setup).unwrap();
        // five wrong tries lock it
        for _ in 0..MAX_TRIES - 1 {
            assert_eq!(c.start("WRONG-WRONG-WRONG").unwrap_err(), PairError::Wrong);
        }
        assert_eq!(c.start("WRONG-WRONG-WRONG").unwrap_err(), PairError::Locked);
        assert_eq!(
            c.start(setup).unwrap_err(),
            PairError::Locked,
            "locked even for the right code"
        );
        // once a passkey is paired, the setup code no longer pairs
        let c = Console::new("http://localhost:8788", &d, [1; 16], Some(setup)).unwrap();
        assert!(c.setup_matches(setup, false).unwrap());
        assert!(!c.setup_matches(setup, true).unwrap());
        assert_eq!(c.start("ANY").unwrap_err(), PairError::Wrong);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn an_approval_pays_once_and_only_its_own_intent() {
        let d = dir("approve");
        let c = Console::new("http://localhost:8788", &d, [1; 16], None).unwrap();
        assert_eq!(c.approve_start([7; 32]).unwrap_err(), PairError::NotPaired);
        let id = c.grant_for_test([7; 32], Duration::ZERO);
        assert_eq!(
            c.take_approval("nope", &[7; 32]).unwrap_err(),
            PairError::NotApproved
        );
        assert_eq!(
            c.take_approval(&id, &[8; 32]).unwrap_err(),
            PairError::NotApproved,
            "another payment"
        );
        c.take_approval(&id, &[7; 32]).unwrap();
        assert_eq!(
            c.take_approval(&id, &[7; 32]).unwrap_err(),
            PairError::NotApproved,
            "used once"
        );
        let old = c.grant_for_test([7; 32], APPROVAL_TTL + Duration::from_secs(1));
        assert_eq!(
            c.take_approval(&old, &[7; 32]).unwrap_err(),
            PairError::NotApproved,
            "expired"
        );
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn origin_must_be_https_except_localhost() {
        let d = dir("origin");
        assert!(Console::new("http://node.example", &d, [1; 16], None).is_err());
        assert!(Console::new("https://node.example", &d, [1; 16], None).is_ok());
        assert_eq!(
            Console::new("https://node.example", &d, [1; 16], None)
                .unwrap()
                .finish(
                    "x",
                    &serde_json::from_value(serde_json::json!({
                        "id": "AA", "rawId": "AA", "type": "public-key",
                        "response": { "attestationObject": "AA", "clientDataJSON": "AA" }
                    }))
                    .unwrap()
                )
                .unwrap_err(),
            PairError::Ceremony
        );
        fs::remove_dir_all(&d).unwrap();
    }
}
