// Console pairing page (HNK-26.T2, BL-D21-16). The node checks the one-time code, the browser
// creates a passkey for this origin, and the node verifies the attestation and keeps the
// credential. Plain script, same origin only (CSP script-src 'self'); helpers in passkey.js.
"use strict";

function creationOptions(publicKey) {
  return {
    ...publicKey,
    challenge: b64u.decode(publicKey.challenge),
    user: { ...publicKey.user, id: b64u.decode(publicKey.user.id) },
    excludeCredentials: (publicKey.excludeCredentials || []).map((c) => ({ ...c, id: b64u.decode(c.id) })),
  };
}

function credentialJson(cred) {
  return {
    id: cred.id,
    rawId: b64u.encode(cred.rawId),
    type: cred.type,
    response: {
      attestationObject: b64u.encode(cred.response.attestationObject),
      clientDataJSON: b64u.encode(cred.response.clientDataJSON),
      transports: typeof cred.response.getTransports === "function" ? cred.response.getTransports() : undefined,
    },
    extensions: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
  };
}

function say(text) {
  $("msg").textContent = text;
}

async function pair(ev) {
  ev.preventDefault();
  const code = $("code").value.trim();
  if (code.replace(/[^a-z0-9]/gi, "").length < 16) {
    $("code").setAttribute("aria-invalid", "true");
    say("Type the 16 characters of the pairing code.");
    return;
  }
  $("code").removeAttribute("aria-invalid");
  const go = $("go");
  go.disabled = true;
  go.classList.add("is-waiting");
  go.firstChild.textContent = "Waiting for the passkey";
  say("");
  try {
    const start = await post("/node/console/pair/start", { code });
    let cred;
    try {
      cred = await navigator.credentials.create({ publicKey: creationOptions(start.options.publicKey) });
    } catch (e) {
      const why = {
        InvalidStateError: "This device already holds a passkey for this console.",
        NotAllowedError: "The passkey was not created.",
      }[e && e.name] || "This browser could not create the passkey.";
      throw new Error(`${why} The code is used up: run jitsuin-node pair again for another try.`);
    }
    const done = await post("/node/console/pair/finish", { ceremony: start.ceremony, credential: credentialJson(cred) });
    $("pair").hidden = true;
    $("done-line").textContent = done.credentials === 1 ? "This node now keeps one console passkey." : `This node now keeps ${done.credentials} console passkeys.`;
    $("done").hidden = false;
  } catch (e) {
    say(e.message);
    go.disabled = false;
    go.classList.remove("is-waiting");
    go.firstChild.textContent = "Create passkey";
  }
}

async function info() {
  $("host").textContent = location.host;
  try {
    const r = await fetch("/node/info", { credentials: "same-origin" });
    const j = await r.json();
    $("network").textContent = j.network === "main" ? "Zcash mainnet" : "Zcash testnet";
    $("fingerprint").textContent = contactFingerprint(j.contact);
  } catch {
    $("network").textContent = "unknown";
    $("fingerprint").textContent = "unknown";
  }
}

// An invite link carries the code after "#": the fragment never reaches the server. Fill it in
// and take it out of the address bar and history (HNK-26.T20).
function codeFromLink() {
  const code = decodeURIComponent(location.hash.slice(1)).trim();
  if (!code) return;
  $("code").value = code;
  history.replaceState(null, "", location.pathname);
}

document.addEventListener("DOMContentLoaded", () => {
  codeFromLink();
  if (!window.PublicKeyCredential) {
    say("This browser has no passkeys. Open this page in a current browser.");
    $("go").disabled = true;
  }
  $("pair").addEventListener("submit", pair);
  info();
});
