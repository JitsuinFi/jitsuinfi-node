// Shared by the console pages: element lookup, base64url, JSON POST to the node.
"use strict";

const $ = (id) => document.getElementById(id);

const b64u = {
  decode(s) {
    const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0)).buffer;
  },
  encode(buf) {
    let s = "";
    for (const b of new Uint8Array(buf)) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  },
};

async function post(path, body) {
  const r = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body ?? {}), credentials: "same-origin" });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || `the node answered ${r.status}`);
  return j;
}

function contactFingerprint(contact) {
  const card = JSON.parse(atob(contact.slice("jitsuin-contact-v1:".length).replace(/-/g, "+").replace(/_/g, "/")));
  return card.fingerprint;
}
