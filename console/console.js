// Console sign-in (HNK-26.T3, BL-D21-17): a one-time challenge from the node, an assertion from
// the paired passkey, then an HttpOnly session cookie the page never sees.
"use strict";

function requestOptions(publicKey) {
  return {
    ...publicKey,
    challenge: b64u.decode(publicKey.challenge),
    allowCredentials: (publicKey.allowCredentials || []).map((c) => ({ ...c, id: b64u.decode(c.id) })),
  };
}

function assertionJson(cred) {
  return {
    id: cred.id,
    rawId: b64u.encode(cred.rawId),
    type: cred.type,
    response: {
      authenticatorData: b64u.encode(cred.response.authenticatorData),
      clientDataJSON: b64u.encode(cred.response.clientDataJSON),
      signature: b64u.encode(cred.response.signature),
      userHandle: cred.response.userHandle ? b64u.encode(cred.response.userHandle) : null,
    },
    extensions: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
  };
}

const short = (s) => (s.length > 20 ? `${s.slice(0, 10)}…${s.slice(-8)}` : s);

// Message types (jitsuinfi-frontend src/lib/relay-message.ts) in the operator's words.
const TYPE_LABEL = {
  "deal.offer": "Financing offer",
  "deal.entry": "Board entry",
  "deal.seal": "Seal",
  "history.chain": "Buyer history",
  "invoice.signature": "Buyer signature",
  "key.invoice_pk": "Invoice key",
  "invoice.sign_request": "Signing request",
};
const ROLE_BADGE = { supplier: "売", buyer: "買", fund: "資", member: "資", financier: "証" };

function el(tag, attrs = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  for (const c of children) e.append(c);
  return e;
}

function ago(iso) {
  const s = Math.max(0, (Date.now() - Date.parse(iso)) / 1000);
  if (s < 90) return "just now";
  if (s < 5400) return `${Math.round(s / 60)} min ago`;
  if (s < 129600) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} days ago`;
}

function kib(n) {
  return n < 1024 ? `${n} B` : `${Math.round(n / 1024)} KB`;
}

function mailRow(m) {
  const signed = m.signer !== undefined && m.signer !== null;
  const verdict = signed ? el("span", { class: m.signature_ok ? "mail-verdict" : "mail-verdict is-bad", title: m.signature_ok ? "Signature holds" : "Signature does not hold" }, m.signature_ok ? "認" : "拒") : el("span");
  const line = el("span", { class: "mail-line" }, `from ${m.from?.role ?? "?"} · ${ago(m.received_at)}`);
  if (m.n) line.append(" · N ", el("span", { class: "is-mono" }, short(m.n)));
  const actions = el("div", { class: "mail-actions" });
  (m.attachments || []).forEach((a, i) => actions.append(el("a", { href: `/node/mail/${encodeURIComponent(m.relay_id)}/attachments/${i}`, download: "" }, `${a.name} (${kib(a.size)})`)));
  const remove = el("button", { type: "button" }, "Remove");
  remove.addEventListener("click", async () => {
    remove.disabled = true;
    try {
      const r = await fetch(`/node/mail/${encodeURIComponent(m.relay_id)}`, { method: "DELETE", credentials: "same-origin" });
      if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || `the node answered ${r.status}`);
      await loadMail();
    } catch (e) {
      $("mail-note").textContent = e.message;
      remove.disabled = false;
    }
  });
  actions.append(remove);
  return el("li", { class: "mail-row" }, el("span", { class: "mail-badge", "aria-hidden": "true" }, ROLE_BADGE[m.from?.role] ?? "外"), el("span", { class: "mail-what" }, TYPE_LABEL[m.type] ?? m.type), verdict, line, actions);
}

async function loadMail() {
  const note = $("mail-note");
  note.textContent = "Opening sealed messages…";
  try {
    const r = await fetch("/node/mail", { credentials: "same-origin" });
    const j = await r.json();
    if (!r.ok) throw new Error(j.error || `the node answered ${r.status}`);
    $("mail-list").replaceChildren(...j.messages.map(mailRow));
    const refused = j.refused ? ` ${j.refused} could not be opened or were addressed elsewhere.` : "";
    note.textContent = j.messages.length ? refused.trim() : `No messages.${refused}`;
  } catch (e) {
    note.textContent = e.message;
  }
}

async function render() {
  const [session, info] = await Promise.all([
    fetch("/node/console/session", { credentials: "same-origin" }).then((r) => r.json()),
    fetch("/node/info", { credentials: "same-origin" }).then((r) => r.json()),
  ]);
  $("network").textContent = info.network === "main" ? "Zcash mainnet" : "Zcash testnet";
  $("fingerprint").textContent = contactFingerprint(info.contact);
  $("signin").hidden = session.signed_in;
  $("home").hidden = !session.signed_in;
  $("out").hidden = !session.signed_in;
  for (const e of document.querySelectorAll("[data-private]")) e.hidden = !session.signed_in;
  $("mail").hidden = !session.signed_in;
  if (session.signed_in) {
    $("lede").textContent = "This node's keys and wallet stay on the node.";
    $("mailbox").textContent = short(info.mailbox_id);
    $("mailbox").title = info.mailbox_id;
    $("wallet").textContent = short(info.wallet_address);
    $("wallet").title = info.wallet_address;
    loadMail();
  } else if (!session.console) {
    $("go").disabled = true;
    $("msg").textContent = "The console is off on this node (NODE_ORIGIN is not set).";
  } else if (!session.paired) {
    $("lede").textContent = "No passkey is paired with this console yet.";
    $("go").hidden = true;
  }
}

async function signIn() {
  const go = $("go");
  go.disabled = true;
  go.classList.add("is-waiting");
  $("msg").textContent = "";
  try {
    const start = await post("/node/console/login/start");
    let cred;
    try {
      cred = await navigator.credentials.get({ publicKey: requestOptions(start.options.publicKey) });
    } catch (e) {
      throw new Error(e && e.name === "NotAllowedError" ? "The passkey did not sign in." : "This browser could not use the passkey.");
    }
    await post("/node/console/login/finish", { ceremony: start.ceremony, credential: assertionJson(cred) });
    await render();
  } catch (e) {
    $("msg").textContent = e.message;
  } finally {
    go.disabled = false;
    go.classList.remove("is-waiting");
  }
}

document.addEventListener("DOMContentLoaded", () => {
  $("host").textContent = location.host;
  $("go").addEventListener("click", signIn);
  $("mail-refresh").addEventListener("click", loadMail);
  $("out").addEventListener("click", async () => {
    await post("/node/console/logout").catch(() => {});
    await render();
  });
  render().catch(() => {
    $("msg").textContent = "The node did not answer.";
    $("signin").hidden = false;
  });
});

// Payment approval (HNK-26.T15): a fresh passkey assertion for one payment's intent (N, amount,
// address). The deal pipeline (HNK-26.T16) calls this before the node pays an advance; the
// approval id it returns is used once, within 5 minutes, for that payment only.
async function approvePayment(intent) {
  const start = await post("/node/console/approve/start", intent);
  const cred = await navigator.credentials.get({ publicKey: requestOptions(start.options.publicKey) });
  const done = await post("/node/console/approve/finish", { ceremony: start.ceremony, credential: assertionJson(cred) });
  return done.approval;
}

