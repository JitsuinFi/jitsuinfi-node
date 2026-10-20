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
  for (const el of document.querySelectorAll("[data-private]")) el.hidden = !session.signed_in;
  if (session.signed_in) {
    $("lede").textContent = "This node's keys and wallet stay on the node.";
    $("mailbox").textContent = short(info.mailbox_id);
    $("mailbox").title = info.mailbox_id;
    $("wallet").textContent = short(info.wallet_address);
    $("wallet").title = info.wallet_address;
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
  $("out").addEventListener("click", async () => {
    await post("/node/console/logout").catch(() => {});
    await render();
  });
  render().catch(() => {
    $("msg").textContent = "The node did not answer.";
    $("signin").hidden = false;
  });
});
