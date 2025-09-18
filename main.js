// index.js
import { createPrivateKey, sign } from "crypto";
import { canonicalize } from "json-canonicalize";
import { webcrypto as crypto } from "node:crypto";
const { subtle } = crypto;

import { abToBytes, bytesToB64, b64ToBytes } from "./utils/bytes.js";

// HPKE
import { CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";

// Config (replace with your values)
const wallet_id = "fcvsl05oo5muzkdizixbvz62";
const privyAppID = "cmdip4eml0064l40jspyn9iii";
const user_jwt = "";
const privyAppSecret = "";

// helper for basic auth
function basicAuth(id, secret) {
  return Buffer.from(`${id}:${secret}`).toString("base64");
}

// Generate ECDH P-256 keypair
async function generateP256ECDH() {
  const keyPair = await subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );

  const spkiAb = await subtle.exportKey("spki", keyPair.publicKey);
  const pkcs8Ab = await subtle.exportKey("pkcs8", keyPair.privateKey);

  return { spki: abToBytes(spkiAb), pkcs8: abToBytes(pkcs8Ab) };
}

// Snippet-1 style decryption logic
async function decryptAuthorizationKey(pkcs8B64, encB64, ctB64) {
  const suite = new CipherSuite({
    kem: new DhkemP256HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Chacha20Poly1305(),
  });

  // Import PKCS8 private key
  const privateKey = await subtle.importKey(
    "pkcs8",
    b64ToBytes(pkcs8B64).buffer,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey", "deriveBits"]
  );

  // Create recipient context
  const recipient = await suite.createRecipientContext({
    recipientKey: privateKey,
    enc: b64ToBytes(encB64),
  });

  // Decrypt ciphertext
  const plaintext = await recipient.open(b64ToBytes(ctB64));

  // Privy returns base64 DER, so decode + wrap in PEM
  const derBytes = Buffer.from(plaintext).toString("utf8");
  const base64Key = Buffer.from(derBytes, "base64").toString("base64");
  const pemKey = [
    "-----BEGIN PRIVATE KEY-----",
    base64Key.match(/.{1,64}/g).join("\n"),
    "-----END PRIVATE KEY-----",
  ].join("\n");

  return pemKey;
}

// Sign request payload
function getAuthorizationSignature({ url, body, privKeyPem }) {
  const payload = {
    version: 1,
    method: "POST",
    url,
    body,
    headers: { "privy-app-id": privyAppID },
  };

  const serializedPayload = canonicalize(payload);
  const privateKey = createPrivateKey({
    key: privKeyPem,
    format: "pem",
    type: "pkcs8",
  });

  const sig = sign("sha256", Buffer.from(serializedPayload), privateKey);
  return sig.toString("base64");
}

async function main() {
  // 1) generate ephemeral ECDH keypair
  const { spki, pkcs8 } = await generateP256ECDH();
  const pub_key_b64 = bytesToB64(spki);
  const private_key_b64 = bytesToB64(pkcs8);

  // 2) authenticate with Privy
  const authResp = await fetch("https://api.privy.io/v1/wallets/authenticate", {
    method: "POST",
    headers: {
      Authorization: `Basic ${basicAuth(privyAppID, privyAppSecret)}`,
      "privy-app-id": privyAppID,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      user_jwt,
      encryption_type: "HPKE",
      recipient_public_key: pub_key_b64,
    }),
  });

  if (!authResp.ok) {
    console.error("Auth failed:", authResp.status, await authResp.text());
    throw new Error("Privy authenticate failed");
  }

  const data = await authResp.json();
  console.log("Auth response:", data);

  const ENC_B64 = data?.encrypted_authorization_key?.encapsulated_key;
  const CT_B64 = data?.encrypted_authorization_key?.ciphertext;

  if (!ENC_B64 || !CT_B64) throw new Error("Missing encrypted_authorization_key");

  // 3) decrypt to PEM
  const PRIVY_AUTH_KEY_PEM = await decryptAuthorizationKey(
    private_key_b64,
    ENC_B64,
    CT_B64
  );

  // 4) sign payload
  const urlPath = `/v1/wallets/${wallet_id}/raw_sign`;
  const body = {
    hash: "0x0bd61313bc3103e806197bd99da4a6a6c567428e27b099365fd52c16daf05f03",
  };

  const signature = getAuthorizationSignature({
    url: urlPath,
    body,
    privKeyPem: PRIVY_AUTH_KEY_PEM,
  });

  console.log("✅ Authorization Signature:", signature);

  // 5) call raw_sign
  const rawResp = await fetch(`https://api.privy.io${urlPath}`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${basicAuth(privyAppID, privyAppSecret)}`,
      "privy-app-id": privyAppID,
      "privy-authorization-signature": signature,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ params: body }),
  });

  if (!rawResp.ok) {
    console.error("raw_sign failed:", rawResp.status, await rawResp.text());
    throw new Error("Privy raw_sign failed");
  }

  console.log("📝 raw_sign response:", await rawResp.json());
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
