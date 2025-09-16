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
// CHANGE JWT 
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

  const spki = abToBytes(spkiAb);
  const pkcs8 = abToBytes(pkcs8Ab);

  return { spki, pkcs8 };
}

// Decrypt HPKE payload
async function decryptAuthorizationKey(pkcs8B64, encB64, ctB64) {
  const pkcs8Bytes = b64ToBytes(pkcs8B64);
  const encBytes = b64ToBytes(encB64);
  const ctBytes = b64ToBytes(ctB64);

  const privKeyCrypto = await subtle.importKey(
    "pkcs8",
    pkcs8Bytes.buffer,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );

  const suite = new CipherSuite({
    kem: new DhkemP256HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Chacha20Poly1305(),
  });

  const recipient = await suite.createRecipientContext({
    recipientKey: privKeyCrypto,
    enc: encBytes,
  });

  const plaintext = await recipient.open(ctBytes);
  const privKeyB64 = Buffer.from(plaintext).toString("utf8");
  console.log("🔓 Decrypted key (base64):", privKeyB64);

  return Buffer.from(privKeyB64, "base64"); // DER bytes
}

// Sign request payload
function getAuthorizationSignature({ url, body, privKeyBytes }) {
  const payload = {
    version: 1,
    method: "POST",
    url,
    body,
    headers: {
      "privy-app-id": privyAppID,
    },
  };

  const serializedPayload = canonicalize(payload);
  const serializedPayloadBuffer = Buffer.from(serializedPayload);

  const privateKey = createPrivateKey({
    key: Buffer.from(privKeyBytes),
    format: "der",
    type: "pkcs8",
  });

  const signatureBuffer = sign("sha256", serializedPayloadBuffer, privateKey);
  return signatureBuffer.toString("base64");
}

async function main() {
  // 1) generate ephemeral ECDH keypair
  const { spki, pkcs8 } = await generateP256ECDH();
  const pub_key_b64 = bytesToB64(spki);
  const private_key_b64 = bytesToB64(pkcs8);

  // 2) authenticate with Privy
  const auth_url = "https://api.privy.io/v1/wallets/authenticate";
  const auth_options = {
    method: "POST",
    headers: {
      Authorization: `Basic ${basicAuth(privyAppID, privyAppSecret)}`,
      "privy-app-id": `${privyAppID}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      user_jwt,
      encryption_type: "HPKE",
      recipient_public_key: pub_key_b64,
    }),
  };

  const authResp = await fetch(auth_url, auth_options);
  if (!authResp.ok) {
    console.error("Auth failed:", authResp.status, await authResp.text());
    throw new Error("Privy authenticate failed");
  }
  const data = await authResp.json();
  console.log("Auth response:", data);

  const ENC_B64 = data?.encrypted_authorization_key?.encapsulated_key;
  const CIPHERTEXT_B64 = data?.encrypted_authorization_key?.ciphertext;

  if (!ENC_B64 || !CIPHERTEXT_B64) {
    throw new Error("Missing encrypted_authorization_key in response");
  }

  // 3) decrypt authorization key
  const PRIVY_AUTHORIZATION_KEY_BYTES = await decryptAuthorizationKey(
    private_key_b64,
    ENC_B64,
    CIPHERTEXT_B64
  );

  // 4) generate signature
  const urlPath = `/v1/wallets/${wallet_id}/raw_sign`;
  const body = {
    hash: "0x0bd61313bc3103e806197bd99da4a6a6c567428e27b099365fd52c16daf05f03",
  };

  const signature = getAuthorizationSignature({
    url: urlPath,
    body,
    privKeyBytes: PRIVY_AUTHORIZATION_KEY_BYTES,
  });

  console.log("✅ Authorization Signature:", signature);

  // 5) call raw_sign
  const rawSignUrl = `https://api.privy.io${urlPath}`;
  const rawSignOptions = {
    method: "POST",
    headers: {
      Authorization: `Basic ${basicAuth(privyAppID, privyAppSecret)}`,
      "privy-app-id": privyAppID,
      "privy-authorization-signature": signature,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ params: body }),
  };

  const rawResp = await fetch(rawSignUrl, rawSignOptions);
  if (!rawResp.ok) {
    console.error("raw_sign failed:", rawResp.status, await rawResp.text());
    throw new Error("Privy raw_sign failed");
  }
  const rawData = await rawResp.json();
  console.log("📝 raw_sign response:", rawData);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
