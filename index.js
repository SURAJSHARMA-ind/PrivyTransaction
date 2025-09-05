// Try to put in a single file but not tested yet

import { webcrypto as crypto } from "node:crypto";
import { CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import canonicalize from "json-canonicalize";
import https from "https";

// --- CONFIG ---
const PRIVY_APP_ID = "";
const PRIVY_BASIC_AUTH =
  "";
const PRIVY_USER_JWT =
  "";
const WALLET_ID = ""; //get after u login admin website and u can get it inside authenticate api

// --- UTILS ---
function bytesToB64(bytes) {
  return Buffer.from(bytes).toString("base64");
}
function abToBytes(ab) {
  return new Uint8Array(ab);
}
function base64ToArrayBuffer(b64) {
  const raw = Buffer.from(b64, "base64");
  return raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength);
}
function httpsPost({ hostname, path, headers, body }) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname,
        path,
        method: "POST",
        headers,
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          if (res.statusCode >= 400) {
            reject(
              new Error(
                `HTTP ${res.statusCode}: ${data || res.statusMessage}`
              )
            );
          } else {
            resolve(JSON.parse(data));
          }
        });
      }
    );
    req.on("error", reject);
    req.write(JSON.stringify(body));
    req.end();
  });
}

// --- MAIN FLOW ---
async function main() {
  // 1. Generate ECDH keypair
  const { subtle } = crypto;
  const keyPair = await subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );
  const spki = abToBytes(await subtle.exportKey("spki", keyPair.publicKey));
  const pkcs8 = abToBytes(await subtle.exportKey("pkcs8", keyPair.privateKey));
  const pubB64 = bytesToB64(spki);
  const privB64 = bytesToB64(pkcs8);

  console.log("Generated ECDH keypair.");
  // 2. Call /wallets/authenticate
  const authBody = {
    user_jwt: PRIVY_USER_JWT,
    encryption_type: "HPKE",
    recipient_public_key: pubB64,
  };
  const authHeaders = {
    Authorization: `Basic ${PRIVY_BASIC_AUTH}`,
    "Content-Type": "application/json",
    "privy-app-id": PRIVY_APP_ID,
  };
  const authResp = await httpsPost({
    hostname: "api.privy.io",
    path: "/v1/wallets/authenticate",
    headers: authHeaders,
    body: authBody,
  });
  // Response: { encapsulated_key, ciphertext, wallet_id }
  const { encapsulated_key, ciphertext, wallet_id } = authResp;
  console.log("Received encrypted authorization key.");

  // 3. Decrypt the response
  const pkcs8Buf = base64ToArrayBuffer(privB64);
  const privKey = await subtle.importKey(
    "pkcs8",
    pkcs8Buf,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits", "deriveKey"]
  );
  const suite = new CipherSuite({
    kem: new DhkemP256HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Chacha20Poly1305(),
  });
  const recipient = await suite.createRecipientContext({
    recipientKey: privKey,
    enc: Buffer.from(encapsulated_key, "base64"),
  });
  const decrypted = await recipient.open(Buffer.from(ciphertext, "base64"));
  const privyAuthKey = Buffer.from(decrypted).toString("base64");
  console.log("Decrypted Privy authorization key.");

  // 4. Generate privy-authorization-signature
  // Example hash to sign (replace with your actual hash)
  const hashToSign =
    "0x0bd61313bc3103e806197bd99da4a6a6c567428e27b099365fd52c16daf05f03";
  const url = `/v1/wallets/${wallet_id || WALLET_ID}/raw_sign`;
  const payload = {
    version: 1,
    method: "POST",
    url,
    body: { hash: hashToSign },
    headers: { "privy-app-id": PRIVY_APP_ID },
  };
  const serializedPayload = canonicalize(payload);
  const serializedPayloadBuffer = Buffer.from(serializedPayload);
  const privateKeyAsPem = `-----BEGIN PRIVATE KEY-----\n${privyAuthKey}\n-----END PRIVATE KEY-----`;
  const signKey = crypto.createPrivateKey({
    key: privateKeyAsPem,
    format: "pem",
  });
  const signatureBuffer = crypto.sign(
    "sha256",
    serializedPayloadBuffer,
    signKey
  );
  const privyAuthSignature = signatureBuffer.toString("base64");
  console.log("Generated privy-authorization-signature.");

  // 5. Call /wallets/:id/raw_sign
  const signHeaders = {
    Authorization: `Basic ${PRIVY_BASIC_AUTH}`,
    "Content-Type": "application/json",
    "privy-app-id": PRIVY_APP_ID,
    "privy-authorization-signature": privyAuthSignature,
  };
  const signBody = { params: { hash: hashToSign } };
  const signResp = await httpsPost({
    hostname: "api.privy.io",
    path: url,
    headers: signHeaders,
    body: signBody,
  });
  console.log("Raw sign API response:", signResp);
}

main().catch((e) => {
  console.error("Error:", e);
  process.exit(1);
});