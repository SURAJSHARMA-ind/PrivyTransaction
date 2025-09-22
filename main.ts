import { webcrypto as crypto } from "node:crypto";
import { CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import { generateAuthorizationSignature } from "@privy-io/server-auth/wallet-api";

const { subtle } = crypto;

// --- CONFIGURATION (replace with your values) ---
const WALLET_ID = "fcvsl05oo5muzkdizixbvz62";
const PRIVY_APP_ID = "cmdip4eml0064l40jspyn9iii";
const USER_JWT = "";
const PRIVY_APP_SECRET = "";

// --- TYPE DEFINITIONS ---
interface AuthResponse {
  encrypted_authorization_key?: {
    encapsulated_key: string;
    ciphertext: string;
  };
}

interface AuthorizationSignatureParams {
  url: string;
  body: Record<string, unknown>;
  privKeyPem: string;
}

// --- UTILITY FUNCTIONS ---

/** Converts an ArrayBuffer to a Uint8Array. */
function abToBytes(ab: ArrayBuffer): Uint8Array {
  return new Uint8Array(ab);
}

/** Converts a Uint8Array to a Base64 encoded string. */
function bytesToB64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

/** Converts a Base64 encoded string to a Uint8Array. */
function b64ToBytes(b64: string): Uint8Array {
  return Uint8Array.from(Buffer.from(b64, "base64"));
}

/** Safely converts a Uint8Array view to a standalone ArrayBuffer. */
function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

/** Creates a Basic Authentication header value. */
function basicAuth(id: string, secret: string): string {
  return Buffer.from(`${id}:${secret}`).toString("base64");
}

// --- CORE LOGIC ---

/** Generates an ECDH P-256 keypair for HPKE. */
async function generateP256ECDH(): Promise<{
  spki: Uint8Array;
  pkcs8: Uint8Array;
}> {
  const keyPair = await subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );

  const spkiAb = await subtle.exportKey("spki", keyPair.publicKey);
  const pkcs8Ab = await subtle.exportKey("pkcs8", keyPair.privateKey);

  return { spki: abToBytes(spkiAb), pkcs8: abToBytes(pkcs8Ab) };
}

/** Decrypts the authorization key from Privy using HPKE. */
async function decryptAuthorizationKey(
  pkcs8B64: string,
  encB64: string,
  ctB64: string,
): Promise<string> {
  const suite = new CipherSuite({
    kem: new DhkemP256HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Chacha20Poly1305(),
  });

  const privateKey = await subtle.importKey(
    "pkcs8",
    b64ToBytes(pkcs8B64),
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );

  const recipient = await suite.createRecipientContext({
    recipientKey: privateKey,
    enc: toArrayBuffer(b64ToBytes(encB64)),
  });

  const plaintextAb = await recipient.open(toArrayBuffer(b64ToBytes(ctB64)));

  // The decrypted plaintext is the base64 representation of the DER-encoded key
  const base64DerKey = Buffer.from(plaintextAb).toString("utf8");

  // Format the base64 DER key into a standard PEM format
  return base64DerKey;
}

async function main() {
  // 1. Generate an ephemeral ECDH keypair to receive the encrypted key
  const { spki, pkcs8 } = await generateP256ECDH();
  const ephemeralPublicKeyB64 = bytesToB64(spki);
  const ephemeralPrivateKeyB64 = bytesToB64(pkcs8);

  // 2. Authenticate with Privy to get the encrypted authorization key
  console.log("Authenticating with Privy...");
  const authResp = await fetch("https://api.privy.io/v1/wallets/authenticate", {
    method: "POST",
    headers: {
      Authorization: `Basic ${basicAuth(PRIVY_APP_ID, PRIVY_APP_SECRET)}`,
      "privy-app-id": PRIVY_APP_ID,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      user_jwt: USER_JWT,
      encryption_type: "HPKE",
      recipient_public_key: ephemeralPublicKeyB64,
    }),
  });

  if (!authResp.ok) {
    console.error("Auth failed:", authResp.status, await authResp.text());
    throw new Error("Privy authentication failed");
  }

  const data: AuthResponse = await authResp.json();
  console.log("Authenticate data",data)
  const encryptedKey = data?.encrypted_authorization_key;

  if (!encryptedKey?.encapsulated_key || !encryptedKey?.ciphertext) {
    throw new Error("Missing encrypted_authorization_key in response");
  }
  console.log("✅ Authentication successful.");

  // 3. Decrypt the authorization key using the ephemeral private key
  const privyAuthKeyPem = await decryptAuthorizationKey(
    ephemeralPrivateKeyB64,
    encryptedKey.encapsulated_key,
    encryptedKey.ciphertext,
  );

  // 4. Create and sign the payload for the target RPC method
  const urlPath = `https://api.privy.io/v1/wallets/${WALLET_ID}/raw_sign`;
  const body = {
    params: {
      hash: "0x8e5b98f019743969c9d48096003fa8d9012ec2c92d0f8997eeca3a77a4b0fba9",
    },
  };

  const signature = generateAuthorizationSignature({
    authorizationPrivateKey: `wallet-auth:${privyAuthKeyPem}`,
    input: {
      version: 1,
      method: "POST",
      url: urlPath,
      body,
      headers: { "privy-app-id": PRIVY_APP_ID },
    },
  });
  console.log("✅ Authorization Signature:", signature);

  // 5. Call the protected RPC endpoint with the authorization signature
  console.log("Calling raw_sign endpoint...");
  const rawResp = await fetch(`${urlPath}`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${basicAuth(PRIVY_APP_ID, PRIVY_APP_SECRET)}`,
      "privy-app-id": PRIVY_APP_ID,
      "privy-authorization-signature": signature!,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });

  if (!rawResp.ok) {
    console.error("raw_sign failed:", rawResp.status, await rawResp.text());
    throw new Error("Privy raw_sign request failed");
  }

  console.log("📝 raw_sign response:", await rawResp.json());
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});