import { webcrypto as crypto } from "node:crypto";
import { CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import { generateAuthorizationSignature } from "@privy-io/server-auth/wallet-api";
const { subtle } = crypto;
// --- CONFIGURATION (replace with your values) ---
const WALLET_ID = "fcvsl05oo5muzkdizixbvz62";
const PRIVY_APP_ID = "cmdip4eml0064l40jspyn9iii";
const USER_JWT = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IlBrd2psay1LWHM2WUFCRjVkQ3hyZERUVUxGR3BfQ0ZwaUJBT2Z4WURmbzAifQ.eyJzaWQiOiJjbWZydnAwNzMwMWR4bDQwY2g5dG81dDN0IiwiaXNzIjoicHJpdnkuaW8iLCJpYXQiOjE3NTgzNDkxNjYsImF1ZCI6ImNtZGlwNGVtbDAwNjRsNDBqc3B5bjlpaWkiLCJzdWIiOiJkaWQ6cHJpdnk6Y21mMjZsOXZiMDE1bGxiMGJoZnUxZmRsZyIsImV4cCI6MTc1ODM1Mjc2Nn0.i3WhSq1048Bu4oNsjNYN3cuiPpTUmQSn2YT4L9W3-51Nj_f6H0YnbiYvAFln5P_J-5EPbt6PJS49SboUGAO-Ww";
const PRIVY_APP_SECRET = "5h8AKwmzMKqRZMwisEoP2vthHR5SDioonXgMrYoBSmSohwr3gDpywkiQEgY6HseGPFmGDsaqoyVJEf7yZaueu74E";
// --- UTILITY FUNCTIONS ---
/** Converts an ArrayBuffer to a Uint8Array. */
function abToBytes(ab) {
    return new Uint8Array(ab);
}
/** Converts a Uint8Array to a Base64 encoded string. */
function bytesToB64(bytes) {
    return Buffer.from(bytes).toString("base64");
}
/** Converts a Base64 encoded string to a Uint8Array. */
function b64ToBytes(b64) {
    return Uint8Array.from(Buffer.from(b64, "base64"));
}
/** Safely converts a Uint8Array view to a standalone ArrayBuffer. */
function toArrayBuffer(bytes) {
    const copy = new Uint8Array(bytes.byteLength);
    copy.set(bytes);
    return copy.buffer;
}
/** Creates a Basic Authentication header value. */
function basicAuth(id, secret) {
    return Buffer.from(`${id}:${secret}`).toString("base64");
}
// --- CORE LOGIC ---
/** Generates an ECDH P-256 keypair for HPKE. */
async function generateP256ECDH() {
    const keyPair = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    const spkiAb = await subtle.exportKey("spki", keyPair.publicKey);
    const pkcs8Ab = await subtle.exportKey("pkcs8", keyPair.privateKey);
    return { spki: abToBytes(spkiAb), pkcs8: abToBytes(pkcs8Ab) };
}
/** Decrypts the authorization key from Privy using HPKE. */
async function decryptAuthorizationKey(pkcs8B64, encB64, ctB64) {
    const suite = new CipherSuite({
        kem: new DhkemP256HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new Chacha20Poly1305(),
    });
    const privateKey = await subtle.importKey("pkcs8", b64ToBytes(pkcs8B64), { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
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
    const data = await authResp.json();
    const encryptedKey = data?.encrypted_authorization_key;
    if (!encryptedKey?.encapsulated_key || !encryptedKey?.ciphertext) {
        throw new Error("Missing encrypted_authorization_key in response");
    }
    console.log("✅ Authentication successful.");
    // 3. Decrypt the authorization key using the ephemeral private key
    const privyAuthKeyPem = await decryptAuthorizationKey(ephemeralPrivateKeyB64, encryptedKey.encapsulated_key, encryptedKey.ciphertext);
    // 4. Create and sign the payload for the target RPC method
    const urlPath = `https://api.privy.io/v1/wallets/${WALLET_ID}/raw_sign`;
    const body = {
        params: {
            hash: "0x0bd61313bc3103e806197bd99da4a6a6c567428e27b099365fd52c16daf05f03",
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
            "privy-authorization-signature": signature,
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
