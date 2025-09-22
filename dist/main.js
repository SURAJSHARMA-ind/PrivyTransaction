import { webcrypto as crypto } from "node:crypto";
import { CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import { generateAuthorizationSignature } from "@privy-io/server-auth/wallet-api";
import { messageWithIntent, toSerializedSignature, } from "@mysten/sui/cryptography";
import { SuiClient, getFullnodeUrl } from "@mysten/sui/client";
import { verifyTransactionSignature } from "@mysten/sui/verify";
import { blake2b } from "@noble/hashes/blake2.js";
import { Transaction } from "@mysten/sui/transactions";
import { toHex } from "@mysten/sui/utils";
import { Ed25519PublicKey } from "@mysten/sui/keypairs/ed25519";
// After you've added the data to your transaction
const { subtle } = crypto;
// --- CONFIGURATION (replace with your values) ---
const WALLET_ID = "fcvsl05oo5muzkdizixbvz62";
const PRIVY_APP_ID = "cmdip4eml0064l40jspyn9iii";
const USER_JWT = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IlBrd2psay1LWHM2WUFCRjVkQ3hyZERUVUxGR3BfQ0ZwaUJBT2Z4WURmbzAifQ.eyJzaWQiOiJjbWZ1dHZ2ZXowMTFzaWMwY3czaGtsN2IzIiwiaXNzIjoicHJpdnkuaW8iLCJpYXQiOjE3NTg1Mjc1MjYsImF1ZCI6ImNtZGlwNGVtbDAwNjRsNDBqc3B5bjlpaWkiLCJzdWIiOiJkaWQ6cHJpdnk6Y21mMjZsOXZiMDE1bGxiMGJoZnUxZmRsZyIsImV4cCI6MTc1ODUzMTEyNn0.afc1wZSakct94MxQP5br9KnPruoggRs5o2m51fVDCyYkxiCRdx_NOCFQQ3QtW-30r8AHh5Iyq6iKS7MsYWr58A";
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
    console.log("Authenticate Response", data);
    const wallet = data.wallets?.[0];
    if (!wallet?.public_key) {
        throw new Error("Wallet publicKey is missing");
    }
    let publicKeyStr;
    if (typeof wallet.public_key === "string") {
        publicKeyStr = wallet.public_key;
    }
    else if ("Ed25519" in wallet.public_key) {
        publicKeyStr = wallet.public_key.Ed25519;
    }
    else {
        throw new Error("Unknown public_key format");
    }
    // Convert base64 string to PublicKey instance
    const publicKeyObj = new Ed25519PublicKey(publicKeyStr);
    // ...existing code...
    const address = data.wallets?.[0]?.address;
    if (!address) {
        throw new Error("Wallet address is missing");
    }
    // ...existing code...
    console.log("publickey", publicKeyObj);
    console.log("address", address);
    const encryptedKey = data?.encrypted_authorization_key;
    if (!encryptedKey?.encapsulated_key || !encryptedKey?.ciphertext) {
        throw new Error("Missing encrypted_authorization_key in response");
    }
    console.log("✅ Authentication successful.");
    // 3. Decrypt the authorization key using the ephemeral private key
    const privyAuthKeyPem = await decryptAuthorizationKey(ephemeralPrivateKeyB64, encryptedKey.encapsulated_key, encryptedKey.ciphertext);
    const sender = "0x8762666447873afe0dbbcc3e8f1fd4164c3251c42cfa3454f339173145db1a59"; //
    const tx = new Transaction();
    tx.transferObjects([tx.gas], tx.pure.address(address.toString()));
    tx.setSender(sender);
    const client = new SuiClient({ url: getFullnodeUrl("testnet") });
    // build transaction
    const txBytes = await tx.build({ client });
    const intentMessage = messageWithIntent("TransactionData", txBytes);
    const digest = blake2b(intentMessage, { dkLen: 32 });
    // Convert the digest to a hex string for signing
    const hashToSign = "0x" + toHex(digest);
    console.log("hashToSign", hashToSign);
    // 4. Create and sign the payload for the target RPC method
    const urlPath = `https://api.privy.io/v1/wallets/${WALLET_ID}/raw_sign`;
    const body = {
        params: {
            hash: hashToSign,
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
    // console.log("📝 raw_sign response:", await rawResp.json());
    const rawSign = await rawResp.json();
    console.log("rawsign", rawSign);
    const rawSignature = await rawSign.data.signature;
    console.log("Rawsign", rawSignature);
    const txSignature = toSerializedSignature({
        signature: rawSignature,
        signatureScheme: "ED25519",
        publicKey: publicKeyObj,
    });
    const signer = await verifyTransactionSignature(txBytes, txSignature, { address });
    console.log(signer.toSuiAddress() === address); // true
}
main().catch((err) => {
    console.error("Fatal error:", err);
    process.exit(1);
});
