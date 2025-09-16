// getAuthorizationSignature.js
import crypto from "crypto";
import {canonicalize} from "json-canonicalize"; 

// Replace with your actual decrypted Privy authorization key
// (the one you got after decryption, starting with "wallet-auth:")
const PRIVY_AUTHORIZATION_KEY =
  "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgzlk8Q+HL5ePCFwcC0kXsEN6wVVfF1zPsWPxahdeMY5ehRANCAAQu15LdLqQ8FsKGmdjB4gOL323Ah/VIg/cmfmngmV7OROpDjaABH4sxgoy/ITz6ujSAY/Ij0Z5zlTMshLn6qjs/";

/**
 * Generate an authorization signature for Privy API
 */
function getAuthorizationSignature({ url, body }) {
  // Step 1: Build payload
  const payload = {
    version: 1,
    method: "POST",
    url,
    body,
    headers: {
      "privy-app-id": "cmdip4eml0064l40jspyn9iii",
      // If request has idempotency key, add here
    },
  };

  // Step 2: Canonicalize JSON (order keys deterministically)
  const serializedPayload = canonicalize(payload);
  const serializedPayloadBuffer = Buffer.from(serializedPayload);


  // Step 3: Wrap in PEM format
  const privateKeyAsPem = `-----BEGIN PRIVATE KEY-----\n${PRIVY_AUTHORIZATION_KEY}\n-----END PRIVATE KEY-----`;

  // Step 5: Create Node.js KeyObject
  const privateKey = crypto.createPrivateKey({
    key: privateKeyAsPem,
    format: "pem",
  });

  // Step 6: Sign payload
  const signatureBuffer = crypto.sign("sha256", serializedPayloadBuffer, privateKey);
  const signature = signatureBuffer.toString("base64");

  return signature;
}

// Example usage
const signature = getAuthorizationSignature({
  url: "/v1/wallets/fcvsl05oo5muzkdizixbvz62/raw_sign",
  body: {
    // Example body data you’re sending
    hash: "0x0bd61313bc3103e806197bd99da4a6a6c567428e27b099365fd52c16daf05f03",
  },
});

console.log("Authorization Signature:", signature);


