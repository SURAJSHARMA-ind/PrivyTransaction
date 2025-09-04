// privy-signature.js
import { generateAuthorizationSignature } from "@privy-io/server-auth/wallet-api";

// Example request payload
const input = {
  version: 1,
  method: "POST",
  path: "/v1/wallets",  
  body: JSON.stringify({ hello: "world" }),
  headers: {
    "privy-app-id": "",
    // "privy-idempotency-key": "optional-key"
  },
};

// This should be your decrypted key from your decrypt.js output
const authorizationPrivateKey = "=="; // base64 string

// Generate the Privy-Authorization-Signature
const signature = generateAuthorizationSignature({
  input,
  authorizationPrivateKey,
});

console.log("Privy-Authorization-Signature:", signature);
