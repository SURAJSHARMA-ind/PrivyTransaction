# Privy Sign Proof of Concept

This project demonstrates how to interact with the Privy API for secure transaction signing.

## Steps to Run

1. **Generate Keypair**
   - Run `keygen_ecdh-p256.js` to generate an ECDH P-256 keypair.
   - Pass the generated public key to [`https://api.privy.io/v1/wallets/authenticate`](https://api.privy.io/v1/wallets/authenticate).

2. **Decrypt Response**
   - Use the response from the authentication endpoint.
   - Run `derypt-hpke.js` to decrypt the response.

3. **Generate Authorization Signature**
   - Pass all required values from the previous steps.
   - Run `generateAuthorizationSignature.js` to generate the authorization signature.

---

**Note:** Update the scripts with your actual