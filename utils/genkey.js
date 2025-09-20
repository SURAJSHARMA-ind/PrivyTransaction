import * as crypto from "crypto";

async function generateEcdhP256KeyPair() {
  // Generate a P-256 key pair
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "ECDH",
      namedCurve: "P-256",
    },
    true,
    ["deriveBits"]
  );

  // The privateKey will be used later to decrypt the encapsulatedKey data returned from the /v1/user_signers/authenticate endpoint.
  const privateKey = keyPair.privateKey;
  const privateKeyRaw = await crypto.subtle.exportKey("pkcs8", privateKey);
  const privateKeyBase64 = Buffer.from(privateKeyRaw).toString("base64");

  // The publicKey will be used to encrypt the session key and will be sent to the /v1/user_signers/authenticate endpoint.
  // The publicKey must be a base64-encoded, SPKI-format string
  const publicKeyInSpkiFormat = await crypto.subtle.exportKey(
    "spki",
    keyPair.publicKey
  );
  const recipientPublicKey = Buffer.from(publicKeyInSpkiFormat).toString(
    "base64"
  );
  console.log("privateKey", privateKeyBase64);
  console.log("recipientPublicKey", recipientPublicKey);
  return { privateKey, recipientPublicKey };
}

generateEcdhP256KeyPair();
