// decrypt.js
import { webcrypto } from "crypto";
import { CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";

const { subtle } = webcrypto;

function base64ToArrayBuffer(b64) {
  const raw = Buffer.from(b64, "base64");
  return raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength);
}

const privateKeyBase64 = ` `;
const encapsulated_key ="";
const ciphertext ="";

async function decryptAuthorizationKey(encKeyB64, ciphertextB64, pkcs8Base64) {
  const pkcs8 = base64ToArrayBuffer(pkcs8Base64.trim());
  const privKey = await subtle.importKey(
    "pkcs8",
    pkcs8,
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
    enc: Buffer.from(encKeyB64, "base64"),
  });

  const decrypted = await recipient.open(Buffer.from(ciphertextB64, "base64"));
  console.log(
    "🔓 Decrypted Auth Key (base64):",
    Buffer.from(decrypted).toString("base64")
  );
  console.log(
    "🔓 Decrypted Auth Key (hex):",
    Buffer.from(decrypted).toString("hex")
  );
}

decryptAuthorizationKey(encapsulated_key, ciphertext, privateKeyBase64);
