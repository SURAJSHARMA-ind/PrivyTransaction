// decrypt-hpke.js
import { webcrypto } from 'node:crypto';
import { CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from '@hpke/core';
import { Chacha20Poly1305 } from '@hpke/chacha20poly1305';
import { b64ToBytes } from './bytes.js';

const { subtle } = webcrypto;

// Fill these from your server response / storage:
const PRIVATE_KEY_PKCS8_B64 = 'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgs9OGAdjiXpcbH1tXk0kd8/ctAk8t7nS8cDbYVMBvpMKhRANCAARIWjMPEwMu3trw54ic6SFjcRazFJRCABxaOP9/vxjdKX4noZ1Q/lLp1zPlRdvuVGaQ/kfE+HgQa54ANwhK99NA';  // your ECDH P-256 private key (PKCS8) base64
const ENC_B64 = 'BDsol5tQ7V77I8LAVvN3t9OUDB98EPuymhtIgQj/9xfMuaDe2eEbE7xsVPOJDym99WjH6THeErci+Cs839szgXo=';                // HPKE encapsulated key (base64)
const CIPHERTEXT_B64 = 'HRZpW2odKBOOGEmGdsblnQJEL7GJpIBqLfeyBNcr2fgmL8W+PgAmy6/oST+Bh5LPzyikon38Ix6UP5bE6udlK2hOIIERcfpSXcBMZZFORG3Kn19PVryMfCFBt7eHI32C4fa6aVIeFEbdyspgNWF9GhdU9nyNPshFWM596+QCz9hvzy058tcKXdYEVMUDFAg92nr+8JnKMPVLBnj0/BbPClA/2ruroXVAcvbpn1dPC231lOyc0d7EvWvJ1BHnBg+xUs8USjxyro0=';         // HPKE ciphertext (base64)

async function decryptAuthorizationKey(pkcs8B64, encB64, ctB64) {
  // Keep everything as Uint8Array
  const pkcs8Bytes = b64ToBytes(pkcs8B64);
  const encBytes = b64ToBytes(encB64);
  const ctBytes = b64ToBytes(ctB64);

  const privKey = await subtle.importKey(
    'pkcs8',
    pkcs8Bytes, // BufferSource: Uint8Array is valid
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits'] // match our intent
  );

  const suite = new CipherSuite({
    kem: new DhkemP256HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Chacha20Poly1305(),
  });

  const recipient = await suite.createRecipientContext({
    recipientKey: privKey,
    enc: encBytes, // Uint8Array (not Buffer) to match docs
  });

  const plaintext = await recipient.open(ctBytes);

  // If you expect UTF-8 text:
  const text = new TextDecoder().decode(plaintext);
  // If you expect raw key bytes:
  // const base64Key = bytesToB64(new Uint8Array(plaintext));

  console.log('🔓 Decrypted (utf8):', text);
  return plaintext;
}

decryptAuthorizationKey(PRIVATE_KEY_PKCS8_B64, ENC_B64, CIPHERTEXT_B64)
  .catch((e) => {
    console.error('Decrypt error:', e);
    process.exit(1);
  });
