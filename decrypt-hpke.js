// decrypt-hpke.js
import { webcrypto } from 'node:crypto';
import { CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from '@hpke/core';
import { Chacha20Poly1305 } from '@hpke/chacha20poly1305';
import { b64ToBytes } from './bytes.js';

const { subtle } = webcrypto;

// Fill these from your server response / storage:
const PRIVATE_KEY_PKCS8_B64 = 'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgvvyWw1anFt2GWkAZ9RDiD05QekQl3V/oqzB4wXaBDU2hRANCAATfioVWQ6C34rFeCKfWid9i2PiL6QXB3TfXKuIBFn1d+aO5cqG4YJKwcHnLCX9V2zePPViqyKnFVUPIEZNz5FPi';  // your ECDH P-256 private key (PKCS8) base64
const ENC_B64 = 'BB2mB2TWdAnBBnHxaQ7nb+/rHPN+h9fnpYXZa0OI+enE9KhBLvM57DIdA9VmZ0axIymUBXHPoD+kY61HDfnbjAY=';                // HPKE encapsulated key (base64)
const CIPHERTEXT_B64 = 'mzrKcSC+TO25jzgz7TPYWrowCPJ5tNFrMa2z49jyRGdzJNjZ5W1N6Y+fh6kXq3kmlUiRcnqvUsPtpzmbDUZjKjjJ+gRCnpfU1+2D+aoqYsTpLE+mSH+mcfvmRDKdMAzrciO/2NcCnxmyQJozlEiVVf3SW7+3OUts7l1+EBqgO/oxaiSi9897s2NWOdT/6YMSBbEj3F1dr6qkvPGnoJgEQ6tvMeooFscKwhXqiufKBgTkwOOU4F03eoYxWuY9BcRE5bAP0bx0UFw=';         // HPKE ciphertext (base64)

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
