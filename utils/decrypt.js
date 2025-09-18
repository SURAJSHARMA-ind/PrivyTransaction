import {Chacha20Poly1305} from '@hpke/chacha20poly1305';
import {CipherSuite, DhkemP256HkdfSha256, HkdfSha256} from '@hpke/core';

// Initialize the cipher suite
const suite = new CipherSuite({
    kem: new DhkemP256HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Chacha20Poly1305(),
});

// Convert base64 to ArrayBuffer using browser APIs
const base64ToBuffer = (base64: string) => Uint8Array.from(atob(base64), (c) => c.charCodeAt(0)).buffer;

// Import private key using WebCrypto
const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    base64ToBuffer('insert-base64-encoded-private-key'),
    {
    name: 'ECDH',
    namedCurve: 'P-256',
    },
    true,
    ['deriveKey', 'deriveBits'],
);

// Create recipient context and decrypt
const recipient = await suite.createRecipientContext({
    recipientKey: privateKey,
    enc: base64ToBuffer('insert-encapsulated-key-from-api-response'),
});

return new TextDecoder().decode(await recipient.open(base64ToBuffer('insert-ciphertext-from-api-response')));