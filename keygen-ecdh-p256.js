// keygen-ecdh-p256.js
import { webcrypto as crypto } from 'node:crypto';
import { abToBytes, bytesToB64 } from './bytes.js';

const { subtle } = crypto;

async function generateP256ECDH() {
  const keyPair = await subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits'] // HPKE needs deriveBits only
  );

  const spki = abToBytes(await subtle.exportKey('spki', keyPair.publicKey));
  const pkcs8 = abToBytes(await subtle.exportKey('pkcs8', keyPair.privateKey));

  console.log('[ECDH] Public Key (SPKI, base64) - give this to the server:');
  console.log(bytesToB64(spki));
  console.log('[ECDH] Private Key (PKCS8, base64) - keep secret:');
  console.log(bytesToB64(pkcs8));

  // If you really need JWK, do it carefully; base64url != base64
  // const jwk = await subtle.exportKey('jwk', keyPair.privateKey);
  // console.log('[ECDH] Private JWK.d (base64url) - DO NOT LOG IN PROD');
  // console.log(jwk.d);
}

generateP256ECDH().catch((e) => {
  console.error('Keygen error:', e);
  process.exit(1);
});
