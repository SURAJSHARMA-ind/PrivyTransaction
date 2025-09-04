import { webcrypto as crypto } from 'node:crypto';

const { subtle } = crypto;

async function generateP256SpkiBase64(mode = 'ecdh') {
  const algo = mode === 'ecdsa' ? 'ECDSA' : 'ECDH';
  const usages = mode === 'ecdsa' ? ['verify'] : ['deriveBits'];
  const keyPair = await subtle.generateKey(
    { name: algo, namedCurve: 'P-256' },
    true,
    usages
  );

  const spki = await subtle.exportKey('spki', keyPair.publicKey);
  const spkiB64 = Buffer.from(new Uint8Array(spki)).toString('base64');

  const pkcs8 = await subtle.exportKey('pkcs8', keyPair.privateKey);
  const pkcs8B64 = Buffer.from(new Uint8Array(pkcs8)).toString('base64');

  const jwk = await subtle.exportKey('jwk', keyPair.privateKey);

  console.log(`[${algo}] Public Key (SPKI, base64) -> paste this into Privy:`);
  console.log(spkiB64);
  console.log(`[${algo}] Private Key (PKCS8, base64):`);
  console.log(pkcs8B64);
  console.log(`[${algo}] Private Key (JWK d - base64url):`);
  console.log(jwk.d);
}

const modeArg = process.argv[2] && process.argv[2].toLowerCase();
const mode = modeArg === 'ecdsa' ? 'ecdsa' : 'ecdh';

generateP256SpkiBase64(mode).catch((err) => {
  console.error('Error generating P-256 keys:', err);
  process.exit(1);
});


