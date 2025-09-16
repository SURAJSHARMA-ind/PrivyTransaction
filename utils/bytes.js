// bytes.js
export function b64ToBytes(b64) {
  // Standard base64 -> Uint8Array
  return new Uint8Array(Buffer.from(b64.trim(), 'base64'));
}

export function bytesToB64(bytes) {
  // Uint8Array -> standard base64
  return Buffer.from(bytes).toString('base64');
}

export function abToBytes(ab) {
  // ArrayBuffer -> Uint8Array view (zero-copy)
  return new Uint8Array(ab);
}
