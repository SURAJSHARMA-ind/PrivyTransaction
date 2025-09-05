import {
  messageWithIntent,
  toSerializedSignature,
} from "@mysten/sui/cryptography";
import { blake2b } from "@noble/hashes/blake2b";
import { verifyTransactionSignature } from "@mysten/sui/verify";
// After you've added the data to your transaction
const txBytes = await tx.build({ client });
const intentMessage = messageWithIntent("TransactionData", txBytes);
const digest = blake2b(intentMessage, { dkLen: 32 });

// Convert the digest to a hex string for signing
const hashToSign = '0x' + toHex(digest);

// Obtain the raw signature from Privy's raw_sign endpoint
const rawSignature = ... // call privy raw_sign on `hashToSign`

// Create and verify the transaction signature
const txSignature = toSerializedSignature({
signature: rawSignature,
signatureScheme: "ED25519",
publicKey,
});
const signer = await verifyTransactionSignature(txBytes, txSignature, {address});
console.log(signer.toSuiAddress() === address); // true