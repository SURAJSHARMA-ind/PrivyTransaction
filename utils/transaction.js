import {
  messageWithIntent,
  toSerializedSignature,
} from "@mysten/sui/cryptography";
import { blake2b } from "@noble/hashes/blake2.js";
import { SuiClient, getFullnodeUrl } from "@mysten/sui/client";
import { verifyTransactionSignature } from "@mysten/sui/verify";
import { Transaction } from "@mysten/sui/transactions";
import { toHex } from "@mysten/sui/utils";
// After you've added the data to your transaction
import { Ed25519PublicKey } from "@mysten/sui/keypairs/ed25519";

// Assuming your publicKey is in a variable, e.g., `rawPublicKeyB64`
const rawPublicKeyHex =
  "00c6be00db8ff388722b6cf11873d89074a726ffca7eef25b8f676d2810da19cc9";
const publicKeyBytes = new Uint8Array(
  Buffer.from(rawPublicKeyHex.slice(2), "hex")
); // Remove '00' prefix
const publicKey = new Ed25519PublicKey(publicKeyBytes);

// Now, use this new `publicKey` object in your function call.
const client = new SuiClient({ url: getFullnodeUrl("testnet") });
const sender =
  "0x8762666447873afe0dbbcc3e8f1fd4164c3251c42cfa3454f339173145db1a59"; // It will change

const address =
  "0x8762666447873afe0dbbcc3e8f1fd4164c3251c42cfa3454f339173145db1a59";
const tx = new Transaction();
tx.transferObjects(
  [tx.gas],
  tx.pure.address(
    "0x8762666447873afe0dbbcc3e8f1fd4164c3251c42cfa3454f339173145db1a59"
  )
);
tx.setSender(sender);

const txBytes = await tx.build({ client });
const intentMessage = messageWithIntent("TransactionData", txBytes);
const digest = blake2b(intentMessage, { dkLen: 32 });
const hashToSign = "0x" + toHex(digest);
console.log(hashToSign);
// Convert the digest to a hex string for signing

// Obtain the raw signature from Privy's raw_sign endpoint

const rawSignatureHex = ""; // output from Privy
const cleanHex = rawSignatureHex.startsWith("0x")
  ? rawSignatureHex.slice(2)
  : rawSignatureHex;

const signatureBytes = new Uint8Array(
  Buffer.from(cleanHex, "hex")
);

// Create and verify the transaction signature
const txSignature = toSerializedSignature({
  signature: signatureBytes,
  signatureScheme: "ED25519",
  publicKey: publicKey,
});
const signer = await verifyTransactionSignature(txBytes, txSignature, {
  address,
});
console.log(signer.toSuiAddress() === address); // true

const txResult = await client.executeTransactionBlock({
  transactionBlock: txBytes, // Uint8Array from tx.build()
  signature: txSignature,    // serialized signature
  options: {
    requestType: "WaitForLocalExecution",
  },
});

console.log(txResult)