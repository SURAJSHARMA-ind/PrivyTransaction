import {
  messageWithIntent,
  toSerializedSignature,
} from "@mysten/sui/cryptography";
import { blake2b } from "@noble/hashes/blake2.js";
import { SuiClient, getFullnodeUrl } from "@mysten/sui/client";
import { verifyTransactionSignature } from "@mysten/sui/verify";
import { Transaction } from "@mysten/sui/transactions";
import { toHex } from "@mysten/sui/utils";
import { Ed25519PublicKey } from "@mysten/sui/keypairs/ed25519";

const main = async () => {
  const client = new SuiClient({ url: getFullnodeUrl("testnet") });

  const sender = "0x8762666447873afe0dbbcc3e8f1fd4164c3251c42cfa3454f339173145db1a59";
  const recipient = "0xad195a42820b49f028cc29656b5442d64aa3ae25711bb39e5dd388f959fc2299";
  const amountToSend = 1_000n; // 1 SUI in MIST

  // Public key in hex from Privy
  const rawPublicKeyHex =
    "00c6be00db8ff388722b6cf11873d89074a726ffca7eef25b8f676d2810da19cc9";
  const publicKeyBytes = new Uint8Array(
    Buffer.from(rawPublicKeyHex.slice(2), "hex")
  );
  const publicKey = new Ed25519PublicKey(publicKeyBytes);

  // Build transaction
  const tx = new Transaction();
  tx.setSender(sender);

  // --- Transfer SUI using gas coin ---
  // Split gas coin for partial SUI amount
  const splitCoins = tx.splitCoins(tx.gas, [Number(amountToSend)]);
  // Transfer the split coin to recipient
  tx.transferObjects([splitCoins[0]], tx.pure.address(recipient));

  // Build transaction bytes
  const txBytes = await tx.build({ client });

  // Hash to sign
  const intentMessage = messageWithIntent("TransactionData", txBytes);
  const digest = blake2b(intentMessage, { dkLen: 32 });
  const hashToSign = "0x" + toHex(digest);
  console.log("Hash to sign:", hashToSign);

  // --- Get raw signature from Privy for hashToSign ---
  const rawSignatureHex =
    ""; // Privy output

  const cleanHex = rawSignatureHex.startsWith("0x")
    ? rawSignatureHex.slice(2)
    : rawSignatureHex;

  const signatureBytes = new Uint8Array(Buffer.from(cleanHex, "hex"));

  // Serialize signature
  const txSignature = toSerializedSignature({
    signature: signatureBytes,
    signatureScheme: "ED25519",
    publicKey,
  });

  // Optional: Verify transaction signature
  const signer = await verifyTransactionSignature(txBytes, txSignature, {
    address: sender,
  });
  console.log("Signature valid?", signer.toSuiAddress() === sender);

  // Execute transaction
  const txResult = await client.executeTransactionBlock({
    transactionBlock: txBytes,
    signature: txSignature,
    options: { requestType: "WaitForLocalExecution" },
  });

  console.log("Transaction result:", txResult);

//   // --- Check full transaction status ---
// const txStatus = await client.getTransactionBlock({
//   digest: txResult.digest,
//   options: { showEffects: true }
// });
// console.log("Full transaction status:", txStatus);
};

main().catch(console.error);
