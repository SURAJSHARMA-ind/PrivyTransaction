import { Transaction } from "@mysten/sui/transactions";
import { SuiClient, getFullnodeUrl } from "@mysten/sui/client";
import { messageWithIntent } from "@mysten/sui/cryptography";
import { blake2b } from '@noble/hashes/blake2.js';
import { toHex } from "@mysten/sui/utils";

const client = new SuiClient({ url: getFullnodeUrl("testnet") });

async function hashTx() {
    // we have to generate wallet address of the prviate pubic key we generate 
    const sender = "0x8762666447873afe0dbbcc3e8f1fd4164c3251c42cfa3454f339173145db1a59";// It will change 

    const tx = new Transaction();
    tx.transferObjects(
        [tx.gas],
        tx.pure.address("0x8762666447873afe0dbbcc3e8f1fd4164c3251c42cfa3454f339173145db1a59")
    );
    tx.setSender(sender);

    const txBytes = await tx.build({ client });

    const intentMessage = messageWithIntent("TransactionData", txBytes);
    const digest = blake2b(intentMessage, { dkLen: 32 });
    const hashToSign = "0x" + toHex(digest);
    console.log("📝 Hash to sign:", hashToSign);
    return hashToSign;
}

const hashTxn = await hashTx();
const hashToSign = '0x' + hashTxn;


