"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g = Object.create((typeof Iterator === "function" ? Iterator : Object).prototype);
    return g.next = verb(0), g["throw"] = verb(1), g["return"] = verb(2), typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
var node_crypto_1 = require("node:crypto");
var core_1 = require("@hpke/core");
var chacha20poly1305_1 = require("@hpke/chacha20poly1305");
var wallet_api_1 = require("@privy-io/server-auth/wallet-api");
var subtle = node_crypto_1.webcrypto.subtle;
// --- CONFIGURATION (replace with your values) ---
var WALLET_ID = "fcvsl05oo5muzkdizixbvz62";
var PRIVY_APP_ID = "cmdip4eml0064l40jspyn9iii";
var USER_JWT = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IlBrd2psay1LWHM2WUFCRjVkQ3hyZERUVUxGR3BfQ0ZwaUJBT2Z4WURmbzAifQ.eyJzaWQiOiJjbWZydnAwNzMwMWR4bDQwY2g5dG81dDN0IiwiaXNzIjoicHJpdnkuaW8iLCJpYXQiOjE3NTgzNDkxNjYsImF1ZCI6ImNtZGlwNGVtbDAwNjRsNDBqc3B5bjlpaWkiLCJzdWIiOiJkaWQ6cHJpdnk6Y21mMjZsOXZiMDE1bGxiMGJoZnUxZmRsZyIsImV4cCI6MTc1ODM1Mjc2Nn0.i3WhSq1048Bu4oNsjNYN3cuiPpTUmQSn2YT4L9W3-51Nj_f6H0YnbiYvAFln5P_J-5EPbt6PJS49SboUGAO-Ww";
var PRIVY_APP_SECRET = "5h8AKwmzMKqRZMwisEoP2vthHR5SDioonXgMrYoBSmSohwr3gDpywkiQEgY6HseGPFmGDsaqoyVJEf7yZaueu74E";
// --- UTILITY FUNCTIONS ---
/** Converts an ArrayBuffer to a Uint8Array. */
function abToBytes(ab) {
    return new Uint8Array(ab);
}
/** Converts a Uint8Array to a Base64 encoded string. */
function bytesToB64(bytes) {
    return Buffer.from(bytes).toString("base64");
}
/** Converts a Base64 encoded string to a Uint8Array. */
function b64ToBytes(b64) {
    return Uint8Array.from(Buffer.from(b64, "base64"));
}
/** Creates a Basic Authentication header value. */
function basicAuth(id, secret) {
    return Buffer.from("".concat(id, ":").concat(secret)).toString("base64");
}
// --- CORE LOGIC ---
/** Generates an ECDH P-256 keypair for HPKE. */
function generateP256ECDH() {
    return __awaiter(this, void 0, void 0, function () {
        var keyPair, spkiAb, pkcs8Ab;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])];
                case 1:
                    keyPair = _a.sent();
                    return [4 /*yield*/, subtle.exportKey("spki", keyPair.publicKey)];
                case 2:
                    spkiAb = _a.sent();
                    return [4 /*yield*/, subtle.exportKey("pkcs8", keyPair.privateKey)];
                case 3:
                    pkcs8Ab = _a.sent();
                    return [2 /*return*/, { spki: abToBytes(spkiAb), pkcs8: abToBytes(pkcs8Ab) }];
            }
        });
    });
}
/** Decrypts the authorization key from Privy using HPKE. */
function decryptAuthorizationKey(pkcs8B64, encB64, ctB64) {
    return __awaiter(this, void 0, void 0, function () {
        var suite, privateKey, recipient, plaintextAb, base64DerKey;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    suite = new core_1.CipherSuite({
                        kem: new core_1.DhkemP256HkdfSha256(),
                        kdf: new core_1.HkdfSha256(),
                        aead: new chacha20poly1305_1.Chacha20Poly1305(),
                    });
                    return [4 /*yield*/, subtle.importKey("pkcs8", b64ToBytes(pkcs8B64), { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])];
                case 1:
                    privateKey = _a.sent();
                    return [4 /*yield*/, suite.createRecipientContext({
                            recipientKey: privateKey,
                            enc: b64ToBytes(encB64).buffer,
                        })];
                case 2:
                    recipient = _a.sent();
                    return [4 /*yield*/, recipient.open(b64ToBytes(ctB64).buffer)];
                case 3:
                    plaintextAb = _a.sent();
                    base64DerKey = Buffer.from(plaintextAb).toString("utf8");
                    // Format the base64 DER key into a standard PEM format
                    return [2 /*return*/, base64DerKey];
            }
        });
    });
}
function main() {
    return __awaiter(this, void 0, void 0, function () {
        var _a, spki, pkcs8, ephemeralPublicKeyB64, ephemeralPrivateKeyB64, authResp, _b, _c, _d, data, encryptedKey, privyAuthKeyPem, urlPath, body, signature, rawResp, _e, _f, _g, _h, _j, _k;
        return __generator(this, function (_l) {
            switch (_l.label) {
                case 0: return [4 /*yield*/, generateP256ECDH()];
                case 1:
                    _a = _l.sent(), spki = _a.spki, pkcs8 = _a.pkcs8;
                    ephemeralPublicKeyB64 = bytesToB64(spki);
                    ephemeralPrivateKeyB64 = bytesToB64(pkcs8);
                    // 2. Authenticate with Privy to get the encrypted authorization key
                    console.log("Authenticating with Privy...");
                    return [4 /*yield*/, fetch("https://api.privy.io/v1/wallets/authenticate", {
                            method: "POST",
                            headers: {
                                Authorization: "Basic ".concat(basicAuth(PRIVY_APP_ID, PRIVY_APP_SECRET)),
                                "privy-app-id": PRIVY_APP_ID,
                                "Content-Type": "application/json",
                            },
                            body: JSON.stringify({
                                user_jwt: USER_JWT,
                                encryption_type: "HPKE",
                                recipient_public_key: ephemeralPublicKeyB64,
                            }),
                        })];
                case 2:
                    authResp = _l.sent();
                    if (!!authResp.ok) return [3 /*break*/, 4];
                    _c = (_b = console).error;
                    _d = ["Auth failed:", authResp.status];
                    return [4 /*yield*/, authResp.text()];
                case 3:
                    _c.apply(_b, _d.concat([_l.sent()]));
                    throw new Error("Privy authentication failed");
                case 4: return [4 /*yield*/, authResp.json()];
                case 5:
                    data = _l.sent();
                    encryptedKey = data === null || data === void 0 ? void 0 : data.encrypted_authorization_key;
                    if (!(encryptedKey === null || encryptedKey === void 0 ? void 0 : encryptedKey.encapsulated_key) || !(encryptedKey === null || encryptedKey === void 0 ? void 0 : encryptedKey.ciphertext)) {
                        throw new Error("Missing encrypted_authorization_key in response");
                    }
                    console.log("✅ Authentication successful.");
                    return [4 /*yield*/, decryptAuthorizationKey(ephemeralPrivateKeyB64, encryptedKey.encapsulated_key, encryptedKey.ciphertext)];
                case 6:
                    privyAuthKeyPem = _l.sent();
                    urlPath = "https://api.privy.io/v1/wallets/".concat(WALLET_ID, "/raw_sign");
                    body = {
                        hash: "0x0bd61313bc3103e806197bd99da4a6a6c567428e27b099365fd52c16daf05f03",
                    };
                    signature = (0, wallet_api_1.generateAuthorizationSignature)({
                        authorizationPrivateKey: "wallet-auth:".concat(privyAuthKeyPem),
                        input: {
                            version: 1,
                            method: "POST",
                            url: urlPath,
                            body: body,
                            headers: { "privy-app-id": PRIVY_APP_ID },
                        },
                    });
                    console.log("✅ Authorization Signature:", signature);
                    // 5. Call the protected RPC endpoint with the authorization signature
                    console.log("Calling raw_sign endpoint...");
                    return [4 /*yield*/, fetch("".concat(urlPath), {
                            method: "POST",
                            headers: {
                                Authorization: "Basic ".concat(basicAuth(PRIVY_APP_ID, PRIVY_APP_SECRET)),
                                "privy-app-id": PRIVY_APP_ID,
                                "privy-authorization-signature": signature,
                                "Content-Type": "application/json",
                            },
                            body: JSON.stringify(body),
                        })];
                case 7:
                    rawResp = _l.sent();
                    if (!!rawResp.ok) return [3 /*break*/, 9];
                    _f = (_e = console).error;
                    _g = ["raw_sign failed:", rawResp.status];
                    return [4 /*yield*/, rawResp.text()];
                case 8:
                    _f.apply(_e, _g.concat([_l.sent()]));
                    throw new Error("Privy raw_sign request failed");
                case 9:
                    _j = (_h = console).log;
                    _k = ["📝 raw_sign response:"];
                    return [4 /*yield*/, rawResp.json()];
                case 10:
                    _j.apply(_h, _k.concat([_l.sent()]));
                    return [2 /*return*/];
            }
        });
    });
}
main().catch(function (err) {
    console.error("Fatal error:", err);
    process.exit(1);
});
