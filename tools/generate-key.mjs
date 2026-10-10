// Generates the RSA key for the relay-api function.
// Usage:  node tools/generate-key.mjs
// Copy the single-line value printed below into the function variable VAULT_RSA_PRIVATE_KEY.
import crypto from "node:crypto";
import fs from "node:fs";

const { privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 3072 });
const pem = privateKey.export({ type: "pkcs8", format: "pem" });
fs.writeFileSync("private_key.pem", pem, { mode: 0o600 });
console.log("Saved private_key.pem (keep it private, never commit it).\n");
console.log("Paste this as the value of VAULT_RSA_PRIVATE_KEY:\n");
console.log(pem.trim().replace(/\n/g, "\\n"));
