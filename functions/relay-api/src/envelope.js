import crypto from "node:crypto";

/**
 * Binary envelope (v3), produced in the browser:
 *   "ORL3" | u16 wrappedKeyLen | wrappedKey (RSA-OAEP-SHA256)
 *   | metaIv(12) | u32 metaLen | metaCiphertext (AES-256-GCM, tag appended)
 *   | contentIv(12) | contentCiphertext (AES-256-GCM, tag appended)
 * The server only needs the header to read metadata; content is decrypted by authorised clients.
 */
export const HEADER_READ_BYTES = 131072;
const MAGIC = "ORL3";

export function parseHeader(buf) {
  const fail = (m) => { const e = new Error(m); e.envelope = true; throw e; };
  if (buf.length < 4 + 2 || buf.toString("latin1", 0, 4) !== MAGIC) fail("Not an Obsidian Relay envelope.");
  let o = 4;
  const wrappedLen = buf.readUInt16BE(o); o += 2;
  if (wrappedLen < 64 || wrappedLen > 1024 || buf.length < o + wrappedLen + 16) fail("Envelope key is malformed.");
  const wrapped = buf.subarray(o, o + wrappedLen); o += wrappedLen;
  const metaIv = buf.subarray(o, o + 12); o += 12;
  const metaLen = buf.readUInt32BE(o); o += 4;
  if (metaLen < 17 || metaLen > 65536 || buf.length < o + metaLen + 12) fail("Envelope metadata is malformed.");
  const metaCt = buf.subarray(o, o + metaLen); o += metaLen;
  const contentIv = buf.subarray(o, o + 12); o += 12;
  return { wrapped, metaIv, metaCt, contentIv, contentOffset: o };
}

export function unwrapKey(privateKey, wrapped) {
  return crypto.privateDecrypt(
    { key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
    wrapped,
  );
}

export function gcmDecrypt(key, iv, data) {
  if (data.length < 16) throw new Error("Ciphertext too short.");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(data.subarray(data.length - 16));
  return Buffer.concat([decipher.update(data.subarray(0, data.length - 16)), decipher.final()]);
}

export function readMetadata(privateKey, header) {
  const key = unwrapKey(privateKey, header.wrapped);
  if (key.length !== 32) throw new Error("Invalid content key.");
  const meta = JSON.parse(gcmDecrypt(key, header.metaIv, header.metaCt).toString("utf8"));
  return { key, meta };
}
