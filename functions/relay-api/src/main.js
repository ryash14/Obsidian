import crypto from "node:crypto";
import { Api, ApiError, Db, Query, Storage } from "./appwrite.js";
import { HEADER_READ_BYTES, gcmDecrypt, parseHeader, readMetadata, unwrapKey } from "./envelope.js";

/* ================= configuration ================= */
const env = process.env;
const IDS = {
  database: env.RELAY_DATABASE_ID || "relay",
  items: "items",
  codes: "codes",
  attempts: "attempts",
  bucket: env.RELAY_BUCKET_ID || "relay-files",
};
const MAX_FAILURES = Number(env.ACCESS_MAX_FAILURES || 5);
const LOCK_SECONDS = Number(env.ACCESS_LOCK_SECONDS || 300);
const MAX_BYTES = Number(env.RELAY_MAX_BYTES || 50 * 1024 * 1024);
const ALLOWED_ORIGINS = (env.ALLOWED_ORIGINS || "*").split(",").map((s) => s.trim()).filter(Boolean);

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

/* ================= keys ================= */
let keyState = null;
function keys() {
  if (keyState) return keyState;
  const pem = (env.VAULT_RSA_PRIVATE_KEY || "").replace(/\\n/g, "\n").trim();
  if (!pem) throw new HttpError(500, "Server is not configured: VAULT_RSA_PRIVATE_KEY is missing.");
  let privateKey;
  try { privateKey = crypto.createPrivateKey(pem); }
  catch { throw new HttpError(500, "Server is not configured: VAULT_RSA_PRIVATE_KEY is not a valid PEM key."); }
  const spki = crypto.createPublicKey(privateKey).export({ type: "spki", format: "der" });
  const pepper = crypto.createHash("sha256").update(privateKey.export({ type: "pkcs8", format: "der" })).digest();
  keyState = { privateKey, spki, pepper };
  return keyState;
}
const codeId = (code) => crypto.createHmac("sha256", keys().pepper).update(`code:${code}`).digest("hex").slice(0, 32);
const ipId = (ip) => crypto.createHmac("sha256", keys().pepper).update(`ip:${ip}`).digest("hex").slice(0, 32);
const validCode = (c) => typeof c === "string" && /^\d{6}$/.test(c);
const validFileId = (id) => typeof id === "string" && /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,35}$/.test(id);

/* ================= schema bootstrap (runs once per container) ================= */
let schemaPromise = null;
function ensureSchema(db, storage) {
  if (!schemaPromise) {
    schemaPromise = (async () => {
      await db.detect();
      await db.ensureDatabase("Obsidian Relay");
      await Promise.all([
        db.ensureTable(IDS.items, "Items"),
        db.ensureTable(IDS.codes, "Access codes"),
        db.ensureTable(IDS.attempts, "Access attempts"),
        storage.ensureBucket(IDS.bucket, "Relay files"),
      ]);
      const itemCols = [
        ["scope", "string", 64], ["fileId", "string", 64], ["name", "string", 512], ["type", "string", 255],
        ["size", "integer"], ["encryptedAt", "string", 40], ["relativePath", "string", 1024],
        ["wrappedKey", "string", 1400], ["contentIv", "string", 32], ["contentOffset", "integer"],
      ];
      await Promise.all([
        ...itemCols.map(([k, t, s]) => db.ensureColumn(IDS.items, k, t, s)),
        db.ensureColumn(IDS.codes, "createdAt", "string", 40),
        db.ensureColumn(IDS.attempts, "count", "integer"),
        db.ensureColumn(IDS.attempts, "until", "integer"),
      ]);
      await Promise.all([
        db.waitAvailable(IDS.items, itemCols.map((c) => c[0])),
        db.waitAvailable(IDS.codes, ["createdAt"]),
        db.waitAvailable(IDS.attempts, ["count", "until"]),
      ]);
      await db.ensureIndex(IDS.items, "scope_idx", ["scope"]);
      await db.waitAvailable(IDS.items, [], ["scope_idx"]);
    })().catch((err) => { schemaPromise = null; throw err; });
  }
  return schemaPromise;
}

/* ================= request helpers ================= */
function corsHeaders(req) {
  const origin = req.headers["origin"] || "";
  const allow = ALLOWED_ORIGINS.includes("*") ? "*" : ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0] || "";
  return {
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-Access-Code",
    "Access-Control-Expose-Headers": "Content-Disposition, Content-Type",
    "Access-Control-Max-Age": "86400",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    Vary: "Origin",
  };
}

function readJson(req) {
  try { if (req.bodyJson && typeof req.bodyJson === "object") return req.bodyJson; } catch { /* not JSON */ }
  const raw = typeof req.bodyText === "string" ? req.bodyText : typeof req.bodyRaw === "string" ? req.bodyRaw : req.body;
  if (raw && typeof raw === "object") return raw;
  try { return raw ? JSON.parse(raw) : {}; } catch { throw new HttpError(400, "Request body must be JSON."); }
}

function clientIp(req) {
  const h = req.headers;
  return (h["x-forwarded-for"] || h["x-real-ip"] || h["x-appwrite-client-ip"] || "unknown").split(",")[0].trim();
}

function publicEndpoint() {
  return (env.PUBLIC_APPWRITE_ENDPOINT || env.APPWRITE_FUNCTION_API_ENDPOINT || "").replace(/\/$/, "");
}

/* ================= access-code guard ================= */
async function checkLock(db, ip) {
  const row = await db.get(IDS.attempts, ipId(ip));
  if (row && Number(row.until) > Date.now() / 1000) throw new HttpError(429, "Too many attempts. Try again in a few minutes.");
  return row;
}
async function registerFailure(db, ip, row) {
  const now = Math.floor(Date.now() / 1000);
  let count = (row && Number(row.until) <= now ? Number(row.count) || 0 : 0) + 1;
  let until = 0;
  if (count >= MAX_FAILURES) { count = 0; until = now + LOCK_SECONDS; }
  if (row) await db.update(IDS.attempts, row.$id, { count, until });
  else await db.create(IDS.attempts, ipId(ip), { count, until }).catch(() => {});
}
async function clearFailures(db, ip, row) {
  if (row && (Number(row.count) || Number(row.until))) await db.update(IDS.attempts, row.$id, { count: 0, until: 0 }).catch(() => {});
}

/** Resolve the storage scope for this request: "public" or the hashed access code. */
async function resolveScope(db, req, code = req.headers["x-access-code"]) {
  if (code === undefined || code === null || code === "") return "public";
  const ip = clientIp(req);
  const attempts = await checkLock(db, ip);
  const id = validCode(String(code)) ? codeId(String(code)) : null;
  if (!id || !(await db.get(IDS.codes, id))) {
    await registerFailure(db, ip, attempts);
    throw new HttpError(404, "Access code not found.");
  }
  await clearFailures(db, ip, attempts);
  return id;
}

async function ownedItem(db, id, scope) {
  if (!validFileId(id)) throw new HttpError(404, "Item not found.");
  const row = await db.get(IDS.items, id);
  if (!row || row.scope !== scope) throw new HttpError(404, "Item not found.");
  return row;
}

const toItem = (r) => ({
  id: r.$id, name: r.name, type: r.type, size_bytes: Number(r.size) || 0,
  encrypted_at: r.encryptedAt, relative_path: r.relativePath || "",
});

/* ================= route handlers ================= */
async function handle(ctx) {
  const { req, db, storage } = ctx;
  const path = (req.path || "/").replace(/\/+$/, "") || "/";
  const method = req.method;
  const route = (m, re) => (method === m ? path.match(re) : null);
  let m;

  if (route("GET", /^\/(health)?$/)) return { json: { ok: true, service: "obsidian-relay" } };

  await db.detect();
  await ensureSchema(db, storage);

  if (route("GET", /^\/config$/)) {
    return { json: {
      endpoint: publicEndpoint(),
      projectId: env.APPWRITE_FUNCTION_PROJECT_ID,
      bucketId: IDS.bucket,
      maxBytes: MAX_BYTES,
      publicKey: keys().spki.toString("base64"),
    } };
  }


  if (route("POST", /^\/code\/verify$/)) {
    const { code } = readJson(req);
    await resolveScope(db, req, String(code ?? ""));
    return { json: { ok: true } };
  }

  if (route("POST", /^\/code\/create$/)) {
    const { code } = readJson(req);
    if (!validCode(String(code ?? ""))) throw new HttpError(400, "Access code must be exactly 6 digits.");
    const ip = clientIp(req);
    const attempts = await checkLock(db, ip);
    try {
      await db.create(IDS.codes, codeId(String(code)), { createdAt: new Date().toISOString() });
    } catch (err) {
      if (err.status === 409) {
        await registerFailure(db, ip, attempts);   // creating taken codes counts as a guess
        throw new HttpError(409, "That access code is already in use. Choose another.");
      }
      throw err;
    }
    return { status: 201, json: { ok: true } };
  }

  if (route("POST", /^\/relay$/)) {
    const scope = await resolveScope(db, req);
    const { fileId } = readJson(req);
    if (!validFileId(fileId)) throw new HttpError(400, "Invalid file reference.");
    let file;
    try { file = await storage.getFile(IDS.bucket, fileId); }
    catch (err) { if (err.status === 404) throw new HttpError(404, "Uploaded file was not found."); throw err; }
    if (file.chunksTotal && file.chunksUploaded < file.chunksTotal) throw new HttpError(409, "Upload is not complete yet.");

    const reject = async (msg) => { await storage.deleteFile(IDS.bucket, fileId); throw new HttpError(400, msg); };
    let header, meta;
    try {
      const head = await storage.download(IDS.bucket, fileId, `bytes=0-${HEADER_READ_BYTES - 1}`);
      header = parseHeader(head);
      ({ meta } = readMetadata(keys().privateKey, header));
    } catch (err) {
      if (err instanceof ApiError) throw err;
      return reject("The encrypted payload is invalid.");
    }
    const size = Number(meta.size_bytes);
    const name = String(meta.name || "").trim();
    if (!name || !Number.isFinite(size) || size < 0) return reject("The encrypted payload metadata is invalid.");
    if (size > MAX_BYTES) return reject(`File exceeds the ${Math.round(MAX_BYTES / 1048576)} MB limit.`);
    const total = Number(file.sizeOriginal ?? file.size);
    if (Number.isFinite(total) && total !== header.contentOffset + size + 16) return reject("The encrypted payload size does not match.");

    try {
      await db.create(IDS.items, fileId, {
        scope, fileId,
        name: name.slice(0, 512),
        type: String(meta.type || "application/octet-stream").slice(0, 255),
        size,
        encryptedAt: String(meta.encrypted_at || new Date().toISOString()).slice(0, 40),
        relativePath: String(meta.relative_path || "").slice(0, 1024),
        wrappedKey: header.wrapped.toString("base64"),
        contentIv: header.contentIv.toString("base64"),
        contentOffset: header.contentOffset,
      });
    } catch (err) {
      if (err.status === 409) throw new HttpError(409, "This upload was already registered.");
      throw err;
    }
    return { status: 201, json: { ok: true, id: fileId } };
  }

  if (route("GET", /^\/catalog$/)) {
    const scope = await resolveScope(db, req);
    const rows = await db.list(IDS.items, [Query.equal("scope", scope)]);
    return { json: rows.map(toItem) };
  }

  if ((m = route("GET", /^\/item\/([^/]+)\/access$/))) {
    const scope = await resolveScope(db, req);
    const row = await ownedItem(db, m[1], scope);
    const key = unwrapKey(keys().privateKey, Buffer.from(row.wrappedKey, "base64"));
    let url = null;
    try {
      const token = await storage.createToken(IDS.bucket, row.fileId, 10);
      if (token && token.secret && publicEndpoint()) {
        url = `${publicEndpoint()}/storage/buckets/${IDS.bucket}/files/${row.fileId}/download`
          + `?project=${encodeURIComponent(env.APPWRITE_FUNCTION_PROJECT_ID)}&token=${encodeURIComponent(token.secret)}`;
      }
    } catch (err) {
      ctx.log(`File token unavailable, client will use the proxy route: ${err.message}`);
    }
    return { json: {
      ...toItem(row), url,
      key: key.toString("base64"), iv: row.contentIv, offset: Number(row.contentOffset),
    } };
  }

  if ((m = route("GET", /^\/item\/([^/]+)\/raw$/))) {
    const scope = await resolveScope(db, req);
    const row = await ownedItem(db, m[1], scope);
    const blob = await storage.download(IDS.bucket, row.fileId);
    const header = parseHeader(blob);
    const key = unwrapKey(keys().privateKey, header.wrapped);
    const plain = gcmDecrypt(key, header.contentIv, blob.subarray(header.contentOffset));
    const safe = String(row.name).replace(/[^\w.\- ]+/g, "_") || "download.bin";
    return { binary: plain, headers: {
      "Content-Type": row.type || "application/octet-stream",
      "Content-Disposition": `attachment; filename="${safe}"; filename*=UTF-8''${encodeURIComponent(row.name)}`,
    } };
  }

  if ((m = route("POST", /^\/item\/([^/]+)\/delete$/))) {
    const scope = await resolveScope(db, req);
    const row = await ownedItem(db, m[1], scope);
    await storage.deleteFile(IDS.bucket, row.fileId);
    await db.remove(IDS.items, row.$id);
    return { status: 200, json: { ok: true } };
  }

  if (route("POST", /^\/clear$/)) {
    const scope = await resolveScope(db, req);
    const rows = await db.list(IDS.items, [Query.equal("scope", scope)]);
    for (let i = 0; i < rows.length; i += 10) {
      await Promise.all(rows.slice(i, i + 10).map(async (r) => {
        await storage.deleteFile(IDS.bucket, r.fileId);
        await db.remove(IDS.items, r.$id);
      }));
    }
    return { json: { ok: true, removed: rows.length } };
  }

  throw new HttpError(404, "Route not found.");
}

/* ================= entrypoint ================= */
export default async ({ req, res, log, error }) => {
  const headers = corsHeaders(req);
  if (req.method === "OPTIONS") return res.send("", 204, headers);

  try {
    const apiKey = req.headers["x-appwrite-key"] || env.APPWRITE_API_KEY;
    if (!apiKey) throw new HttpError(500, "Server is not configured: no Appwrite API key available to the function.");
    const api = new Api({ endpoint: env.APPWRITE_FUNCTION_API_ENDPOINT, projectId: env.APPWRITE_FUNCTION_PROJECT_ID, key: apiKey });
    const ctx = { req, log, db: new Db(api, IDS.database), storage: new Storage(api) };
    const out = await handle(ctx);
    if (out.binary) {
      const h = { ...headers, ...out.headers };
      return typeof res.binary === "function" ? res.binary(out.binary, 200, h) : res.send(out.binary, 200, h);
    }
    return res.json(out.json, out.status || 200, headers);
  } catch (err) {
    if (err instanceof HttpError) return res.json({ error: err.message }, err.status, headers);
    error(`${err.name}: ${err.message}\n${err.stack || ""}`);
    if (err instanceof ApiError) {
      const hint = err.status === 401 ? " Check the function's scopes in Settings." : "";
      return res.json({ error: `Storage service error: ${err.message}.${hint}` }, 502, headers);
    }
    return res.json({ error: "Unexpected server error." }, 500, headers);
  }
};
