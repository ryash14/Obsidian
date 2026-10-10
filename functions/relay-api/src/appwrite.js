/**
 * Minimal, dependency-free Appwrite REST client.
 * Prefers the TablesDB API and falls back to the legacy Databases API automatically,
 * so it works on Appwrite Cloud and on self-hosted 1.6+.
 */
export class ApiError extends Error {
  constructor(status, message, type = "") {
    super(message || `Appwrite request failed (${status})`);
    this.status = status;
    this.type = type;
  }
}

const q = {
  equal: (attribute, values) => JSON.stringify({ method: "equal", attribute, values: [].concat(values) }),
  limit: (n) => JSON.stringify({ method: "limit", values: [n] }),
  cursorAfter: (id) => JSON.stringify({ method: "cursorAfter", values: [id] }),
};
export { q as Query };

export class Api {
  constructor({ endpoint, projectId, key }) {
    this.endpoint = endpoint.replace(/\/$/, "");
    this.projectId = projectId;
    this.key = key;
  }

  async call(method, path, { json, query, headers = {}, raw = false } = {}) {
    const url = new URL(this.endpoint + path);
    for (const [k, v] of Object.entries(query || {})) {
      if (Array.isArray(v)) v.forEach((item) => url.searchParams.append(`${k}[]`, item));
      else if (v !== undefined) url.searchParams.set(k, v);
    }
    const init = {
      method,
      headers: { "X-Appwrite-Project": this.projectId, "X-Appwrite-Key": this.key, ...headers },
    };
    if (json !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(json);
    }
    let res;
    try {
      res = await fetch(url, init);
    } catch (err) {
      throw new ApiError(502, `Could not reach Appwrite: ${err.message}`);
    }
    if (raw && res.ok) return res;
    const text = await res.text();
    let data = {};
    try { data = text ? JSON.parse(text) : {}; } catch { data = { message: text }; }
    if (!res.ok) throw new ApiError(res.status, data.message, data.type);
    return data;
  }
}

export class Db {
  constructor(api, databaseId) {
    this.api = api;
    this.databaseId = databaseId;
    this.mode = null;
  }

  async detect() {
    if (this.mode) return this.mode;
    if (!Db.detected) {
      try {
        await this.api.call("GET", "/tablesdb", { query: { queries: [q.limit(1)] } });
        Db.detected = "tables";
      } catch (err) {
        if (err.status === 404) Db.detected = "legacy";
        else throw err;
      }
    }
    this.mode = Db.detected;
    return this.mode;
  }

  get t() { return this.mode === "tables"; }
  dbPath() { return this.t ? `/tablesdb/${this.databaseId}` : `/databases/${this.databaseId}`; }
  tablePath(table) { return `${this.dbPath()}/${this.t ? "tables" : "collections"}/${table}`; }
  rowsPath(table) { return `${this.tablePath(table)}/${this.t ? "rows" : "documents"}`; }
  colPath(table) { return `${this.tablePath(table)}/${this.t ? "columns" : "attributes"}`; }

  /* ---------- rows ---------- */
  async get(table, id) {
    try { return await this.api.call("GET", `${this.rowsPath(table)}/${id}`); }
    catch (err) { if (err.status === 404) return null; throw err; }
  }
  create(table, id, data) {
    return this.api.call("POST", this.rowsPath(table), { json: { [this.t ? "rowId" : "documentId"]: id, data } });
  }
  update(table, id, data) {
    return this.api.call("PATCH", `${this.rowsPath(table)}/${id}`, { json: { data } });
  }
  async remove(table, id) {
    try { await this.api.call("DELETE", `${this.rowsPath(table)}/${id}`); return true; }
    catch (err) { if (err.status === 404) return false; throw err; }
  }
  async list(table, queries = []) {
    const out = [];
    let cursor = null;
    for (;;) {
      const page = [...queries, q.limit(100)];
      if (cursor) page.push(q.cursorAfter(cursor));
      const res = await this.api.call("GET", this.rowsPath(table), { query: { queries: page } });
      const rows = res.rows || res.documents || [];
      out.push(...rows);
      if (rows.length < 100) return out;
      cursor = rows[rows.length - 1].$id;
    }
  }

  /* ---------- schema ---------- */
  async ensureDatabase(name) {
    try { await this.api.call("GET", this.dbPath()); return; } catch (err) { if (err.status !== 404) throw err; }
    await ignoreConflict(this.api.call("POST", this.t ? "/tablesdb" : "/databases", { json: { databaseId: this.databaseId, name } }));
  }

  async ensureTable(table, name) {
    try { await this.api.call("GET", this.tablePath(table)); return; } catch (err) { if (err.status !== 404) throw err; }
    const json = this.t
      ? { tableId: table, name, permissions: [], rowSecurity: false }
      : { collectionId: table, name, permissions: [], documentSecurity: false };
    await ignoreConflict(this.api.call("POST", `${this.dbPath()}/${this.t ? "tables" : "collections"}`, { json }));
  }

  async ensureColumn(table, key, type, size) {
    try { await this.api.call("GET", `${this.colPath(table)}/${key}`); return; } catch (err) { if (err.status !== 404) throw err; }
    const body = type === "string" ? { key, size, required: false } : { key, required: false };
    const kinds = type === "string" ? (this.t ? ["varchar", "string"] : ["string"]) : ["integer"];
    let lastError;
    for (const kind of kinds) {
      try { await ignoreConflict(this.api.call("POST", `${this.colPath(table)}/${kind}`, { json: body })); return; }
      catch (err) { lastError = err; if (err.status !== 404 && err.status !== 400) throw err; }
    }
    throw lastError;
  }

  async ensureIndex(table, key, columns) {
    const base = `${this.tablePath(table)}/indexes`;
    try { await this.api.call("GET", `${base}/${key}`); return; } catch (err) { if (err.status !== 404) throw err; }
    const json = { key, type: "key", [this.t ? "columns" : "attributes"]: columns };
    await ignoreConflict(this.api.call("POST", base, { json }));
  }

  async waitAvailable(table, keys, indexKeys = []) {
    const deadline = Date.now() + 45000;
    let pending = [...keys.map((k) => `${this.colPath(table)}/${k}`), ...indexKeys.map((k) => `${this.tablePath(table)}/indexes/${k}`)];
    while (pending.length) {
      if (Date.now() > deadline) throw new ApiError(503, "Database schema is still being prepared. Try again in a moment.");
      const states = await Promise.all(pending.map((path) => this.api.call("GET", path)));
      const failed = states.findIndex((s) => s.status === "failed");
      if (failed >= 0) throw new ApiError(500, `Schema item failed: ${pending[failed]} ${states[failed].error || ""}`);
      pending = pending.filter((_, i) => states[i].status !== "available");
      if (pending.length) await new Promise((r) => setTimeout(r, 400));
    }
  }
}

export class Storage {
  constructor(api) { this.api = api; }

  async ensureBucket(bucketId, name) {
    try { await this.api.call("GET", `/storage/buckets/${bucketId}`); return; } catch (err) { if (err.status !== 404) throw err; }
    await ignoreConflict(this.api.call("POST", "/storage/buckets", {
      json: {
        bucketId, name,
        permissions: ['create("any")'],   // browsers may upload ciphertext; nobody may read/list it directly
        fileSecurity: false,
        enabled: true,
        encryption: false,                // payloads are already AES-256-GCM encrypted
        antivirus: false,
        compression: "none",
      },
    }));
  }

  getFile(bucketId, fileId) {
    return this.api.call("GET", `/storage/buckets/${bucketId}/files/${fileId}`);
  }

  async download(bucketId, fileId, range) {
    const res = await this.api.call("GET", `/storage/buckets/${bucketId}/files/${fileId}/download`, {
      raw: true, headers: range ? { Range: range } : {},
    });
    return Buffer.from(await res.arrayBuffer());
  }

  async deleteFile(bucketId, fileId) {
    try { await this.api.call("DELETE", `/storage/buckets/${bucketId}/files/${fileId}`); return true; }
    catch (err) { if (err.status === 404) return false; throw err; }
  }

  createToken(bucketId, fileId, minutes = 10) {
    const expire = new Date(Date.now() + minutes * 60000).toISOString();
    return this.api.call("POST", `/tokens/buckets/${bucketId}/files/${fileId}`, { json: { expire } });
  }
}

async function ignoreConflict(promise) {
  try { return await promise; } catch (err) { if (err.status === 409) return null; throw err; }
}
