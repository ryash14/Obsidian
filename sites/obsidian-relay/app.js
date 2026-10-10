"use strict";

/* =========================================================================
   Obsidian Relay — Appwrite edition (static site)
   - Files are encrypted in the browser (AES-256-GCM, key wrapped with RSA-OAEP).
   - Ciphertext is uploaded straight to Appwrite Storage (chunked, any size up to the limit).
   - The relay-api Function registers, lists, authorises and deletes items.
   ========================================================================= */

const $ = (s, root = document) => root.querySelector(s);
const $$ = (s, root = document) => [...root.querySelectorAll(s)];
const TEXT_PATTERN = /\.(txt|log|md|json|js|jsx|ts|tsx|py|java|c|cpp|h|css|html|xml|yaml|yml|csv|svg|ini|env|sh|sql)$/i;
const CHUNK = 5 * 1024 * 1024;

const CONFIG = window.RELAY_CONFIG || {};
const FN = String(CONFIG.functionUrl || "").replace(/\/+$/, "");
const state = { items: [], q: "", sort: "new", viewing: null, queue: [], code: null, busy: false, remote: null };

/* ================= helpers ================= */
function b64(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
function unb64(text) {
  const bin = atob(text);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function formatSize(n) {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB"]; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}
function timeAgo(iso) {
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (!isFinite(s)) return "";
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
const isText = (x) => (x.type || "").startsWith("text/") || TEXT_PATTERN.test(x.name || "");
const extOf = (n) => { const m = /\.([a-z0-9]{1,4})$/i.exec(n || ""); return m ? m[1] : "file"; };
const maskCode = (c) => (c ? "••••" + c.slice(-2) : "");
const errorText = (e) => (e && e.message) || "Something went wrong.";
const randomId = () => "r" + [...crypto.getRandomValues(new Uint8Array(15))].map((b) => b.toString(16).padStart(2, "0")).join("");

/* ================= backend (Appwrite Function) ================= */
async function fn(path, { method = "GET", json, code } = {}) {
  if (!FN || FN.includes("YOUR-FUNCTION-DOMAIN")) throw new Error("The site is not configured. Set functionUrl in config.js.");
  const headers = {};
  if (json !== undefined) headers["Content-Type"] = "application/json";
  if (code) headers["X-Access-Code"] = code;
  let res;
  try {
    res = await fetch(FN + path, { method, headers, body: json === undefined ? undefined : JSON.stringify(json), cache: "no-store" });
  } catch {
    throw new Error("Could not reach the relay service. Check your connection.");
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.error || `Request failed (${res.status}).`);
    err.status = res.status;
    throw err;
  }
  return data;
}

async function remote() {
  if (!state.remote) {
    const cfg = await fn("/config");
    state.remote = {
      endpoint: (CONFIG.endpoint || cfg.endpoint || "").replace(/\/+$/, ""),
      projectId: CONFIG.projectId || cfg.projectId,
      bucketId: cfg.bucketId,
      maxBytes: cfg.maxBytes,
      publicKey: await crypto.subtle.importKey("spki", unb64(cfg.publicKey), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]),
    };
  }
  return state.remote;
}

/* ================= encryption ================= */
async function sealEnvelope(meta, content) {
  if (!window.crypto?.subtle) throw new Error("Encryption needs HTTPS or localhost.");
  const { publicKey } = await remote();
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
  const metaIv = crypto.getRandomValues(new Uint8Array(12));
  const contentIv = crypto.getRandomValues(new Uint8Array(12));
  const metaCt = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: metaIv }, key,
    new TextEncoder().encode(JSON.stringify({ ...meta, encrypted_at: new Date().toISOString() }))));
  const contentCt = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: contentIv }, key, content));
  const wrapped = new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, await crypto.subtle.exportKey("raw", key)));

  const head = new Uint8Array(4 + 2 + wrapped.length + 12 + 4);
  const view = new DataView(head.buffer);
  head.set([0x4f, 0x52, 0x4c, 0x33], 0);           // "ORL3"
  view.setUint16(4, wrapped.length);
  head.set(wrapped, 6);
  head.set(metaIv, 6 + wrapped.length);
  view.setUint32(6 + wrapped.length + 12, metaCt.length);
  return new Blob([head, metaCt, contentIv, contentCt], { type: "application/octet-stream" });
}

async function openPayload(item) {
  const access = await fn(`/item/${encodeURIComponent(item.id)}/access`, { code: state.code });
  if (access.url) {
    try {
      const res = await fetch(access.url, { cache: "no-store" });
      if (res.ok) {
        const buffer = await res.arrayBuffer();
        const key = await crypto.subtle.importKey("raw", unb64(access.key), "AES-GCM", false, ["decrypt"]);
        const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(access.iv) }, key, buffer.slice(access.offset));
        return new Blob([plain], { type: item.type || "application/octet-stream" });
      }
    } catch { /* fall back to the function proxy below */ }
  }
  const headers = state.code ? { "X-Access-Code": state.code } : {};
  const res = await fetch(`${FN}/item/${encodeURIComponent(item.id)}/raw`, { headers, cache: "no-store" });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.error || "Could not retrieve this item.");
  }
  return res.blob();
}

/* ================= upload to Appwrite Storage ================= */
function xhrUpload(url, form, headers, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", url);
    for (const [k, v] of Object.entries(headers)) xhr.setRequestHeader(k, v);
    xhr.upload.onprogress = (e) => e.lengthComputable && onProgress && onProgress(e.loaded / e.total);
    xhr.onload = () => {
      let data = {}; try { data = JSON.parse(xhr.responseText); } catch {}
      if (xhr.status >= 200 && xhr.status < 300) resolve(data);
      else reject(new Error(data.message || `Storage upload failed (${xhr.status}).`));
    };
    xhr.onerror = () => reject(new Error("Network error while uploading to storage. Is this site's domain added as a Web platform in Appwrite?"));
    xhr.send(form);
  });
}

async function uploadBlob(blob, onProgress) {
  const r = await remote();
  if (r.maxBytes && blob.size > r.maxBytes * 1.02 + 70000) {
    throw new Error(`File is too large. The limit is ${formatSize(r.maxBytes)}.`);
  }
  const url = `${r.endpoint}/storage/buckets/${r.bucketId}/files`;
  const id = randomId();
  const total = blob.size;
  for (let start = 0; start < total; start += CHUNK) {
    const end = Math.min(start + CHUNK, total);
    const form = new FormData();
    form.append("fileId", id);
    form.append("file", blob.slice(start, end), "payload.orl");
    const headers = { "X-Appwrite-Project": r.projectId };
    if (total > CHUNK) {
      headers["Content-Range"] = `bytes ${start}-${end - 1}/${total}`;
      if (start > 0) headers["X-Appwrite-ID"] = id;
    }
    await xhrUpload(url, form, headers, (p) => onProgress && onProgress((start + p * (end - start)) / total));
  }
  return id;
}

async function storeItem(meta, bytes, code, onProgress) {
  const sealed = await sealEnvelope(meta, bytes);
  const fileId = await uploadBlob(sealed, onProgress);
  await fn("/relay", { method: "POST", json: { fileId }, code });
}

/* ================= toasts & banner ================= */
function toast(title, detail = "", tone = "") {
  const node = document.createElement("div");
  node.className = `toast ${tone}`;
  const box = document.createElement("div");
  const t = document.createElement("strong"); t.textContent = title; box.append(t);
  if (detail) { const d = document.createElement("span"); d.textContent = detail; box.append(d); }
  node.append(box);
  const holder = $("#toasts");
  holder.append(node);
  while (holder.children.length > 3) holder.firstElementChild.remove();
  setTimeout(() => node.classList.add("out"), 3600);
  setTimeout(() => node.remove(), 3900);
}
function banner(message) {
  const el = $("#banner");
  if (!message) { el.hidden = true; return; }
  el.replaceChildren();
  const s = document.createElement("strong"); s.textContent = "Relay unavailable. ";
  el.append(s, document.createTextNode(message));
  el.hidden = false;
}

/* ================= modals ================= */
const openModal = (d) => { if (!d.open) d.showModal(); };
const closeModal = (d) => { if (d.open) d.close(); };
$$("dialog").forEach((d) => d.addEventListener("click", (e) => {
  if (e.target !== d) return;
  if (d.dispatchEvent(new Event("cancel", { cancelable: true }))) closeModal(d);
}));

function confirmAction(title, sub, okLabel = "Confirm") {
  const dialog = $("#confirm-dialog");
  $("#confirm-title").textContent = title;
  $("#confirm-sub").textContent = sub;
  $("#confirm-ok").textContent = okLabel;
  openModal(dialog);
  return new Promise((resolve) => {
    const ok = () => done(true), no = () => done(false);
    const onCancel = (e) => { e.preventDefault(); done(false); };
    function done(v) {
      $("#confirm-ok").removeEventListener("click", ok);
      $("#confirm-cancel").removeEventListener("click", no);
      dialog.removeEventListener("cancel", onCancel);
      closeModal(dialog); resolve(v);
    }
    $("#confirm-ok").addEventListener("click", ok);
    $("#confirm-cancel").addEventListener("click", no);
    dialog.addEventListener("cancel", onCancel);
  });
}

function chooseDestination() {
  const dialog = $("#storage-dialog");
  openModal(dialog);
  return new Promise((resolve) => {
    const onClick = (e) => {
      const btn = e.target.closest("[data-choice]");
      if (btn) done(btn.dataset.choice === "cancel" ? null : btn.dataset.choice);
    };
    const onCancel = (e) => { e.preventDefault(); done(null); };
    function done(v) {
      dialog.removeEventListener("click", onClick);
      dialog.removeEventListener("cancel", onCancel);
      closeModal(dialog); resolve(v);
    }
    dialog.addEventListener("click", onClick);
    dialog.addEventListener("cancel", onCancel);
  });
}

/* ---- 6-digit code dialog ---- */
const otpInputs = $$("#otp input");
const otpValue = () => otpInputs.map((i) => i.value).join("");
const otpFill = (v = "") => otpInputs.forEach((input, i) => { input.value = v[i] || ""; });
otpInputs.forEach((input, index) => {
  input.addEventListener("input", () => {
    input.value = input.value.replace(/\D/g, "").slice(-1);
    $("#otp").classList.remove("error"); $("#code-error").hidden = true;
    if (input.value && index < otpInputs.length - 1) otpInputs[index + 1].focus();
    if (otpValue().length === 6) $("#code-form").requestSubmit();
  });
  input.addEventListener("keydown", (e) => {
    if (e.key === "Backspace" && !input.value && index > 0) { otpInputs[index - 1].focus(); otpInputs[index - 1].value = ""; e.preventDefault(); }
    else if (e.key === "ArrowLeft" && index > 0) otpInputs[index - 1].focus();
    else if (e.key === "ArrowRight" && index < 5) otpInputs[index + 1].focus();
  });
  input.addEventListener("paste", (e) => {
    const digits = (e.clipboardData.getData("text") || "").replace(/\D/g, "").slice(0, 6);
    if (!digits) return;
    e.preventDefault(); otpFill(digits);
    otpInputs[Math.min(digits.length, 5)].focus();
    if (digits.length === 6) $("#code-form").requestSubmit();
  });
  input.addEventListener("focus", () => input.select());
});

function askCode({ title, sub, submitLabel, check, initial = "" }) {
  const dialog = $("#code-dialog"), form = $("#code-form"), error = $("#code-error"), submit = $("#code-submit");
  $("#code-title").textContent = title;
  $("#code-sub").textContent = sub;
  submit.textContent = submitLabel;
  error.hidden = true; $("#otp").classList.remove("error");
  otpFill(initial);
  openModal(dialog);
  setTimeout(() => otpInputs[Math.min(initial.length, 5)].focus(), 30);
  return new Promise((resolve) => {
    let pending = false;
    const showError = (msg) => {
      error.textContent = msg; error.hidden = false;
      const otp = $("#otp"); otp.classList.remove("error"); void otp.offsetWidth; otp.classList.add("error");
    };
    const onSubmit = async (e) => {
      e.preventDefault();
      if (pending) return;
      const code = otpValue();
      if (!/^\d{6}$/.test(code)) return showError("Enter all 6 digits.");
      pending = true; submit.disabled = true; submit.textContent = "Checking…";
      try { await check(code); done(code); }
      catch (err) { showError(errorText(err)); otpFill(""); otpInputs[0].focus(); }
      finally { pending = false; submit.disabled = false; submit.textContent = submitLabel; }
    };
    const onCancel = (e) => { e && e.preventDefault(); done(null); };
    function done(v) {
      form.removeEventListener("submit", onSubmit);
      $("#code-cancel").removeEventListener("click", onCancel);
      dialog.removeEventListener("cancel", onCancel);
      closeModal(dialog); resolve(v);
    }
    form.addEventListener("submit", onSubmit);
    $("#code-cancel").addEventListener("click", onCancel);
    dialog.addEventListener("cancel", onCancel);
  });
}

async function resolveDestination() {
  const choice = await chooseDestination();
  if (!choice) return null;
  if (choice === "public") return { code: null };
  if (choice === "existing") {
    const code = await askCode({
      title: "Add to existing access code",
      sub: "Enter the 6-digit code to store this under.",
      submitLabel: "Add",
      initial: state.code || "",
      check: (c) => fn("/code/verify", { method: "POST", json: { code: c } }),
    });
    return code ? { code } : null;
  }
  const code = await askCode({
    title: "Create a new access code",
    sub: "Choose any 6 digits. You'll need this code to see these files later.",
    submitLabel: "Create & add",
    check: (c) => fn("/code/create", { method: "POST", json: { code: c } }),
  });
  if (code) toast("Access code created", `Remember it: ${code}`, "ok");
  return code ? { code } : null;
}
const destinationLabel = (code) => (code ? `access code ${maskCode(code)}` : "the open Aster Index");
async function afterStore(code) { if ((code || null) === state.code) await load(); }

/* ================= tabs ================= */
function switchTab(id) {
  $$(".tab-panel").forEach((p) => { p.hidden = p.id !== id; });
  $$(".tab-button").forEach((b) => b.classList.toggle("active", b.dataset.tab === id));
}
$$(".tab-button").forEach((b) => b.addEventListener("click", () => switchTab(b.dataset.tab)));

/* ================= access code (header) ================= */
const accessInput = $("#access-code"), accessField = $("#access-field");
function setScope(code) {
  state.code = code || null;
  try { code ? sessionStorage.setItem("relay-code", code) : sessionStorage.removeItem("relay-code"); } catch {}
  accessField.hidden = !!code;
  $("#access-chip").hidden = !code;
  $("#access-chip-code").textContent = maskCode(code);
  const badge = $("#drift-badge");
  badge.textContent = code ? "Access Channel Active" : "Drift Channel Active";
  badge.classList.toggle("code", !!code);
  $("#index-title").textContent = code ? "Aster Index · Sealed" : "Aster Index";
  return load();
}
function flagAccessError() { accessField.classList.remove("error"); void accessField.offsetWidth; accessField.classList.add("error"); }
accessInput.addEventListener("input", () => {
  accessInput.value = accessInput.value.replace(/\D/g, "").slice(0, 6);
  accessField.classList.remove("error");
});
$("#access-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const code = accessInput.value.trim();
  if (!/^\d{6}$/.test(code)) { flagAccessError(); toast("Invalid access code", "Enter exactly 6 digits.", "error"); return; }
  $("#access-open").disabled = true;
  try {
    await fn("/code/verify", { method: "POST", json: { code } });
    accessInput.value = "";
    await setScope(code);
    toast("Access code opened", "Showing only files stored under this code.", "ok");
  } catch (err) {
    flagAccessError();
    toast("Could not open", errorText(err), "error");
  } finally { $("#access-open").disabled = false; }
});
$("#access-close").addEventListener("click", () => { setScope(null); accessInput.focus(); });

/* ================= Lumen Input ================= */
const contentField = $("#content");
function updateCount() {
  const v = contentField.value;
  const lines = v ? v.split("\n").length : 0;
  $("#char-count").textContent =
    `${v.length.toLocaleString()} characters · ${lines.toLocaleString()} lines · ${formatSize(new TextEncoder().encode(v).length)}`;
}
contentField.addEventListener("input", () => { updateCount(); $("#paste-error").hidden = true; });
contentField.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") { e.preventDefault(); $("#paste-form").requestSubmit(); }
  else if (e.key === "Tab" && !e.shiftKey) {
    e.preventDefault();
    contentField.setRangeText("  ", contentField.selectionStart, contentField.selectionEnd, "end");
    updateCount();
  }
});
$("#paste-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const error = $("#paste-error");
  if (!contentField.value.trim()) { error.textContent = "Add some content before committing."; error.hidden = false; contentField.focus(); return; }
  if (state.busy) return;
  const dest = await resolveDestination();
  if (!dest) return;
  const submit = $("#paste-submit");
  state.busy = true; submit.disabled = true; submit.textContent = "Encrypting…";
  try {
    const bytes = new TextEncoder().encode(contentField.value);
    const name = $("#filename").value.trim() || "paste.txt";
    await storeItem({ name, type: "text/plain", size_bytes: bytes.length, last_modified: Date.now(), relative_path: "" }, bytes, dest.code);
    e.target.reset(); updateCount();
    toast("Lumen committed", `Stored in ${destinationLabel(dest.code)}.`, "ok");
    await afterStore(dest.code);
  } catch (err) {
    error.textContent = errorText(err); error.hidden = false;
  } finally {
    state.busy = false; submit.disabled = false; submit.textContent = "Commit Lumen";
  }
});

/* ================= Quill Transfer ================= */
const fileInput = $("#file-input"), folderInput = $("#folder-input");
function renderQueue() {
  const list = $("#queue");
  list.replaceChildren();
  $("#queue-wrap").hidden = !state.queue.length;
  $("#queue-count").textContent = state.queue.length;
  $("#queue-size").textContent = state.queue.length ? `(${formatSize(state.queue.reduce((a, q) => a + q.file.size, 0))})` : "";
  state.queue.forEach((entry, index) => {
    const li = document.createElement("li");
    const ext = document.createElement("div"); ext.className = "ext"; ext.textContent = extOf(entry.file.name);
    const body = document.createElement("div"); body.className = "q-body";
    const name = document.createElement("span"); name.className = "q-name"; name.textContent = entry.file.name;
    const meta = document.createElement("span"); meta.className = "q-meta";
    meta.textContent = entry.status || `${entry.path || "root"} · ${formatSize(entry.file.size)}`;
    body.append(name, meta);
    li.append(ext, body);
    if (!state.busy) {
      const rm = document.createElement("button");
      rm.type = "button"; rm.className = "btn btn-danger btn-sm"; rm.textContent = "Remove";
      rm.addEventListener("click", () => { state.queue.splice(index, 1); renderQueue(); });
      li.append(rm);
    }
    list.append(li);
  });
}
function addToQueue(entries) {
  const key = (q) => `${q.path}|${q.file.name}|${q.file.size}|${q.file.lastModified}`;
  const seen = new Set(state.queue.map(key));
  let added = 0;
  for (const entry of entries) { if (!seen.has(key(entry))) { seen.add(key(entry)); state.queue.push(entry); added++; } }
  $("#upload-status").textContent = ""; $("#upload-status").classList.remove("error");
  renderQueue();
  if (added) toast(`${added} item${added > 1 ? "s" : ""} queued`);
}
fileInput.addEventListener("change", () => { addToQueue([...fileInput.files].map((file) => ({ file, path: "" }))); fileInput.value = ""; });
folderInput.addEventListener("change", () => { addToQueue([...folderInput.files].map((file) => ({ file, path: file.webkitRelativePath || "" }))); folderInput.value = ""; });
$("#pick-files").addEventListener("click", (e) => { e.stopPropagation(); fileInput.click(); });
$("#pick-folder").addEventListener("click", (e) => { e.stopPropagation(); folderInput.click(); });
$("#queue-clear").addEventListener("click", () => { state.queue = []; renderQueue(); });
const dropzone = $("#dropzone");
dropzone.addEventListener("click", () => fileInput.click());
dropzone.addEventListener("keydown", (e) => { if ((e.key === "Enter" || e.key === " ") && e.target === dropzone) { e.preventDefault(); fileInput.click(); } });

const veil = $("#veil"); let dragDepth = 0;
const hasFiles = (e) => [...(e.dataTransfer?.types || [])].includes("Files");
const endDrag = () => { dragDepth = 0; veil.classList.remove("on"); dropzone.classList.remove("dragging"); };
const readBatch = (reader) => new Promise((res, rej) => reader.readEntries(res, rej));
const entryFile = (entry) => new Promise((res, rej) => entry.file(res, rej));
async function walk(entry, prefix, out) {
  if (entry.isFile) out.push({ file: await entryFile(entry), path: prefix ? prefix + entry.name : "" });
  else if (entry.isDirectory) {
    const reader = entry.createReader(); let batch;
    do { batch = await readBatch(reader); for (const child of batch) await walk(child, `${prefix}${entry.name}/`, out); } while (batch.length);
  }
}
window.addEventListener("dragenter", (e) => { if (!hasFiles(e)) return; e.preventDefault(); dragDepth++; veil.classList.add("on"); dropzone.classList.add("dragging"); });
window.addEventListener("dragover", (e) => { if (!hasFiles(e)) return; e.preventDefault(); e.dataTransfer.dropEffect = "copy"; });
window.addEventListener("dragleave", (e) => { if (!hasFiles(e)) return; dragDepth = Math.max(0, dragDepth - 1); if (!dragDepth) endDrag(); });
window.addEventListener("drop", async (e) => {
  if (!hasFiles(e)) return;
  e.preventDefault();
  const entries = [...(e.dataTransfer.items || [])].map((i) => i.webkitGetAsEntry?.()).filter(Boolean);
  const fallback = [...(e.dataTransfer.files || [])];
  endDrag(); switchTab("file-tab");
  try {
    const collected = [];
    if (entries.length) for (const en of entries) await walk(en, "", collected);
    else fallback.forEach((file) => collected.push({ file, path: "" }));
    addToQueue(collected);
  } catch (err) { toast("Could not read dropped items", errorText(err), "error"); }
});

$("#upload-button").addEventListener("click", async () => {
  const status = $("#upload-status");
  status.classList.remove("error");
  if (!state.queue.length) { status.textContent = "Select or drop at least one file first."; status.classList.add("error"); return; }
  if (state.busy) return;
  const dest = await resolveDestination();
  if (!dest) return;

  const button = $("#upload-button"), progress = $("#progress"), bar = progress.firstElementChild;
  const queue = state.queue.slice();
  state.busy = true; button.disabled = true; progress.hidden = false;
  let done = 0;
  try {
    for (const entry of queue) {
      const f = entry.file;
      status.textContent = `Sending ${done + 1} of ${queue.length}: ${entry.path || f.name}`;
      bar.style.width = "0";
      entry.status = "Encrypting…"; renderQueue();
      await storeItem({
        name: f.name, type: f.type || "application/octet-stream", size_bytes: f.size,
        last_modified: f.lastModified, relative_path: entry.path || "",
      }, new Uint8Array(await f.arrayBuffer()), dest.code, (p) => {
        bar.style.width = `${Math.round(p * 100)}%`;
        entry.status = `Uploading ${Math.round(p * 100)}%`; renderQueue();
      });
      done++;
      state.queue.splice(state.queue.indexOf(entry), 1);
      renderQueue();
    }
    status.textContent = "";
    toast("Quill sent", `${done} item${done > 1 ? "s" : ""} stored in ${destinationLabel(dest.code)}.`, "ok");
  } catch (err) {
    status.textContent = `Upload failed: ${errorText(err)}`; status.classList.add("error");
  } finally {
    state.queue.forEach((q) => delete q.status);
    state.busy = false; button.disabled = false; progress.hidden = true;
    renderQueue();
    if (done) await afterStore(dest.code).catch(() => {});
  }
});

/* ================= Aster Index ================= */
async function load() {
  try {
    state.items = await fn("/catalog", { code: state.code });
    banner(null);
  } catch (err) {
    if (state.code && (err.status === 404 || err.status === 429)) {
      toast("Access code closed", errorText(err), "error");
      return setScope(null);
    }
    state.items = [];
    banner(errorText(err));
  }
  updateSummary(); render();
}
function updateSummary() {
  const total = state.items.reduce((a, x) => a + (x.size_bytes || 0), 0);
  $("#count").textContent = state.items.length;
  $("#total").textContent = `(${formatSize(total)})`;
  $("#summary-actions").hidden = !state.items.length;
}
function render() {
  const list = $("#items");
  const q = state.q.trim().toLowerCase();
  const rows = state.items.filter((i) => !q || (i.name || "").toLowerCase().includes(q));
  const sorters = {
    new: (a, b) => new Date(b.encrypted_at) - new Date(a.encrypted_at),
    old: (a, b) => new Date(a.encrypted_at) - new Date(b.encrypted_at),
    name: (a, b) => (a.name || "").localeCompare(b.name || ""),
    size: (a, b) => (b.size_bytes || 0) - (a.size_bytes || 0),
  };
  rows.sort(sorters[state.sort]);
  list.replaceChildren();
  if (!rows.length) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = state.items.length ? "No files match your search." : "The index is currently quiet.";
    if (!state.items.length) {
      const hint = document.createElement("small");
      hint.textContent = state.code ? "Nothing is stored under this access code yet." : "Drop a file or a whole folder anywhere on this page to stage it.";
      empty.append(hint);
    }
    list.append(empty);
    return;
  }
  for (const item of rows) {
    const row = document.createElement("article");
    row.className = "item";
    const ext = document.createElement("div"); ext.className = "ext"; ext.textContent = extOf(item.name);
    const body = document.createElement("div"); body.className = "item-body";
    const name = document.createElement("strong"); name.className = "filename"; name.textContent = item.name; name.title = item.relative_path || item.name;
    const meta = document.createElement("span"); meta.className = "metadata";
    meta.textContent = [formatSize(item.size_bytes), item.type || "unknown", timeAgo(item.encrypted_at)].filter(Boolean).join(" · ");
    body.append(name, meta);
    const actions = document.createElement("div"); actions.className = "item-actions";
    const mk = (label, cls, handler) => {
      const b = document.createElement("button"); b.type = "button"; b.className = `btn btn-sm ${cls}`; b.textContent = label;
      b.addEventListener("click", async () => { b.disabled = true; try { await handler(); } finally { b.disabled = false; } });
      actions.append(b);
    };
    mk("Open", "", () => openViewer(item));
    mk("Retrieve", "", () => retrieve(item));
    if (isText(item)) mk("Copy", "", () => copyItem(item));
    mk("Delete", "btn-danger", () => deleteItem(item));
    row.append(ext, body, actions);
    list.append(row);
  }
}
function saveBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename; document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30000);
}
async function retrieve(item) {
  try { saveBlob(await openPayload(item), item.name); }
  catch (err) { toast("Retrieve failed", errorText(err), "error"); }
}
async function copyItem(item) {
  try { await navigator.clipboard.writeText(await (await openPayload(item)).text()); toast("Copied to clipboard", item.name, "ok"); }
  catch (err) { toast("Copy failed", errorText(err), "error"); }
}
async function deleteItem(item) {
  try {
    await fn(`/item/${encodeURIComponent(item.id)}/delete`, { method: "POST", code: state.code });
    toast("Deleted", item.name);
    await load();
  } catch (err) { toast("Delete failed", errorText(err), "error"); }
}
$("#clear-button").addEventListener("click", async () => {
  const where = state.code ? "this access code" : "the open Aster Index";
  if (!(await confirmAction("Reset Drift?", `Every item in ${where} will be permanently deleted from the cloud.`, "Reset"))) return;
  try { const r = await fn("/clear", { method: "POST", code: state.code }); toast("Drift reset", `${r.removed} item(s) removed.`, "ok"); await load(); }
  catch (err) { toast("Reset failed", errorText(err), "error"); }
});
$("#search").addEventListener("input", (e) => { state.q = e.target.value; render(); });
$("#sort").addEventListener("change", (e) => { state.sort = e.target.value; render(); });

/* ---- ZIP (built in the browser, no size limits from the backend) ---- */
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; }
  return t;
})();
function crc32(bytes) { let c = 0xffffffff; for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; }
function buildZip(files) {
  const enc = new TextEncoder(), parts = [], central = [];
  let offset = 0;
  const now = new Date();
  const dosTime = (now.getHours() << 11) | (now.getMinutes() << 5) | (now.getSeconds() >> 1);
  const dosDate = ((now.getFullYear() - 1980) << 9) | ((now.getMonth() + 1) << 5) | now.getDate();
  for (const f of files) {
    const name = enc.encode(f.name), crc = crc32(f.data), size = f.data.length;
    const local = new DataView(new ArrayBuffer(30));
    local.setUint32(0, 0x04034b50, true); local.setUint16(4, 20, true); local.setUint16(6, 0x0800, true);
    local.setUint16(8, 0, true); local.setUint16(10, dosTime, true); local.setUint16(12, dosDate, true);
    local.setUint32(14, crc, true); local.setUint32(18, size, true); local.setUint32(22, size, true);
    local.setUint16(26, name.length, true); local.setUint16(28, 0, true);
    parts.push(local.buffer, name, f.data);
    const cd = new DataView(new ArrayBuffer(46));
    cd.setUint32(0, 0x02014b50, true); cd.setUint16(4, 20, true); cd.setUint16(6, 20, true); cd.setUint16(8, 0x0800, true);
    cd.setUint16(10, 0, true); cd.setUint16(12, dosTime, true); cd.setUint16(14, dosDate, true);
    cd.setUint32(16, crc, true); cd.setUint32(20, size, true); cd.setUint32(24, size, true);
    cd.setUint16(28, name.length, true); cd.setUint32(42, offset, true);
    central.push(cd.buffer, name);
    offset += 30 + name.length + size;
  }
  const cdSize = central.reduce((a, p) => a + p.byteLength, 0);
  const end = new DataView(new ArrayBuffer(22));
  end.setUint32(0, 0x06054b50, true); end.setUint16(8, files.length, true); end.setUint16(10, files.length, true);
  end.setUint32(12, cdSize, true); end.setUint32(16, offset, true);
  return new Blob([...parts, ...central, end.buffer], { type: "application/zip" });
}
$("#zip-button").addEventListener("click", async () => {
  const button = $("#zip-button");
  if (!state.items.length) return;
  button.disabled = true;
  try {
    const used = new Map(), files = [];
    for (let i = 0; i < state.items.length; i++) {
      const item = state.items[i];
      button.textContent = `Preparing ${i + 1}/${state.items.length}…`;
      const data = new Uint8Array(await (await openPayload(item)).arrayBuffer());
      let name = (item.relative_path || item.name).replace(/^\/+/, "");
      if (used.has(name)) {
        const n = used.get(name) + 1; used.set(name, n);
        const dot = name.lastIndexOf(".");
        name = dot > 0 ? `${name.slice(0, dot)}_${n}${name.slice(dot)}` : `${name}_${n}`;
      } else used.set(name, 1);
      files.push({ name, data });
    }
    const stamp = new Date().toISOString().replace(/[-:T]/g, "").slice(0, 14);
    saveBlob(buildZip(files), `vault_${stamp}.zip`);
    toast("ZIP ready", `${files.length} file(s) packed.`, "ok");
  } catch (err) {
    toast("ZIP failed", errorText(err), "error");
  } finally { button.disabled = false; button.textContent = "Download all (ZIP)"; }
});

/* ================= viewer ================= */
const viewer = $("#viewer"), viewerBody = $("#viewer-body");
let viewerUrl = null;
async function openViewer(item) {
  state.viewing = item;
  $("#viewer-title").textContent = item.name;
  $("#viewer-copy").hidden = !isText(item);
  viewerBody.textContent = "Decrypting…";
  openModal(viewer);
  try {
    const blob = await openPayload(item);
    if (viewerUrl) { URL.revokeObjectURL(viewerUrl); viewerUrl = null; }
    viewerBody.replaceChildren();
    if ((item.type || "").startsWith("image/")) {
      viewerUrl = URL.createObjectURL(blob);
      const img = document.createElement("img"); img.src = viewerUrl; img.alt = item.name; viewerBody.append(img);
    } else if (isText(item)) {
      const pre = document.createElement("pre"); pre.textContent = await blob.text(); viewerBody.append(pre);
    } else {
      viewerBody.textContent = `No inline preview for this file type (${item.type || "unknown"}). Use Retrieve to download it.`;
    }
  } catch (err) { viewerBody.textContent = errorText(err); }
}
$("[data-close]", viewer).addEventListener("click", () => closeModal(viewer));
$("#viewer-download").addEventListener("click", () => state.viewing && retrieve(state.viewing));
$("#viewer-copy").addEventListener("click", () => state.viewing && copyItem(state.viewing));

/* ================= misc & boot ================= */
$("#theme-toggle").addEventListener("click", () => {
  const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem("relay-theme", next); } catch {}
});
document.addEventListener("keydown", (e) => {
  if (e.key === "/" && !/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName) && !document.querySelector("dialog[open]")) {
    e.preventDefault(); $("#search").focus();
  }
});

updateCount();
(async () => {
  let saved = null;
  try { saved = sessionStorage.getItem("relay-code"); } catch {}
  try { await remote(); } catch (err) { banner(errorText(err)); $("#items").replaceChildren(); return; }
  await setScope(saved && /^\d{6}$/.test(saved) ? saved : null);
})();
