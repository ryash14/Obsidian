# Obsidian Relay — Appwrite edition

Encrypted paste & file relay running entirely on Appwrite:

| Part | Appwrite product | Folder |
|---|---|---|
| Frontend (Lumen Input, Quill Transfer, Aster Index) | **Sites** (static) | `sites/obsidian-relay` |
| Backend API | **Functions** (Node.js 22, zero dependencies) | `functions/relay-api` |
| File contents (AES-256-GCM ciphertext) | **Storage** bucket `relay-files` | created automatically |
| Item index, access codes, lockouts | **Databases** `relay` → `items`, `codes`, `attempts` | created automatically |

The function creates the database, tables, columns, index and bucket by itself on its first request. You don't have to set up the schema by hand.

## How data flows
1. The browser encrypts each file with a fresh AES-256 key. The key is wrapped with the function's RSA public key.
2. The ciphertext uploads **directly to Appwrite Storage**, in 5 MB chunks. This means function body-size limits don't apply. Guests may create files in the bucket but cannot read or list them.
3. The function reads only the small encrypted header, validates it, and records the item under either the open index or a hashed 6-digit access code.
4. To open or download an item, the function checks the scope and issues a 10-minute file token plus the content key. The browser then downloads and decrypts. If file tokens aren't available on your server, the function decrypts and streams the file instead.
5. "Download all (ZIP)" is built in the browser.

## Deploy (Appwrite Console — recommended)

**1. Generate the RSA key** (Node 18+):
```bash
node tools/generate-key.mjs
```
Copy the single-line value it prints. Keep `private_key.pem` private.

**2. Create the function**
- Functions → **Create function** → **Manual** → upload `deploy/relay-api.tar.gz`.
- Runtime **Node.js 22**, entrypoint `src/main.js`, no build commands.
- Settings → **Execute access**: `Any`.
- Settings → **Scopes**: enable *databases, tables, columns, indexes, rows* (read + write), *buckets, files* (read + write), *tokens* (read + write).
  On older self-hosted versions the names are *collections, attributes, documents* instead of *tables, columns, rows*.
- Settings → **Environment variables**: add `VAULT_RSA_PRIVATE_KEY` = the value from step 1. This is the only required variable.
- **Domains** tab: copy the function's domain.
- Open `https://<function-domain>/config` in a browser. A JSON response means the database and bucket were provisioned. An error message there explains what's missing, for example a scope.

**3. Point the site at the function**
Edit `sites/obsidian-relay/config.js`:
```js
window.RELAY_CONFIG = { functionUrl: "https://<function-domain>" };
```

**4. Create the site**
```bash
tar -czf site.tar.gz -C sites/obsidian-relay .
```
Sites → **Create site** → **Manual** → upload `site.tar.gz`. Use framework **Other**, no install/build command, and output directory `./`.

**5. Allow the site to talk to Appwrite Storage**
Project **Overview → Add platform → Web**, and enter the site's hostname (for example `obsidian-relay.appwrite.network`, or your custom domain). Without this, direct uploads are blocked by CORS.

Open the site — done.

## Deploy with the CLI (alternative)
```bash
npm i -g appwrite-cli
appwrite login
# edit projectId / endpoint in appwrite.config.json and functionUrl in sites/obsidian-relay/config.js
appwrite push functions
appwrite push sites
```
Then add the `VAULT_RSA_PRIVATE_KEY` variable and the Web platform (steps 2 and 5) in the Console. If your CLI version rejects a field in `appwrite.config.json`, use the Console steps instead. The CLI config format has changed between versions.

## Optional function variables
| Variable | Default | Purpose |
|---|---|---|
| `ALLOWED_ORIGINS` | `*` | Comma-separated site origins allowed to call the API, e.g. `https://obsidian-relay.appwrite.network` |
| `RELAY_MAX_BYTES` | `52428800` (50 MB) | Max file size. Keep it at or below your bucket/plan file limit |
| `ACCESS_MAX_FAILURES` / `ACCESS_LOCK_SECONDS` | `5` / `300` | Wrong-code lockout |
| `PUBLIC_APPWRITE_ENDPOINT` | auto | Set only on self-hosted if the function's internal endpoint isn't publicly reachable |
| `RELAY_DATABASE_ID` / `RELAY_BUCKET_ID` | `relay` / `relay-files` | Resource IDs |

## Notes
- Data is now **persistent in the cloud** (it is no longer RAM-only). Reset Drift and Delete permanently remove items from Storage and the database.
- File contents are stored only as ciphertext. Filenames, types and sizes are stored in the `items` table so they can be listed. Access codes are stored only as keyed hashes.
- Rotating `VAULT_RSA_PRIVATE_KEY` makes existing items unreadable and changes every access-code hash.
