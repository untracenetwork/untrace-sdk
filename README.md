# untrace-sdk

JavaScript SDK for the Untrace Drive API v1. Thin, typed wrappers over the API, generated from the
Drive OpenAPI contract.

Your server holds a client id and a client secret. Files are encrypted on your machine before they
are sent, with one standard step (AES-256-GCM). Drive stores the ciphertext in 6 regions, and any 3
recover it. The file key is sealed to your key and to the account owner's key, so only those keys
can open it. We cannot read your files.

| Package | Use it for |
|---|---|
| `@untracenetwork/sdk` | The core client for any server runtime (Node 20+, Bun, Deno, Workers) |
| `@untracenetwork/next` | Next.js route handler and server actions |
| `@untracenetwork/react` | Hooks that call your own backend route |
| `@untracenetwork/vue` | Composables that call your own backend route |

```bash
npm i @untracenetwork/sdk     # any server runtime
npm i @untracenetwork/next    # Next.js (pulls in @untracenetwork/sdk)
npm i @untracenetwork/react   # React hooks, browser side
npm i @untracenetwork/vue     # Vue composables, browser side
```

The client secret is server-only. `UntraceClient` refuses to start in a browser. React and Vue code
talks to your backend route, never to Untrace directly. Minimal apps for each package are in
[`examples/`](./examples).

## 1. Create a key in Drive

1. Open Untrace Drive, then **Settings > Developer keys**, and create a key. Pick its scopes:
   `download`, `upload`, `delete`, `manage-sharing`.
2. Copy the **client id** (`utc_...`) and the **client secret** (`untrace_sk_v1_...`). The secret is
   shown once. Untrace does not keep it. If you lose it, revoke the key and create a new one.
3. The account that owns the key needs an active plan. Without one, Drive answers 402.
4. Sign in to Drive at least once as the owner before the key uploads. That publishes the sharing key
   new files are sealed to.
5. A key uploads only into a folder it has been added to. Create one with `untrace.folders.create`
   (needs `upload`), or add the key to an existing folder in Drive.

```bash
# server env only (never NEXT_PUBLIC_)
UNTRACE_CLIENT_ID=utc_...
UNTRACE_CLIENT_SECRET=untrace_sk_v1_...
```

## 2. Core client

```ts
import { UntraceClient } from "@untracenetwork/sdk"

const untrace = new UntraceClient() // reads UNTRACE_CLIENT_ID and UNTRACE_CLIENT_SECRET

const folder = await untrace.folders.create({ name: "Reports" }) // or pick one from folders.list()
const { file, metering } = await untrace.files.upload({ folderId: folder.folderId, data: bytes, name: "report.pdf", mime: "application/pdf" })
const { files, nextCursor } = await untrace.files.list({ folderId: folder.folderId, limit: 50 })
for await (const f of untrace.files.listAll()) console.log(f.name)
const { bytes: plain, name, mime } = await untrace.files.download(file.fileId)
await untrace.files.rename(file.fileId, "report-final.pdf")
await untrace.files.move(file.fileId, otherFolderId) // admin on the file and on the target
await untrace.files.delete(file.fileId) // moves it to the trash
```

`upload` takes a `Uint8Array`, an `ArrayBuffer` or a `Blob`, and a required `folderId`. In this
version one upload is at most 16 MiB once encrypted. `metering` reports what was billed to the owner's
plan. Uploading into a folder the key was not added to (or only as `viewer`) throws
`UntraceFolderAccessError`.

### Folders, key entries and sharing

```ts
const { folders } = await untrace.folders.list() // top-level folders the key was added to
const sub = await untrace.folders.create({ name: "Q3", parentId: folders[0].folderId })
await untrace.folders.rename(sub.folderId, "Q3 2026")
await untrace.folders.move(sub.folderId, otherFolderId) // or null for the top level (owner keys only)
await untrace.folders.trash(sub.folderId)

// Key entries: each one is a key a person holds, with a role and scopes (needs manage-sharing).
const entries = await untrace.keys.list({ type: "folder", id: sub.folderId })
await untrace.keys.attach({ type: "folder", id: sub.folderId }, {
  keyType: "client", keyId: "utc_...", role: "viewer", scopes: ["download"],
  publicKey: otherKeyBoxPublicKey, // that key's untrace.boxPublicKey()
})
await untrace.keys.change({ type: "folder", id: sub.folderId }, entryId, { role: "none" }) // a block

// Sharing with another user: the key is sealed to their published, signed sharing key.
await untrace.shares.offer({ resourceType: "folder", resourceId: sub.folderId, username: "their-username", role: "editor" })
for (const s of await untrace.shares.incoming()) await untrace.shares.accept(s, { shareSecretKey })
```

Access resolves from the top folder down to the file: the nearest entry for your key wins, a block
(`none`) included. A folder has its own X25519 key pair derived from a random folder key, and every
subfolder and file in it carries its key sealed to the folder's public key. Drive answers with the key
where your entry sits (`sealedKey`) and the `keyPath` below it; the SDK opens that path locally. Before
it seals anything to a folder, the SDK opens the folder key itself and checks that the folder's public
key matches it, so it never seals to a key the server picked. Nobody can attach a key in someone else's
name: a share is only an offer until the recipient accepts it with their own key.

Every operation in the contract is also reachable by its `operationId`:

```ts
const shareKey = await untrace.call("getOwnerShareKey")
```

`OPERATIONS` lists every operation with its status. Every operation in this contract is `live`. An
operation a future contract marks `planned` throws `UntracePlannedError` until Drive serves it.

### How authentication works

OAuth 2.0 client credentials. The SDK derives the OAuth `client_secret` from your `untrace_sk_v1_`
secret on your machine (HKDF-SHA256, label `untrace:client-key:oauth:v1`) and exchanges it at
`POST /api/v1/oauth/token` for a Bearer token that lasts 15 minutes. The token is cached and
refreshed for you; concurrent calls share one token request. Your raw secret is never sent anywhere,
so Drive can never compute the key that opens your files.

### How encryption works (UTE1)

On upload the SDK picks a fresh random 32-byte file key, encrypts the file with AES-256-GCM in chunks
(a random 12-byte IV per chunk, framed as `UTE1`), and seals the file key to your key and to the
owner's sharing key, whose signature it checks first. Drive receives ciphertext and sealed keys only.
On download Drive returns the same ciphertext and your sealed key; the SDK opens it and decrypts. Any
tampering fails the check and throws `UntraceIntegrityError`. The format is specified in the contract
(`contract/openapi.yaml`, "Client-side encryption").

## 3. Next.js

```bash
npm install @untracenetwork/next @untracenetwork/react
```

`app/api/untrace/route.ts`:

```ts
import { createUntraceRoute } from "@untracenetwork/next"
import { auth } from "@/auth" // your own session check

export const { GET, POST } = createUntraceRoute({
  authorize: async () => Boolean(await auth()), // required: the route is public otherwise
  allow: ["list", "get", "download", "folders", "folder", "upload"], // read-only by default
})
export const runtime = "nodejs"
```

Server actions: `untraceActions.listFiles(cursor, limit, folderId)`, `listFolders(parentId)`,
`createFolder(name, parentId)`, `getFile()`, `uploadFromForm(formData)` (reads a `folderId` field, or
pass it as the third argument), `renameFile()`, `moveFile()`, `deleteFile()`. Wrap them in your own `"use server"` functions after checking the session.
`getUntrace()` returns one shared client per server process. See [`examples/next`](./examples/next).

## 4. React and Vue

```tsx
import { UntraceProvider, useUntraceFiles, useUntraceFolders, useUntraceUpload } from "@untracenetwork/react"

<UntraceProvider endpoint="/api/untrace"><Files /></UntraceProvider>
// in Files: const { folders } = useUntraceFolders(); const { files } = useUntraceFiles(folderId)
// const { upload } = useUntraceUpload(); await upload(file, folderId)
```

```ts
import { untracePlugin, useUntraceFiles, useUntraceFolders, useUntraceUpload } from "@untracenetwork/vue"

app.use(untracePlugin, { endpoint: "/api/untrace" })
```

### Route protocol and CSRF

`createUntraceHandler` (from `@untracenetwork/sdk/backend`) is a Web `Request` to `Response` handler
for any server. One route:

| Request | Answer |
|---|---|
| `GET ?action=list[&folderId=&cursor=&limit=]` | `{ files, nextCursor }` |
| `GET ?action=get&fileId=` | file metadata, no key material |
| `GET ?action=download&fileId=` | the decrypted bytes |
| `GET ?action=folders[&parentId=&cursor=&limit=]` | `{ folders, nextCursor }`, no key material |
| `GET ?action=folder&folderId=` | folder metadata, no key material |
| `POST ?action=upload&folderId=`, multipart `file[, name]` | `{ file }` |
| `POST ?action=rename&fileId=`, JSON `{ name }` | `{ fileId, name }` |
| `POST ?action=move&fileId=`, JSON `{ folderId }` | `{ fileId, name, folderId }` |
| `POST ?action=delete&fileId=`, JSON `{}` | `{ fileId, trashed }` |
| `POST ?action=create-folder[&parentId=]`, JSON `{ name }` | folder |
| `POST ?action=rename-folder&folderId=`, JSON `{ name }` | folder |
| `POST ?action=move-folder&folderId=`, JSON `{ parentId }` | folder |
| `POST ?action=trash-folder&folderId=`, JSON `{}` | `{ removed }` |
| `POST ?action=share`, JSON `{ resourceType, resourceId, username, role }` | the share offer |

- `authorize(request, action, fileId, { fileId, folderId, parentId })` is required and runs before any
  body is read. The ids come from the query string; a body may not override them. The targets of
  `move`, `move-folder` and `share` are in the body: read `request.clone().json()` in `authorize` if
  you need to check them.
- Only `list`, `get`, `download`, `folders` and `folder` are enabled by default. Opt in to writes with `allow`.
- Every POST needs `x-untrace-request: 1` and a JSON content type (multipart for upload), which a
  cross-site form cannot send. Cross-site and foreign-origin requests are refused unless listed in
  `allowedOrigins`. Keep your session cookie `SameSite=Lax` or `Strict` as a second layer.

## Scopes and roles

| Scope | Allows |
|---|---|
| `download` | read files the key can reach |
| `upload` | upload new files and create folders, billed to the owner's plan |
| `delete` | move files and folders to the trash where the key is `admin` |
| `manage-sharing` | manage key entries and offer shares where the key is `admin` |

Roles are `owner`, `admin`, `editor` and `viewer`; `none` on an entry is a block. A key that uploads a
file becomes its `editor`. The owner's keys can never be changed or removed (409 `owner_immutable`). A file the key cannot reach answers 404, the same as a
file that does not exist. Pass `scope` to `UntraceClient` to ask for fewer scopes than the key holds.

## Errors

Every error is an `UntraceError` with `status`, `code`, `retryable` and a redacted `message`.

| Class | When |
|---|---|
| `UntraceAuthError` | 401 `invalid_client` or `token_expired` (the SDK refreshes once for you) |
| `UntraceScopeError` | 403 `insufficient_scope` or 400 `invalid_scope`; `required` names the scope |
| `UntraceRoleError` | 403 `insufficient_role` |
| `UntraceFolderAccessError` | 403 `folder_access_required`: upload into a folder the key can write to |
| `UntraceNotFoundError` | 404 |
| `UntracePaymentRequiredError` | 402: the owner's plan does not allow it; `planCode` says why |
| `UntraceConflictError` | 409 `conflict` (for example a folder moved inside itself), `owner_immutable`, `unsupported_format` (a file made in the Drive app) |
| `UntraceTooLargeError` | 413, or refused locally before sending |
| `UntraceRateLimitError` | 429; `retryAfterSeconds` |
| `UntraceUnavailableError`, `UntraceTimeoutError` | 503, network, timeout: retry with backoff |
| `UntraceIntegrityError` | a sealed key, a key path, a signature, a folder public key or the ciphertext failed a local check |
| `UntracePlannedError` | the operation is planned and not served yet |
| `UntraceAbortError` | your `AbortSignal` fired |

### Timeouts, cancellation and retries

```ts
const untrace = new UntraceClient({ timeoutMs: 30_000, maxRetries: 2, retryBaseMs: 250 })
const ctl = new AbortController()
await untrace.files.download(fileId, { signal: ctl.signal, timeoutMs: 60_000 })
```

Only 503, 429 (honouring `Retry-After`) and network errors or timeouts are retried. Other 4xx never
are. A network failure on an upload is not retried, so a file is never stored twice.

## Security notes

- Keep `UNTRACE_CLIENT_SECRET` on the server. The client keeps it in a private field and never prints
  it; error messages and bodies are redacted.
- The only cryptography in this repo is the client side of the contract: HKDF for the OAuth value, the
  box key and a folder's box key, AES-256-GCM for file content, and the sealed-key format. Everything else runs in Drive.

## Contract and generated types

`contract/openapi.yaml` is a byte copy of untrace-drive `docs/api/openapi.yaml`, and
`contract/SOURCE.json` records the commit it came from. `npm run gen:types` regenerates
`packages/core/src/generated/`; `npm run check:types` (in CI) fails if they are stale. To update from a
Drive checkout:

```bash
node scripts/gen-types.mjs --from ../untrace-drive
```

## Development

```bash
npm ci --no-audit --no-fund
npm run check:types    # generated types match the contract
npm run check:public   # no internals, no secrets, Apache-2.0 everywhere
npm run build
npm run typecheck      # packages and examples
npm test               # unit tests against a mock Drive (fetch is mocked)
npm run pack:check     # tarballs ship dist, README, LICENSE only
npm run test:live      # opt-in, against a real Drive
```

`npm run test:live` is skipped unless `UNTRACE_CLIENT_ID`, `UNTRACE_CLIENT_SECRET` and
`UNTRACE_BASE_URL` are set. The manual **Live integration** workflow runs it from repo secrets.

Releases: see [docs/RELEASING.md](docs/RELEASING.md). A `v*` tag only verifies; publishing is a manual
workflow that waits for JC's approval.

## License

Apache-2.0. See [LICENSE](./LICENSE).
