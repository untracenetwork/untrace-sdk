# Changelog

All packages in this repo share one version and are released together.

## 2.0.0 (unreleased)

Thin wrappers over the Untrace Drive API v1, typed from the Drive OpenAPI contract
(`docs/api/openapi.yaml` at untrace-drive main `1b18365`, recorded in `contract/SOURCE.json`).
Licence changes from MIT to Apache-2.0.

### Packages

- `@untracenetwork/sdk` 2.0.0: core client (`UntraceClient`) and backend handler (`@untracenetwork/sdk/backend`).
- `@untracenetwork/next` 2.0.0: Next.js route handler factory and server actions.
- `@untracenetwork/react` 2.0.0: hooks against your own backend route.
- `@untracenetwork/vue` 2.0.0: composables against your own backend route.
- `@untracenetwork/node` is removed. Use `@untracenetwork/sdk` (Node 20+ has fetch, Blob and WebCrypto) and
  `examples/node/server.ts` for a `node:http` route.

### Changed

- Auth is OAuth 2.0 client credentials (`POST /api/v1/oauth/token`). The SDK derives the OAuth
  `client_secret` from the `untrace_sk_v1_` secret locally (HKDF-SHA256, `untrace:client-key:oauth:v1`);
  the raw secret is never sent. Tokens are cached, shared between concurrent calls and refreshed once on
  `token_expired`.
- Upload and download use the contract's one client-side step: UTE1 (AES-256-GCM in chunks, random IV
  per chunk, header and chunk index authenticated). The file key is sealed to the caller's key and to the
  owner's sharing key (signature checked first). Drive only receives ciphertext and sealed keys.
- Types come from the contract: `scripts/gen-types.mjs` writes `packages/core/src/generated/`, and CI
  fails when they are stale (`npm run check:types`).
- `client.call(operationId, ...)` reaches every contract operation. All of them are live in this
  contract; an operation a future contract marks `planned` throws `UntracePlannedError`.
- Errors follow the contract codes: new `UntracePlannedError` and `UntraceFolderAccessError`
  (403 `folder_access_required`); `UntraceConflictError` now also covers `owner_immutable` and
  `unsupported_format`.
- `files.upload` needs a `folderId`: a key uploads only into a folder it was added to. The file key is
  also sealed to the folder's public key.
- `files.download` opens the key path when the key reaches the file through a folder entry.
- The backend route protocol keeps its CSRF rules; its actions are `list`, `get`, `download`, `upload`
  (with `folderId`), `rename`, `move`, `delete`, `folders`, `folder`, `create-folder`, `rename-folder`,
  `move-folder`, `trash-folder` and `share`. `authorize` also gets `{ fileId, folderId, parentId }`.
- React and Vue: `upload(file, folderId, name?)`, `useUntraceFiles(folderId)`, new `useUntraceFolders`,
  and fetcher methods for folders, moves and shares. Next: `listFolders`, `createFolder`, `moveFile`,
  and `uploadFromForm` reads a `folderId`.

### Removed

- The challenge and signature login, the file-member API (replaced by key entries), and every
  storage-layout detail. That work runs inside Drive.
- Two runtime dependencies that are no longer needed.

### Added

- `client.folders` (list, get, create, rename, move, trash), `client.keys` (list, attach, change, remove
  on folders and files) and `client.shares` (lookup, offer, incoming, accept), plus `files.move`.
  Folder keys: `deriveFolderBoxKeys` (HKDF-SHA256, `untrace:folder-key:box:v1`) and `openKeyPath`. The
  SDK checks a folder's public key against the folder key before it seals anything to it.
- `examples/`: a Node script and route server, a Next.js app, a React app and a Vue app.
- `npm run check:public`: the public-surface gate (no internals, no secrets, Apache-2.0 everywhere).
- Byte-compatibility tests against vectors produced by Drive's own reference code at `73bf7f2` (the
  client key, OAuth and sealed-key code did not change up to `1b18365`).

## 1.0.0

Never published to npm. Superseded by 2.0.0.
