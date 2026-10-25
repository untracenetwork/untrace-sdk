# Examples

One small app per package. Each one runs against a real Drive with your own key.

| Folder | Package | What it shows |
|---|---|---|
| `node/` | `@untracenetwork/sdk` | A Node script: pick or create a folder, upload into it, list, download, delete. Plus `server.ts`, a plain `node:http` server that mounts the backend route for the React and Vue examples. |
| `next/` | `@untracenetwork/next` + `@untracenetwork/react` | A Next.js App Router route and a page with upload and a file list. |
| `react/` | `@untracenetwork/react` | A React component that lists, uploads and downloads through your route. |
| `vue/` | `@untracenetwork/vue` | A Vue app that does the same. |

Set the key on the server only:

```bash
export UNTRACE_CLIENT_ID=utc_...
export UNTRACE_CLIENT_SECRET=untrace_sk_v1_...
```

`npm run typecheck` at the repo root checks every example against the packages in this repo.
