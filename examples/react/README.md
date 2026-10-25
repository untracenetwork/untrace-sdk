# React example

`App.tsx` talks only to your backend route. Run `examples/node/server.ts` (or any server that mounts
`createUntraceHandler`) and proxy `/api/untrace` to it from your dev server (Vite: `server.proxy`).

```bash
npm i @untracenetwork/react
```

No secret and no key material ever reach the browser.
