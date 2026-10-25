# Vue example

`main.ts` mounts a small Vue 3 app that talks only to your backend route. Run `examples/node/server.ts`
(or any server that mounts `createUntraceHandler`) and proxy `/api/untrace` to it (Vite: `server.proxy`).

```bash
npm i @untracenetwork/vue vue
```

No secret and no key material ever reach the browser.
