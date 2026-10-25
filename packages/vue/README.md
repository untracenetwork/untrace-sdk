# @untracenetwork/vue

Vue composables for Untrace that call your own backend route. No secret ever reaches the browser.

```bash
npm i @untracenetwork/vue
```

```ts
import { untracePlugin, useUntraceFiles } from "@untracenetwork/vue"

// app.use(untracePlugin, { endpoint: "/api/untrace" })
const { files, loading } = useUntraceFiles()
```

Full guide, security model and API reference:
https://github.com/untracenetwork/untrace-sdk#readme

License: Apache-2.0
