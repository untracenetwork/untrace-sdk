# @untracenetwork/react

React hooks for Untrace that call your own backend route. No secret ever reaches the browser.

```bash
npm i @untracenetwork/react
```

```ts
import { UntraceProvider, useUntraceFiles } from "@untracenetwork/react"

// <UntraceProvider endpoint="/api/untrace"> ... </UntraceProvider>
const { files, loading } = useUntraceFiles()
```

Full guide, security model and API reference:
https://github.com/untracenetwork/untrace-sdk#readme

License: Apache-2.0
