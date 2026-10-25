# @untracenetwork/next

Server-only Next.js (App Router) helpers for Untrace: a route handler factory and server actions.

```bash
npm i @untracenetwork/next
```

```ts
// app/api/untrace/route.ts
import { createUntraceRoute } from "@untracenetwork/next"

export const runtime = "nodejs"
export const { GET, POST } = createUntraceRoute({
  authorize: async (request) => Boolean(await yourSessionCheck(request)),
})
```

Full guide, security model and API reference:
https://github.com/untracenetwork/untrace-sdk#readme

License: Apache-2.0
