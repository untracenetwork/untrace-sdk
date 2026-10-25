# @untracenetwork/sdk

The core Untrace client for any server runtime (Node 20+, Bun, Deno, Workers). It holds your client secret, encrypts files locally before upload (AES-256-GCM), and manages files, folders, key entries and shares through the Drive API v1.

```bash
npm i @untracenetwork/sdk
```

```ts
import { UntraceClient } from "@untracenetwork/sdk"

const untrace = new UntraceClient() // reads UNTRACE_CLIENT_ID and UNTRACE_CLIENT_SECRET
const { files } = await untrace.files.list()
const file = await untrace.files.download(files[0].fileId)
```

Full guide, security model and API reference:
https://github.com/untracenetwork/untrace-sdk#readme

License: Apache-2.0
