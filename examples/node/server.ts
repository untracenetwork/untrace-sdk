/**
 * The backend route for the React and Vue examples, on plain node:http.
 *
 *   UNTRACE_CLIENT_ID=... UNTRACE_CLIENT_SECRET=... npx tsx examples/node/server.ts
 *
 * Replace `authorize` with your own session check. The route is public otherwise.
 */
import { createServer } from "node:http"
import { Readable } from "node:stream"

import { createUntraceHandler } from "@untracenetwork/sdk/backend"

const handle = createUntraceHandler({
  // Demo only: allow everything outside production. Check your own session here.
  authorize: () => process.env.NODE_ENV !== "production",
  allow: ["list", "get", "download", "folders", "folder", "upload"],
})

createServer(async (req, res) => {
  if (!req.url?.startsWith("/api/untrace")) {
    res.writeHead(404).end()
    return
  }
  const headers = new Headers()
  for (const [k, v] of Object.entries(req.headers)) if (typeof v === "string") headers.set(k, v)
  const hasBody = req.method === "POST"
  const init: RequestInit & { duplex?: "half" } = { method: req.method, headers }
  if (hasBody) {
    init.body = Readable.toWeb(req) as unknown as ReadableStream
    init.duplex = "half" // required by Node for a streamed request body
  }
  const answer = await handle(new Request(`http://${req.headers.host ?? "localhost"}${req.url}`, init))
  res.writeHead(answer.status, Object.fromEntries(answer.headers.entries()))
  res.end(Buffer.from(await answer.arrayBuffer()))
}).listen(3001, () => console.log("untrace route on http://localhost:3001/api/untrace"))
