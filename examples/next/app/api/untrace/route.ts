import { createUntraceRoute } from "@untracenetwork/next"

// Replace with your own session check (next-auth, Clerk, a cookie). The route is public otherwise.
async function isSignedIn(request: Request): Promise<boolean> {
  return request.headers.get("cookie")?.includes("session=") ?? false
}

export const { GET, POST } = createUntraceRoute({
  authorize: (request) => isSignedIn(request),
  allow: ["list", "get", "download", "folders", "folder", "upload", "delete"],
})

// The SDK uses WebCrypto and fetch; the Node.js runtime is the safe default.
export const runtime = "nodejs"
