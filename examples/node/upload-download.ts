/**
 * Minimal Node script for @untracenetwork/sdk.
 *
 *   UNTRACE_CLIENT_ID=utc_... UNTRACE_CLIENT_SECRET=untrace_sk_v1_... npx tsx examples/node/upload-download.ts
 *
 * The file is encrypted on this machine before it is sent. Drive only sees ciphertext.
 * A key uploads only into a folder it was added to: this script uses the first
 * folder the key can see, or creates one (needs the `upload` scope).
 */
import { UntraceClient, UntracePaymentRequiredError } from "@untracenetwork/sdk"

async function main(): Promise<void> {
  const untrace = new UntraceClient() // reads UNTRACE_CLIENT_ID and UNTRACE_CLIENT_SECRET

  const token = await untrace.getToken()
  console.log("token scopes:", token.scopes.join(" "))

  const { folders } = await untrace.folders.list()
  const folder = folders.find((f) => f.role !== "viewer") ?? (await untrace.folders.create({ name: "SDK uploads" }))
  console.log("folder:", folder.name, folder.folderId)

  const { file, metering } = await untrace.files.upload({
    folderId: folder.folderId,
    data: new TextEncoder().encode("hello from the Untrace SDK"),
    name: "hello.txt",
    mime: "text/plain",
  })
  console.log("uploaded", file.fileId, `${metering.meteredBytes} bytes billed to the ${metering.billedTo}`)

  for await (const f of untrace.files.listAll({ folderId: folder.folderId })) console.log("-", f.name, f.size, f.role)

  const back = await untrace.files.download(file.fileId)
  console.log("downloaded:", new TextDecoder().decode(back.bytes))

  await untrace.files.delete(file.fileId)
  console.log("moved to trash")
}

main().catch((err) => {
  if (err instanceof UntracePaymentRequiredError) console.error("The Drive owner needs an active plan:", err.planCode)
  else console.error(err)
  process.exitCode = 1
})
