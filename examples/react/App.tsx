import { useState } from "react"
import { UntraceProvider, UntraceRouteError, useUntrace, useUntraceFiles, useUntraceFolders, useUntraceUpload } from "@untracenetwork/react"

function FileList() {
  // A key uploads only into a folder it was added to: use the first one it can write to.
  const { folders } = useUntraceFolders()
  const folder = folders.find((f) => f.role !== "viewer")
  const { files, loading, error, refresh } = useUntraceFiles(folder?.folderId)
  const { upload, uploading } = useUntraceUpload()
  const api = useUntrace()
  const [preview, setPreview] = useState<string | null>(null)

  async function open(fileId: string) {
    try {
      const blob = await api.download(fileId)
      setPreview(await blob.text())
    } catch (e) {
      setPreview(e instanceof UntraceRouteError ? `error: ${e.code}` : String(e))
    }
  }

  return (
    <section>
      <input
        type="file"
        disabled={uploading || !folder}
        onChange={async (e) => {
          const f = e.target.files?.[0]
          if (f && folder) {
            await upload(f, folder.folderId)
            await refresh()
          }
        }}
      />
      {loading ? <p>Loading...</p> : null}
      {error ? <p role="alert">{error.message}</p> : null}
      <ul>
        {files.map((f) => (
          <li key={f.fileId}>
            <button onClick={() => void open(f.fileId)}>{f.name}</button> {f.size} bytes
          </li>
        ))}
      </ul>
      {preview !== null ? <pre>{preview}</pre> : null}
    </section>
  )
}

export default function App() {
  return (
    <UntraceProvider endpoint="/api/untrace">
      <FileList />
    </UntraceProvider>
  )
}
