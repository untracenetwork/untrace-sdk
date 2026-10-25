"use client"

import { UntraceProvider, useUntrace, useUntraceFiles, useUntraceFolders, useUntraceUpload } from "@untracenetwork/react"

function Files() {
  // A key uploads only into a folder it was added to: use the first one it can write to.
  const { folders } = useUntraceFolders()
  const folder = folders.find((f) => f.role !== "viewer")
  const { files, loading, error, refresh } = useUntraceFiles(folder?.folderId)
  const { upload, uploading } = useUntraceUpload()
  const api = useUntrace()
  return (
    <main>
      <h1>My files</h1>
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
      {loading && <p>Loading...</p>}
      {error && <p role="alert">{error.message}</p>}
      <ul>
        {files.map((f) => (
          <li key={f.fileId}>
            <a href={api.downloadUrl(f.fileId)} download={f.name}>
              {f.name}
            </a>{" "}
            ({f.size} bytes, {f.role})
          </li>
        ))}
      </ul>
    </main>
  )
}

export default function Page() {
  return (
    <UntraceProvider endpoint="/api/untrace">
      <Files />
    </UntraceProvider>
  )
}
