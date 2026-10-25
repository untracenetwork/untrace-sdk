/**
 * @untracenetwork/react: hooks that call YOUR backend route (createUntraceRoute /
 * createUntraceHandler). No secret and no Untrace credentials in the browser.
 */
import { createContext, createElement, useCallback, useContext, useEffect, useState, type ReactNode } from "react"

import { createUntraceFetcher, type FileSummary, type FolderSummary, type UntraceFetcher } from "./fetcher"

export * from "./fetcher"

const Ctx = createContext<UntraceFetcher | null>(null)

export function UntraceProvider(props: { endpoint?: string; fetch?: typeof fetch; children?: ReactNode }) {
  const [fetcher] = useState(() => createUntraceFetcher({ endpoint: props.endpoint, fetch: props.fetch }))
  return createElement(Ctx.Provider, { value: fetcher }, props.children)
}

let fallback: UntraceFetcher | null = null

export function useUntrace(): UntraceFetcher {
  return useContext(Ctx) ?? (fallback ??= createUntraceFetcher())
}

/** Files you can see, or the files of one folder. */
export function useUntraceFiles(folderId?: string | null): {
  files: FileSummary[]
  loading: boolean
  error: Error | null
  refresh: () => Promise<void>
} {
  const api = useUntrace()
  const [files, setFiles] = useState<FileSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)
  const refresh = useCallback(async () => {
    setLoading(true)
    try {
      setFiles((await api.list(null, folderId)).files)
      setError(null)
    } catch (e) {
      setError(e as Error)
    } finally {
      setLoading(false)
    }
  }, [api, folderId])
  useEffect(() => {
    void refresh()
  }, [refresh])
  return { files, loading, error, refresh }
}

/** Top-level folders you were added to, or the subfolders of `parentId`. */
export function useUntraceFolders(parentId?: string | null): {
  folders: FolderSummary[]
  loading: boolean
  error: Error | null
  refresh: () => Promise<void>
} {
  const api = useUntrace()
  const [folders, setFolders] = useState<FolderSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)
  const refresh = useCallback(async () => {
    setLoading(true)
    try {
      setFolders((await api.folders(parentId)).folders)
      setError(null)
    } catch (e) {
      setError(e as Error)
    } finally {
      setLoading(false)
    }
  }, [api, parentId])
  useEffect(() => {
    void refresh()
  }, [refresh])
  return { folders, loading, error, refresh }
}

export function useUntraceUpload(): {
  /** Upload into `folderId`: a key only uploads into a folder it was added to. */
  upload: (file: File | Blob, folderId: string, name?: string) => Promise<{ file: FileSummary }>
  uploading: boolean
  error: Error | null
} {
  const api = useUntrace()
  const [uploading, setUploading] = useState(false)
  const [error, setError] = useState<Error | null>(null)
  const upload = useCallback(
    async (file: File | Blob, folderId: string, name?: string) => {
      setUploading(true)
      setError(null)
      try {
        return await api.upload(file, folderId, name)
      } catch (e) {
        setError(e as Error)
        throw e
      } finally {
        setUploading(false)
      }
    },
    [api]
  )
  return { upload, uploading, error }
}
