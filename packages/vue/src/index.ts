/**
 * @untracenetwork/vue: composables that call YOUR backend route. No secret in the browser.
 */
import { inject, onMounted, ref, toValue, type App, type InjectionKey, type MaybeRefOrGetter, type Ref } from "vue"

import { createUntraceFetcher, type FileSummary, type FolderSummary, type UntraceFetcher } from "./fetcher"

export * from "./fetcher"

export const UNTRACE_KEY: InjectionKey<UntraceFetcher> = Symbol("untrace")

/** `app.use(untracePlugin, { endpoint: "/api/untrace" })` */
export const untracePlugin = {
  install(app: App, opts: { endpoint?: string; fetch?: typeof fetch } = {}) {
    app.provide(UNTRACE_KEY, createUntraceFetcher(opts))
  },
}

export function useUntrace(): UntraceFetcher {
  return inject(UNTRACE_KEY, null) ?? createUntraceFetcher()
}

/** Files you can see, or the files of `opts.folderId` (a value, ref or getter, read on each refresh). */
export function useUntraceFiles(opts: { immediate?: boolean; folderId?: MaybeRefOrGetter<string | null | undefined> } = {}): {
  files: Ref<FileSummary[]>
  loading: Ref<boolean>
  error: Ref<Error | null>
  refresh: () => Promise<void>
} {
  const api = useUntrace()
  const files = ref<FileSummary[]>([]) as Ref<FileSummary[]>
  const loading = ref(false)
  const error = ref<Error | null>(null)
  const refresh = async () => {
    loading.value = true
    try {
      files.value = (await api.list(null, toValue(opts.folderId))).files
      error.value = null
    } catch (e) {
      error.value = e as Error
    } finally {
      loading.value = false
    }
  }
  if (opts.immediate !== false) onMounted(() => void refresh())
  return { files, loading, error, refresh }
}

/** Top-level folders you were added to, or the subfolders of `opts.parentId` (a value, ref or getter). */
export function useUntraceFolders(opts: { immediate?: boolean; parentId?: MaybeRefOrGetter<string | null | undefined> } = {}): {
  folders: Ref<FolderSummary[]>
  loading: Ref<boolean>
  error: Ref<Error | null>
  refresh: () => Promise<void>
} {
  const api = useUntrace()
  const folders = ref<FolderSummary[]>([]) as Ref<FolderSummary[]>
  const loading = ref(false)
  const error = ref<Error | null>(null)
  const refresh = async () => {
    loading.value = true
    try {
      folders.value = (await api.folders(toValue(opts.parentId))).folders
      error.value = null
    } catch (e) {
      error.value = e as Error
    } finally {
      loading.value = false
    }
  }
  if (opts.immediate !== false) onMounted(() => void refresh())
  return { folders, loading, error, refresh }
}

export function useUntraceUpload(): {
  /** Upload into `folderId`: a key only uploads into a folder it was added to. */
  upload: (file: File | Blob, folderId: string, name?: string) => Promise<{ file: FileSummary }>
  uploading: Ref<boolean>
  error: Ref<Error | null>
} {
  const api = useUntrace()
  const uploading = ref(false)
  const error = ref<Error | null>(null)
  const upload = async (file: File | Blob, folderId: string, name?: string) => {
    uploading.value = true
    error.value = null
    try {
      return await api.upload(file, folderId, name)
    } catch (e) {
      error.value = e as Error
      throw e
    } finally {
      uploading.value = false
    }
  }
  return { upload, uploading, error }
}
