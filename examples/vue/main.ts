import { computed, createApp, defineComponent, h, watch } from "vue"
import { untracePlugin, useUntrace, useUntraceFiles, useUntraceFolders, useUntraceUpload } from "@untracenetwork/vue"

const Files = defineComponent({
  setup() {
    // A key uploads only into a folder it was added to: use the first one it can write to.
    const { folders } = useUntraceFolders()
    const folder = computed(() => folders.value.find((f) => f.role !== "viewer"))
    const { files, loading, error, refresh } = useUntraceFiles({ immediate: false, folderId: () => folder.value?.folderId })
    watch(folder, () => void refresh())
    const { upload, uploading } = useUntraceUpload()
    const api = useUntrace()
    const onChange = async (e: Event) => {
      const f = (e.target as HTMLInputElement).files?.[0]
      if (f && folder.value) {
        await upload(f, folder.value.folderId)
        await refresh()
      }
    }
    return () =>
      h("section", [
        h("input", { type: "file", disabled: uploading.value || !folder.value, onChange }),
        loading.value ? h("p", "Loading...") : null,
        error.value ? h("p", { role: "alert" }, error.value.message) : null,
        h(
          "ul",
          files.value.map((f) => h("li", { key: f.fileId }, [h("a", { href: api.downloadUrl(f.fileId), download: f.name }, f.name), ` ${f.size} bytes`]))
        ),
      ])
  },
})

createApp(Files).use(untracePlugin, { endpoint: "/api/untrace" }).mount("#app")
