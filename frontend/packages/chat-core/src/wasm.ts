import { freshUrl, retryLoad } from '@kutup/crypto/retry'
import type { ChatWasmModule } from './types'

// The runtime's directory is named for its content hash (the build passes
// it in, @kutup/config/vite), so a new build is a new URL and the files can
// be cached for good. Without it (tests) the files are looked for directly
// under /chat-wasm/.
declare const __KUTUP_CHAT_WASM__: string | undefined
const BASE = typeof __KUTUP_CHAT_WASM__ === 'string' && __KUTUP_CHAT_WASM__ ? `/chat-wasm/${__KUTUP_CHAT_WASM__}` : '/chat-wasm'
const MODULE_URL = `${BASE}/kutup_chat_core.js`
const WASM_URL = `${BASE}/kutup_chat_core_bg.wasm`
let modulePromise: Promise<ChatWasmModule> | null = null

/** Load and initialize the same-origin wasm-bindgen module once per page. */
export function loadChatWasm(): Promise<ChatWasmModule> {
  if (!modulePromise) {
    // A fetch cut off by a network change is tried again, the script under
    // a fresh URL (the browser remembers a failed module); a failure is not
    // kept, so a later call starts over.
    modulePromise = retryLoad(async (n) => {
      const url = n === 0 ? MODULE_URL : freshUrl(MODULE_URL, n)
      const module = (await import(/* @vite-ignore */ url)) as ChatWasmModule
      await module.default({ module_or_path: WASM_URL })
      return module
    })
    modulePromise.catch(() => {
      modulePromise = null
    })
  }
  return modulePromise
}
