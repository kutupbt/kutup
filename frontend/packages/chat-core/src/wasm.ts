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
    modulePromise = (async () => {
      const module = (await import(/* @vite-ignore */ MODULE_URL)) as ChatWasmModule
      await module.default({ module_or_path: WASM_URL })
      return module
    })()
  }
  return modulePromise
}
