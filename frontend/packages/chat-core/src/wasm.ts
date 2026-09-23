import type { ChatWasmModule } from './types'

// Epoch 2 escapes the pre-fix immutable browser cache used by the original
// stable URLs. Future deployments rely on mandatory revalidation and do not
// need an epoch bump unless the public path itself changes again.
const RUNTIME_CACHE_EPOCH = '2'
const MODULE_URL = `/chat-wasm/kutup_chat_core.js?runtime=${RUNTIME_CACHE_EPOCH}`
const WASM_URL = `/chat-wasm/kutup_chat_core_bg.wasm?runtime=${RUNTIME_CACHE_EPOCH}`
let modulePromise: Promise<ChatWasmModule> | null = null

/** Load and initialize the same-origin wasm-bindgen module once per page. */
export function loadChatWasm(): Promise<ChatWasmModule> {
  if (!modulePromise) {
    modulePromise = (async () => {
      const module = (await import(/* @vite-ignore */ MODULE_URL)) as ChatWasmModule
      await module.default(WASM_URL)
      return module
    })()
  }
  return modulePromise
}
