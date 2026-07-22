import type { ChatWasmModule } from './types'

const MODULE_URL = '/chat-wasm/kutup_chat_core.js'
let modulePromise: Promise<ChatWasmModule> | null = null

/** Load and initialize the same-origin wasm-bindgen module once per page. */
export function loadChatWasm(): Promise<ChatWasmModule> {
  if (!modulePromise) {
    modulePromise = (async () => {
      const module = (await import(/* @vite-ignore */ MODULE_URL)) as ChatWasmModule
      await module.default()
      return module
    })()
  }
  return modulePromise
}
