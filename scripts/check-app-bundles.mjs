// Only the Chat app carries the Chat runtime (docs/plans/chat-crypto-move.md):
// every other app's build holds no Chat WASM, and none of its glue, so an
// import of @kutup/chat-core/wasm creeping back into Drive, Account, Mail or
// any other app fails the web gate instead of shipping 3 MB more to it.
// Run after `pnpm -C frontend build`.
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const apps = fileURLToPath(new URL('../frontend/apps/', import.meta.url))
// The Chat runtime's file names (scripts/build-chat-wasm.sh --out-name).
const chatRuntime = /kutup_chat_core/

function files(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = `${dir}/${name}`
    return statSync(path).isDirectory() ? files(path) : [path]
  })
}

let found = false
let checked = 0
for (const app of readdirSync(apps)) {
  if (app === 'chat') continue
  const dist = `${apps}${app}/dist`
  try {
    statSync(dist)
  } catch {
    throw new Error(`${dist} is missing: build the apps first`)
  }
  checked++
  for (const file of files(dist)) {
    const named = chatRuntime.test(file.slice(dist.length))
    const linked = /\.(js|html)$/.test(file) && chatRuntime.test(readFileSync(file, 'utf8'))
    if (named || linked) {
      console.error(`${app}: ${file.slice(apps.length)} carries the Chat runtime`)
      found = true
    }
  }
}
if (found) process.exit(1)
console.log(`no Chat runtime in the ${checked} apps that aren't Chat`)
