// Every WASM runtime against its gzipped size budget (frontend/wasm-budgets.json),
// so none grows unnoticed: prints each runtime's size and budget, and fails
// when one is over. Run after `pnpm -C frontend build:wasm`.
import { readFile } from 'node:fs/promises'
import { readdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { gzipSync } from 'node:zlib'

const frontend = fileURLToPath(new URL('../frontend/', import.meta.url))
const { budgets } = JSON.parse(await readFile(`${frontend}wasm-budgets.json`, 'utf8'))
let over = false
for (const [runtime, budget] of Object.entries(budgets)) {
  const dir = `${frontend}wasm/${runtime}-wasm`
  const file = readdirSync(dir).find((name) => name.endsWith('_bg.wasm'))
  if (!file) throw new Error(`${dir} has no WASM: build it first`)
  const raw = await readFile(`${dir}/${file}`)
  const gz = gzipSync(raw, { level: 9 }).length
  const share = ((gz / budget) * 100).toFixed(1)
  console.log(`${runtime.padEnd(16)} ${String(raw.length).padStart(9)} raw ${String(gz).padStart(9)} gz  budget ${budget} (${share}%)`)
  if (gz > budget) {
    console.error(`${runtime} is over its budget by ${gz - budget} bytes`)
    over = true
  }
}
if (over) process.exit(1)
