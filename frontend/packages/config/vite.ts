import { createHash } from 'node:crypto'
import { cpSync, createReadStream, existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { createRequire } from 'node:module'
import path from 'node:path'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import type { Plugin, UserConfig } from 'vite'

/** frontend/ — the workspace root. */
const FRONTEND = path.resolve(import.meta.dirname, '../..')
const WASM_ROOT = path.join(FRONTEND, 'wasm')

export type KutupApp = 'account' | 'drive' | 'chat' | 'maps' | 'photos' | 'office'
export type WasmModule = 'crypto' | 'chat'

/**
 * A WASM runtime's content hash (16 hex digits): its directory's files, in
 * name order. Missing (not built yet) is the empty string.
 */
export function wasmHash(module: WasmModule): string {
  const dir = path.join(WASM_ROOT, `${module}-wasm`)
  if (!existsSync(dir)) return ''
  const hash = createHash('sha256')
  for (const name of readdirSync(dir).sort()) {
    const file = path.join(dir, name)
    if (!statSync(file).isFile()) continue
    hash.update(name).update('\0').update(readFileSync(file)).update('\0')
  }
  return hash.digest('hex').slice(0, 16)
}

/**
 * The WASM runtimes are fetched from absolute paths on the page's own origin,
 * `/crypto-wasm/<hash>/…` and `/chat-wasm/<hash>/…` (see @kutup/crypto/rustWasm
 * and @kutup/chat-core/wasm), the hash being the files' own: a new build is a
 * new URL, so they can be cached for good. The bundle learns the hashes as
 * `__KUTUP_CRYPTO_WASM__` and `__KUTUP_CHAT_WASM__`. `pnpm build:wasm` writes
 * the files once to frontend/wasm; this serves them in dev and copies them
 * into each app's dist on build.
 */
function kutupWasm(modules: WasmModule[]): Plugin {
  const dirs = modules.map((m) => `${m}-wasm`)
  let outDir = 'dist'
  return {
    name: 'kutup-wasm',
    config() {
      return {
        define: {
          __KUTUP_CRYPTO_WASM__: JSON.stringify(wasmHash('crypto')),
          __KUTUP_CHAT_WASM__: JSON.stringify(wasmHash('chat')),
        },
      }
    },
    configResolved(config) {
      outDir = path.resolve(config.root, config.build.outDir)
    },
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        const url = (req.url ?? '').split('?')[0]
        const dir = dirs.find((d) => url.startsWith(`/${d}/`))
        if (!dir) return next()
        const file = path.join(WASM_ROOT, dir, path.basename(url))
        if (!existsSync(file) || !statSync(file).isFile()) return next()
        res.setHeader(
          'Content-Type',
          file.endsWith('.wasm') ? 'application/wasm' : 'text/javascript; charset=utf-8',
        )
        res.setHeader('Cache-Control', 'no-cache')
        createReadStream(file).pipe(res)
      })
    },
    closeBundle() {
      // Vitest runs this hook too, with a placeholder outDir: only builds copy.
      if (process.env.VITEST) return
      for (const dir of dirs) {
        const src = path.join(WASM_ROOT, dir)
        if (!existsSync(src)) {
          throw new Error(`${src} is missing — run \`pnpm -C frontend build:wasm\` first`)
        }
        const hash = wasmHash(dir === 'crypto-wasm' ? 'crypto' : 'chat')
        cpSync(src, path.join(outDir, dir, hash), { recursive: true })
      }
    },
  }
}

/** Dev ports; each app also has its own hostname so cookies stay per app. */
export const DEV_PORTS: Record<KutupApp | 'editor', number> = { account: 5173, drive: 5174, chat: 5175, editor: 5176, maps: 5177, photos: 5178, office: 5179 }

/**
 * The Vite config every Kutup web app shares. Each app runs on its own
 * origin (account. / drive. / chat.) and calls `/api` on that origin; in dev
 * Vite proxies it to kutup-server (KUTUP_API_TARGET, default :3000).
 * KUTUP_DEV_DOMAIN and KUTUP_DEV_PORT_OFFSET move the apps for a second
 * local server (docs/contributing.md).
 */
export function kutupApp(opts: { app: KutupApp; wasm: WasmModule[] }): UserConfig {
  const requireFromCrypto = createRequire(path.join(FRONTEND, 'packages/crypto/package.json'))
  const apiTarget = process.env.KUTUP_API_TARGET ?? 'http://localhost:3000'
  // A second local server (federation testing) runs its apps on
  // <app>.<KUTUP_DEV_DOMAIN>, KUTUP_DEV_PORT_OFFSET ports up.
  const domain = process.env.KUTUP_DEV_DOMAIN || 'localhost'
  const port = DEV_PORTS[opts.app] + Number(process.env.KUTUP_DEV_PORT_OFFSET || 0)
  return {
    plugins: [tailwindcss(), react(), kutupWasm(opts.wasm)],
    worker: { format: 'es' },
    resolve: {
      alias: {
        // The ESM build of libsodium-wrappers-sumo has a broken relative
        // import for libsodium-sumo.mjs; force the CJS build.
        'libsodium-wrappers-sumo': requireFromCrypto.resolve('libsodium-wrappers-sumo'),
      },
    },
    optimizeDeps: { include: ['libsodium-wrappers-sumo', 'buffer'] },
    // Maps are written for local debugging but not referenced from the
    // bundles; the image leaves them out (frontend/Dockerfile).
    build: { target: 'es2022', sourcemap: 'hidden' },
    server: {
      host: `${opts.app}.${domain}`,
      port,
      strictPort: true,
      allowedHosts: [`${opts.app}.${domain}`],
      proxy: {
        '/api': { target: apiTarget, changeOrigin: false, ws: true, secure: false },
      },
    },
  }
}

/**
 * The OnlyOffice sandbox (editor.<domain>): static files only — the bridge
 * page, x2t and the OnlyOffice client — with no API, no session and no
 * cookies, embedded by Drive and nothing else.
 *
 * The CSP here is the dev server's; in production the reverse proxy sends
 * the same policy with the configured Drive origin (KUTUP_DRIVE_URL).
 * OnlyOffice needs eval and inline script, which is exactly why it gets an
 * origin that holds nothing worth stealing.
 */
export function editorSandboxCsp(driveOrigin: string): string {
  return [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' 'wasm-unsafe-eval'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    "media-src 'self' blob:",
    "connect-src 'self' data: blob:",
    "worker-src 'self' blob:",
    "frame-src 'self' blob:",
    // 'self': OnlyOffice nests its own editor frame inside the bridge, and
    // frame-ancestors is checked against every ancestor, not just the top.
    `frame-ancestors 'self' ${driveOrigin}`,
    "base-uri 'none'",
    "form-action 'none'",
  ].join('; ')
}

export function kutupEditorSandbox(): UserConfig {
  const drive = process.env.KUTUP_DRIVE_URL ?? `http://drive.localhost:${DEV_PORTS.drive}`
  const headers = {
    'Content-Security-Policy': editorSandboxCsp(new URL(drive).origin),
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
  }
  const server = {
    host: 'editor.localhost',
    port: DEV_PORTS.editor,
    strictPort: true,
    allowedHosts: ['editor.localhost'],
    headers,
  }
  return {
    // The bridge pages are plain HTML in public/; nothing is bundled.
    appType: 'mpa',
    build: { outDir: 'dist', emptyOutDir: true },
    server,
    preview: server,
  }
}
