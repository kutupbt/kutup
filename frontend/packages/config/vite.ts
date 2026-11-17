import { createHash } from 'node:crypto'
import { cpSync, createReadStream, existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { createRequire } from 'node:module'
import path from 'node:path'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import type { Plugin, UserConfig } from 'vite'
import { reloadGuardScript } from './src/reloadGuard.ts'
import { CSP_NONCE_PLACEHOLDER, styleNonceScript } from './src/styleNonce.ts'
import { THEME_SCRIPT } from './src/theme.ts'

/** frontend/ — the workspace root. */
const FRONTEND = path.resolve(import.meta.dirname, '../..')
const WASM_ROOT = path.join(FRONTEND, 'wasm')

export type KutupApp = 'account' | 'drive' | 'chat' | 'maps' | 'photos' | 'office' | 'contacts' | 'mail' | 'pass' | 'calendar'
export type WasmModule = 'crypto' | 'crypto-calendar' | 'chat' | 'pass' | 'mail-search'

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

/** Where the reload guard, the theme and the style nonce scripts are served from. */
const RELOAD_GUARD_FILE = 'kutup-reload-guard.js'
const THEME_FILE = 'theme.js'
const STYLE_NONCE_FILE = 'kutup-style-nonce.js'

/**
 * The classic scripts each app page runs ahead of its bundle, as files on
 * the page's own origin: the apps' policy allows no inline script
 * (frontend/docker/40-kutup-hosts.sh, docs/content-security-policy.md). The
 * reload guard ([`reloadGuard`]) comes first, in builds only (it watches the
 * built bundle); the style nonce ([`styleNonce`]) next, ahead of any module
 * that adds a `<style>`; the no-flash theme ([`THEME_SCRIPT`]) last. Ahead
 * of them all, `<meta name="csp-nonce">` holds the placeholder nginx writes
 * each response's style nonce over.
 */
function pageScripts(): Plugin {
  const build = Date.now().toString(36)
  let serving = false
  return {
    name: 'kutup-page-scripts',
    configResolved(config) {
      serving = config.command === 'serve'
    },
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        const url = (req.url ?? '').split('?')[0]
        const source = url === `/${THEME_FILE}` ? THEME_SCRIPT : url === `/${STYLE_NONCE_FILE}` ? styleNonceScript() : null
        if (source === null) return next()
        res.setHeader('Content-Type', 'text/javascript; charset=utf-8')
        res.setHeader('Cache-Control', 'no-cache')
        res.end(source)
      })
    },
    transformIndexHtml: () => [
      { tag: 'meta', attrs: { name: 'csp-nonce', content: CSP_NONCE_PLACEHOLDER }, injectTo: 'head-prepend' as const },
      ...(serving ? [] : [{ tag: 'script', attrs: { src: `/${RELOAD_GUARD_FILE}` }, injectTo: 'head-prepend' as const }]),
      { tag: 'script', attrs: { src: `/${STYLE_NONCE_FILE}` }, injectTo: 'head-prepend' as const },
      { tag: 'script', attrs: { src: `/${THEME_FILE}` }, injectTo: 'head-prepend' as const },
    ],
    generateBundle() {
      this.emitFile({ type: 'asset', fileName: RELOAD_GUARD_FILE, source: reloadGuardScript(build) })
      this.emitFile({ type: 'asset', fileName: STYLE_NONCE_FILE, source: styleNonceScript() })
      this.emitFile({ type: 'asset', fileName: THEME_FILE, source: THEME_SCRIPT })
    },
  }
}

/** Where an app serves Excalidraw's fonts (`/<this>/fonts/...`). */
const EXCALIDRAW_ASSETS = 'excalidraw-assets'

/**
 * Excalidraw (whiteboards) loads its hand-drawn fonts from
 * `window.EXCALIDRAW_ASSET_PATH`, else from esm.sh, which the apps' policy
 * does not allow. An app whose bundle holds Excalidraw gets the fonts in its
 * own `excalidraw-assets/fonts/`, and @kutup/editors points Excalidraw there
 * before it loads (packages/editors/src/whiteboard/assets.ts).
 */
function excalidrawFonts(): Plugin {
  const fonts = () => {
    const index = createRequire(path.join(FRONTEND, 'packages/editors/package.json')).resolve('@excalidraw/excalidraw')
    return path.resolve(path.dirname(index), '..', 'prod', 'fonts')
  }
  const prefix = `/${EXCALIDRAW_ASSETS}/fonts/`
  let outDir = 'dist'
  let used = false
  return {
    name: 'kutup-excalidraw-fonts',
    configResolved(config) {
      outDir = path.resolve(config.root, config.build.outDir)
    },
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        const url = decodeURIComponent((req.url ?? '').split('?')[0])
        if (!url.startsWith(prefix)) return next()
        const root = fonts()
        const file = path.resolve(root, url.slice(prefix.length))
        if (!file.startsWith(root + path.sep) || !existsSync(file) || !statSync(file).isFile()) return next()
        res.setHeader('Content-Type', 'font/woff2')
        createReadStream(file).pipe(res)
      })
    },
    generateBundle() {
      used = [...this.getModuleIds()].some((id) => id.includes('/@excalidraw/excalidraw/'))
    },
    closeBundle() {
      // Vitest runs this hook too, with a placeholder outDir: only builds copy.
      if (process.env.VITEST || !used) return
      const source = fonts()
      if (!existsSync(source)) throw new Error(`Excalidraw's fonts are missing at ${source}`)
      cpSync(source, path.join(outDir, EXCALIDRAW_ASSETS, 'fonts'), { recursive: true })
    },
  }
}

/**
 * Excalidraw 0.18 bundles an Emscripten build of woff2 (its font subsetting,
 * run when a whiteboard is exported or thumbnailed) whose embind glue builds
 * three kinds of functions from source with `new Function`, which the apps'
 * policy (no `'unsafe-eval'`) refuses. This writes each over with the
 * closure Emscripten itself generates when built without dynamic execution
 * (`-sDYNAMIC_EXECUTION=0`): a named wrapper (`createNamedFunction`), a
 * dynCall wrapper (`getDynCaller`) and the argument-marshalling invoker
 * (`craftInvokerFunction`), each behaving as the generated source did. The
 * names are those of Excalidraw's published minified build: when an upgrade
 * changes them the build fails here, as it does if any `new Function` is
 * left, instead of shipping eval (docs/content-security-policy.md).
 */
const EXCALIDRAW_NO_EVAL: [string, string][] = [
  [
    'function fA(A,g){return A=VA(A),new Function("body",`return function ${A}() {\n    "use strict";    return body.apply(this, arguments);\n};\n`)(g)}',
    'function fA(A,g){return A=VA(A),{[A]:function(){return g.apply(this,arguments)}}[A]}',
  ],
  [
    'function C(B){let E=[];for(let G=1;G<A.length;++G)E.push(`a${G}`);let D=`return function ${`dynCall_${A}_${g}`}(${E.join(", ")}) {\n`;return D+=`    return dynCall(rawFunction${E.length?", ":""}${E.join(", ")});\n`,D+=`};\n`,new Function("dynCall","rawFunction",D)(B,g)}',
    'function C(B){return function(...E){return B(g,...E)}}',
  ],
  [
    'function xg(A,g,C,Q,B){let E=g.length;E<2&&c("argTypes array size mismatch! Must at least get return value and \'this\' types!");let i=g[1]!==null&&C!==null,D=!1;for(var G=1;G<g.length;++G)if(g[G]!==null&&g[G].destructorFunction===void 0){D=!0;break}let h=g[0].name!=="void",N="",s="";for(var G=0;G<E-2;++G)N+=`${G!==0?", ":""}arg${G}`,s+=`${G!==0?", ":""}arg${G}Wired`;let R=`return function ${VA(A)}(${N}) {\nif (arguments.length !== ${E-2}) {\nthrowBindingError(\'function ${A} called with \' + arguments.length + \' arguments, expected ${E-2} args!\');\n}\n`;D&&(R+=`var destructors = [];\n`);let S=D?"destructors":"null",d=["throwBindingError","invoker","fn","runDestructors","retType","classParam"],X=[c,Q,B,ng,g[0],g[1]];i&&(R+=`var thisWired = classParam.toWireType(${S}, this);\n`);for(var G=0;G<E-2;++G)R+=`var arg${G}Wired = argType${G}.toWireType(${S}, arg${G}); // ${g[G+2].name}\n`,d.push(`argType${G}`),X.push(g[G+2]);if(i&&(s=`thisWired${s.length>0?", ":""}${s}`),R+=`${h?"var rv = ":""}invoker(fn${s.length>0?", ":""}${s});\n`,D)R+=`runDestructors(destructors);\n`;else for(var G=i?1:2;G<g.length;++G){let IA=G===1?"thisWired":`arg${G-2}Wired`;g[G].destructorFunction!==null&&(R+=`${IA}_dtor(${IA}); // ${g[G].name}\n`,d.push(`${IA}_dtor`),X.push(g[G].destructorFunction))}return h&&(R+=`var ret = retType.fromWireType(rv);\nreturn ret;\n`),R+=`}\n`,d.push(R),RC(Function,d).apply(null,X)}',
    'function xg(A,g,C,Q,B){let E=g.length;E<2&&c("argTypes array size mismatch! Must at least get return value and \'this\' types!");let i=g[1]!==null&&C!==null,D=!1;for(var G=1;G<g.length;++G)if(g[G]!==null&&g[G].destructorFunction===void 0){D=!0;break}let h=g[0].name!=="void",n=E-2;return fA(A,function(...a){a.length!==n&&c(`function ${A} called with ${a.length} arguments, expected ${n} args!`);let r=D?[]:null,w=[B],t,W=[];i&&(t=g[1].toWireType(r,this),w.push(t));for(let k=0;k<n;++k)W.push(g[k+2].toWireType(r,a[k])),w.push(W[k]);let v=Q(...w);if(D)ng(r);else for(let k=i?1:2;k<g.length;++k)g[k].destructorFunction!==null&&g[k].destructorFunction(k===1?t:W[k-2]);if(h)return g[0].fromWireType(v)})}',
  ],
]

function excalidrawNoEval(): Plugin {
  return {
    name: 'kutup-excalidraw-no-eval',
    transform(code, id) {
      if (!/\/@excalidraw\/excalidraw\/dist\/prod\/[^/]+\.js$/.test(id.split('?')[0]) || !code.includes('new Function')) return null
      let out = code
      for (const [from, to] of EXCALIDRAW_NO_EVAL) {
        if (out.split(from).length !== 2) {
          throw new Error(`kutup-excalidraw-no-eval: ${path.basename(id)} no longer holds the embind code it rewrites (Excalidraw upgraded?): update EXCALIDRAW_NO_EVAL in frontend/packages/config/vite.ts`)
        }
        out = out.replace(from, () => to)
      }
      if (/new Function|\(Function,/.test(out)) {
        throw new Error(`kutup-excalidraw-no-eval: ${path.basename(id)} still builds code with new Function`)
      }
      return { code: out, map: null }
    },
  }
}

/**
 * The WASM runtimes are fetched from absolute paths on the page's own origin,
 * `/crypto-wasm/<hash>/…`, `/chat-wasm/<hash>/…` and `/pass-wasm/<hash>/…` (see
 * @kutup/crypto/rustWasm, @kutup/chat-core/wasm and the Pass app), the hash being the files' own: a new build is a
 * new URL, so they can be cached for good. The bundle learns the hashes as
 * `__KUTUP_CRYPTO_WASM__`, `__KUTUP_CHAT_WASM__` and `__KUTUP_PASS_WASM__`. `pnpm build:wasm` writes
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
          // The crypto runtime this app loads, as `<dir>/<hash>`: `crypto`,
          // or `crypto-calendar` (the same and calendars) where the app
          // lists it; never both.
          __KUTUP_CRYPTO_WASM__: JSON.stringify(
            modules.includes('crypto-calendar')
              ? `crypto-calendar-wasm/${wasmHash('crypto-calendar')}`
              : `crypto-wasm/${wasmHash('crypto')}`,
          ),
          __KUTUP_CHAT_WASM__: JSON.stringify(wasmHash('chat')),
          __KUTUP_PASS_WASM__: JSON.stringify(wasmHash('pass')),
          __KUTUP_MAIL_SEARCH_WASM__: JSON.stringify(wasmHash('mail-search')),
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
        const hash = wasmHash(dir.replace(/-wasm$/, '') as WasmModule)
        cpSync(src, path.join(outDir, dir, hash), { recursive: true })
      }
    },
  }
}

/** The one service worker's source (src/sw/kutup-sw.js): a plain script, served as it is. */
const SERVICE_WORKER_SOURCE = path.join(import.meta.dirname, 'src/sw/kutup-sw.js')
const SERVICE_WORKER_FILE = 'kutup-sw.js'

/**
 * Kutup's service worker (src/sw/kutup-sw.js: media streams and Web Push)
 * at `/kutup-sw.js` in the apps that register it: copied into the build as
 * it is, and served from source in dev. Streams live only in the worker, so
 * the dev server answers `/sw/*` with 404 as the frontend container does
 * (frontend/docker/40-kutup-hosts.sh), never with the app.
 */
function kutupServiceWorker(): Plugin {
  return {
    name: 'kutup-service-worker',
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        const url = (req.url ?? '').split('?')[0]
        if (url === `/${SERVICE_WORKER_FILE}`) {
          res.setHeader('Content-Type', 'text/javascript; charset=utf-8')
          res.setHeader('Cache-Control', 'no-cache')
          res.end(readFileSync(SERVICE_WORKER_SOURCE))
          return
        }
        if (url.startsWith('/sw/')) {
          res.statusCode = 404
          res.setHeader('Cache-Control', 'no-store')
          res.end()
          return
        }
        next()
      })
    },
    generateBundle() {
      this.emitFile({ type: 'asset', fileName: SERVICE_WORKER_FILE, source: readFileSync(SERVICE_WORKER_SOURCE, 'utf8') })
    },
  }
}

/** Dev ports; each app also has its own hostname so cookies stay per app. */
export const DEV_PORTS: Record<KutupApp | 'editor', number> = { account: 5173, drive: 5174, chat: 5175, editor: 5176, maps: 5177, photos: 5178, office: 5179, contacts: 5180, mail: 5181, pass: 5182, calendar: 5183 }

/**
 * The Vite config every Kutup web app shares. Each app runs on its own
 * origin (account. / drive. / chat.) and calls `/api` on that origin; in dev
 * Vite proxies it to kutup-server (KUTUP_API_TARGET, default :3000).
 * KUTUP_DEV_DOMAIN and KUTUP_DEV_PORT_OFFSET move the apps for a second
 * local server (docs/contributing.md).
 */
export function kutupApp(opts: {
  app: KutupApp
  wasm: WasmModule[]
  /** The app registers Kutup's service worker (streams, Web Push): `/kutup-sw.js` is built in. */
  serviceWorker?: boolean
}): UserConfig {
  const requireFromCrypto = createRequire(path.join(FRONTEND, 'packages/crypto/package.json'))
  const apiTarget = process.env.KUTUP_API_TARGET ?? 'http://localhost:3000'
  // A second local server (federation testing) runs its apps on
  // <app>.<KUTUP_DEV_DOMAIN>, KUTUP_DEV_PORT_OFFSET ports up.
  const domain = process.env.KUTUP_DEV_DOMAIN || 'localhost'
  const port = DEV_PORTS[opts.app] + Number(process.env.KUTUP_DEV_PORT_OFFSET || 0)
  return {
    plugins: [
      tailwindcss(),
      react(),
      kutupWasm(opts.wasm),
      pageScripts(),
      excalidrawFonts(),
      excalidrawNoEval(),
      ...(opts.serviceWorker ? [kutupServiceWorker()] : []),
    ],
    worker: { format: 'es' },
    // The release this build belongs to (docs/plans/api-surface.md §1.2),
    // stamped by scripts/publish-images.sh; `0.0.0-dev` otherwise.
    define: { __KUTUP_RELEASE__: JSON.stringify(process.env.KUTUP_RELEASE || '0.0.0-dev') },
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
 * cookies, embedded by Office (where documents and PDFs open) and nothing else.
 *
 * The CSP here is the dev server's; in production the frontend container
 * sends the same policy with the configured Office origin (KUTUP_OFFICE_URL;
 * frontend/docker/40-kutup-hosts.sh).
 * OnlyOffice needs eval and inline script, which is exactly why it gets an
 * origin that holds nothing worth stealing.
 */
export function editorSandboxCsp(officeOrigin: string): string {
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
    `frame-ancestors 'self' ${officeOrigin}`,
    "base-uri 'none'",
    "form-action 'none'",
    // The strict policy's one addition (report-only in production until
    // KUTUP_CSP_ENFORCE=1; docs/content-security-policy.md).
    "object-src 'none'",
  ].join('; ')
}

export function kutupEditorSandbox(): UserConfig {
  const office = process.env.KUTUP_OFFICE_URL ?? `http://office.localhost:${DEV_PORTS.office}`
  const headers = {
    'Content-Security-Policy': editorSandboxCsp(new URL(office).origin),
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
