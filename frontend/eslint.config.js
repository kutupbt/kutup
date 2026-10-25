import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'

/*
 * Two families of rules, both enforcing decisions that decay without a gate
 * (inherited from the asec-next frontend, see docs/frontend.md):
 *
 * - Raw Tailwind palette classes are banned: every colour is a token in
 *   packages/ui/src/styles/tokens.css, or dark mode rots where people look.
 * - Native <select> and checkbox are banned: they take the platform's chrome,
 *   cannot be themed and render in the platform font. Use the ui primitives.
 *
 * The new UI code (apps/*, packages/ui, packages/i18n, packages/config, packages/map, packages/drive-core, packages/drive-ui, packages/editors, packages/contacts-core, packages/mail-core, packages/calendar-core) gets
 * the type-checked rule set. The logic packages moved from the old SPA
 * (crypto, session, files, collab, chat-core) get the untyped recommended set
 * until they are tightened on their own. Both refuse Web Crypto and libsodium
 * outside packages/crypto.
 */
const PALETTE =
  'slate|gray|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose'
const PALETTE_CLASS = String.raw`(^|\s)(bg|text|border|ring|fill|stroke|from|to|via)-(${PALETTE})-\d{2,3}(\s|$)`

const restricted = [
  'error',
  {
    selector: `Literal[value=/${PALETTE_CLASS}/]`,
    message: 'Raw Tailwind palette class. Use a semantic token (bg-card, text-muted-foreground, bg-status-ok).',
  },
  {
    selector: `TemplateElement[value.raw=/${PALETTE_CLASS}/]`,
    message: 'Raw Tailwind palette class in a template literal. Use a semantic token.',
  },
  {
    selector: "JSXOpeningElement[name.name='select']",
    message: 'Native <select>. Use @kutup/ui/components/select (Radix); "any" options take SELECT_ANY.',
  },
  {
    selector:
      "JSXOpeningElement[name.name='input'] > JSXAttribute[name.name='type'][value.value='checkbox']",
    message: 'Native checkbox. Use @kutup/ui/components/checkbox with an explicit <label htmlFor>.',
  },
]

/*
 * A typed array's `.buffer` is its whole backing buffer, not the view: for a
 * view WASM hands back, the module's whole memory (keys, plaintext). It must
 * never reach the network, storage, a Blob or a transfer list: those take
 * `exactBytes(view)` from @kutup/crypto/bytes.
 */
const BUFFER_MESSAGE =
  "A view's .buffer is its whole backing buffer (all of WASM memory for a view into it). Pass exactBytes(view) from @kutup/crypto/bytes."
const bufferSinks = [
  {
    selector:
      "CallExpression[callee.property.name=/^(post|put|patch|request|send|postMessage|add|append)$/] MemberExpression[property.name='buffer']",
    message: BUFFER_MESSAGE,
  },
  {
    selector: "CallExpression[callee.name=/^(fetch|postMessage)$/] MemberExpression[property.name='buffer']",
    message: BUFFER_MESSAGE,
  },
  {
    selector: "NewExpression[callee.name=/^(Blob|File|Response|Request)$/] MemberExpression[property.name='buffer']",
    message: BUFFER_MESSAGE,
  },
]

restricted.push(...bufferSinks)

/*
 * One random source, one hash and one signature (docs/plans/crypto-primitives.md,
 * step 5): outside @kutup/crypto nothing calls Web Crypto or libsodium; it
 * takes randomBytes/fillRandom (@kutup/crypto/random), hash/createHasher
 * (@kutup/crypto/hash) and sign/verify (@kutup/crypto/signing), as Rust takes
 * kutup_crypto::primitives. Every way to reach them is refused: a member by
 * name, a computed member, a destructured property, Reflect, and imports
 * static or dynamic. The static gate refuses eslint-disable for these rules
 * (scripts/check-crypto-exceptions.py).
 */
const WEB_CRYPTO_MESSAGE =
  'Web Crypto outside @kutup/crypto. Use @kutup/crypto/random, /hash or /signing.'
const SODIUM_MESSAGE = 'libsodium outside @kutup/crypto. Use @kutup/crypto, which calls kutup-crypto (WASM).'
const API = '/^(subtle|getRandomValues)$/'
const webCrypto = [
  { selector: `MemberExpression[property.name=${API}]`, message: WEB_CRYPTO_MESSAGE },
  // crypto['subtle'], crypto[`subtle`], crypto[name], globalThis.crypto[name].
  { selector: `MemberExpression[computed=true][property.value=${API}]`, message: WEB_CRYPTO_MESSAGE },
  { selector: "MemberExpression[computed=true][object.name='crypto']", message: WEB_CRYPTO_MESSAGE },
  { selector: "MemberExpression[computed=true][object.property.name='crypto']", message: WEB_CRYPTO_MESSAGE },
  // Taken apart: const { subtle } = crypto, { 'subtle': s }, { [name]: s }.
  { selector: `ObjectPattern > Property[key.name=${API}]`, message: WEB_CRYPTO_MESSAGE },
  { selector: `ObjectPattern > Property[key.value=${API}]`, message: WEB_CRYPTO_MESSAGE },
  { selector: "VariableDeclarator[init.name='crypto'] > ObjectPattern > Property[computed=true]", message: WEB_CRYPTO_MESSAGE },
  { selector: "VariableDeclarator[init.property.name='crypto'] > ObjectPattern > Property[computed=true]", message: WEB_CRYPTO_MESSAGE },
  // Reflect.get(crypto, 'subtle') and its kin.
  { selector: "CallExpression[callee.object.name='Reflect'][arguments.0.name='crypto']", message: WEB_CRYPTO_MESSAGE },
  { selector: "CallExpression[callee.object.name='Reflect'][arguments.0.property.name='crypto']", message: WEB_CRYPTO_MESSAGE },
  // A dynamic import, which no-restricted-imports doesn't see.
  { selector: "ImportExpression[source.value=/^(libsodium-wrappers|@kutup\\/crypto\\/sodium)|crypto\\/src\\/sodium/]", message: SODIUM_MESSAGE },
]
/* A dynamic import of a computed name can reach anything; the WASM loaders
   that load their own glue by URL are named below. */
const computedImports = [
  {
    selector: "ImportExpression[source.type!='Literal']",
    message: 'A dynamic import of a computed name. Name the module; a WASM loader is a named exception in eslint.config.js.',
  },
]
const sodiumImports = [
  'error',
  {
    paths: ['libsodium-wrappers-sumo', 'libsodium-wrappers', '@kutup/crypto/sodium'].map((name) => ({
      name,
      message: SODIUM_MESSAGE,
    })),
    patterns: [{ group: ['libsodium-wrappers*', 'libsodium-wrappers*/**', '@kutup/crypto/sodium/**', '**/crypto/src/sodium', '**/crypto/src/sodium.*'], message: SODIUM_MESSAGE }],
  },
]

const UI_CODE = ['apps/*/src/**/*.{ts,tsx}', 'packages/{ui,i18n,config,map,drive-core,drive-ui,editors,contacts-core,mail-core,calendar-core}/**/*.{ts,tsx}']
const LOGIC_CODE = ['packages/{session,files,collab,chat-core}/src/**/*.{ts,tsx,js,mjs}']
const CRYPTO_CODE = ['packages/crypto/src/**/*.ts']
/* The WASM loaders that import their own wasm-bindgen glue by URL. */
const UI_WASM_LOADERS = ['apps/pass/src/vault/worker.ts', 'packages/mail-core/src/searchWasm.ts']
const LOGIC_WASM_LOADERS = ['packages/chat-core/src/wasm.ts']
/* Scripts served as they are (service workers, early theme scripts). */
const PUBLIC_SCRIPTS = ['apps/*/public/**/*.{js,mjs}']
/* Named exception: the calendar's push worker checks a push's account tag
   with Web Crypto's HMAC (the suite's MAC, as calendar_alarms.rs makes it);
   a service worker can't load @kutup/crypto's WASM before it must answer. */
const PUBLIC_WEB_CRYPTO_EXCEPTIONS = ['apps/calendar/public/push-sw.js']

export default tseslint.config(
  { ignores: ['**/dist', '**/node_modules', 'wasm', 'apps/editor/public'] },
  {
    files: UI_CODE,
    extends: [js.configs.recommended, ...tseslint.configs.recommendedTypeChecked],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
    plugins: { 'react-hooks': reactHooks, 'react-refresh': reactRefresh },
    rules: {
      ...reactHooks.configs.recommended.rules,
      'react-refresh/only-export-components': ['warn', { allowConstantExport: true }],
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      'no-restricted-syntax': [...restricted, ...webCrypto, ...computedImports],
      'no-restricted-imports': sodiumImports,
    },
  },
  {
    files: LOGIC_CODE,
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    languageOptions: { ecmaVersion: 2022, globals: { ...globals.browser, ...globals.worker } },
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      'no-restricted-syntax': ['error', ...bufferSinks, ...webCrypto, ...computedImports],
      'no-restricted-imports': sodiumImports,
    },
  },
  {
    files: UI_WASM_LOADERS,
    rules: { 'no-restricted-syntax': [...restricted, ...webCrypto] },
  },
  {
    files: LOGIC_WASM_LOADERS,
    rules: { 'no-restricted-syntax': ['error', ...bufferSinks, ...webCrypto] },
  },
  {
    files: PUBLIC_SCRIPTS,
    languageOptions: { ecmaVersion: 2022, sourceType: 'script', globals: { ...globals.browser, ...globals.serviceworker } },
    rules: {
      'no-restricted-syntax': ['error', ...webCrypto, ...computedImports],
      'no-restricted-imports': sodiumImports,
    },
  },
  {
    files: PUBLIC_WEB_CRYPTO_EXCEPTIONS,
    rules: { 'no-restricted-syntax': ['error', ...computedImports] },
  },
  {
    // The one place that calls Web Crypto and libsodium.
    files: CRYPTO_CODE,
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    languageOptions: { ecmaVersion: 2022, globals: { ...globals.browser, ...globals.worker } },
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      'no-restricted-syntax': ['error', ...bufferSinks],
    },
  },
  {
    files: ['**/*.test.{ts,tsx}'],
    rules: {
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-non-null-assertion': 'off',
    },
  },
)
