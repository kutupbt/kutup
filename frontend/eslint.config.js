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
 * The new UI code (apps/*, packages/ui, packages/i18n, packages/config, packages/map, packages/drive-core, packages/drive-ui, packages/contacts-core) gets
 * the type-checked rule set. The logic packages moved from the old SPA
 * (crypto, session, files, collab, chat-core) get the untyped recommended set
 * until they are tightened on their own.
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

const UI_CODE = ['apps/*/src/**/*.{ts,tsx}', 'packages/{ui,i18n,config,map,drive-core,drive-ui,contacts-core}/**/*.{ts,tsx}']
const LOGIC_CODE = ['packages/{crypto,session,files,collab,chat-core}/src/**/*.ts']

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
      'no-restricted-syntax': restricted,
    },
  },
  {
    files: LOGIC_CODE,
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    languageOptions: { ecmaVersion: 2022, globals: { ...globals.browser, ...globals.worker } },
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
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
