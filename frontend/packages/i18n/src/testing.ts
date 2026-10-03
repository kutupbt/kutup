import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import type { Messages } from './index'

/** Flatten to dotted key paths. */
export function flattenKeys(obj: unknown, prefix = ''): string[] {
  if (typeof obj !== 'object' || obj === null) return [prefix]
  return Object.entries(obj as Record<string, unknown>).flatMap(([k, v]) =>
    flattenKeys(v, prefix ? `${prefix}.${k}` : k),
  )
}

function emptyKeys(obj: unknown, path = ''): string[] {
  if (typeof obj === 'string') return obj.trim() === '' ? [path] : []
  if (typeof obj !== 'object' || obj === null) return []
  return Object.entries(obj as Record<string, unknown>).flatMap(([k, v]) =>
    emptyKeys(v, path ? `${path}.${k}` : k),
  )
}

export interface LocaleReport {
  onlyInEn: string[]
  onlyInTr: string[]
  empty: string[]
  /** `file: key` for every literal `t('…')` / `key: '…'` not defined in `en`. */
  missing: string[]
}

/**
 * The three rules, as data a test asserts is empty:
 * en/tr define the same keys, no value is empty, and every literal key the
 * source asks for exists. i18next renders a missing key as the key itself,
 * so this is the cheap place to catch "common.edit" shipping as a label.
 * Template keys (t(`kinds.${kind}`)) are not checkable here by construction.
 */
export function checkLocales(opts: { en: Messages; tr: Messages; sourceDirs: string[] }): LocaleReport {
  const en = new Set(flattenKeys(opts.en))
  const tr = new Set(flattenKeys(opts.tr))
  const missing: string[] = []

  const walk = (dir: string) => {
    for (const entry of readdirSync(dir)) {
      const path = join(dir, entry)
      if (statSync(path).isDirectory()) {
        if (entry !== 'node_modules') walk(path)
        continue
      }
      if (!/\.tsx?$/.test(entry) || /\.test\.tsx?$/.test(entry)) continue
      const source = readFileSync(path, 'utf8')
      for (const match of source.matchAll(/(\bt\(|\bkey: |\bi18nKey=\{?)['"]([A-Za-z0-9_.]+)['"]/g)) {
        const key = match[2]
        // `key: '…'` names a message in a table (`key: 'editor.shortcuts.save'`),
        // always dotted; an undotted one is something else's key (a keymap's
        // `key: 'Enter'`).
        if (match[1] === 'key: ' && !key.includes('.')) continue
        const found = en.has(key) || en.has(`${key}_one`) || en.has(`${key}_other`)
        if (!found) missing.push(`${entry}: ${key}`)
      }
    }
  }
  for (const dir of opts.sourceDirs) walk(dir)

  return {
    onlyInEn: [...en].filter((k) => !tr.has(k)).sort(),
    onlyInTr: [...tr].filter((k) => !en.has(k)).sort(),
    empty: [...emptyKeys(opts.en), ...emptyKeys(opts.tr)],
    missing,
  }
}
