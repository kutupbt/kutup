// frontend/src/components/editors/lang.ts
// Maps file extensions to CodeMirror 6 language extensions.
// Extensions not listed return null (plain-text mode).
import { type Extension } from '@codemirror/state'
import { markdown } from '@codemirror/lang-markdown'
import { javascript } from '@codemirror/lang-javascript'
import { python } from '@codemirror/lang-python'
import { rust } from '@codemirror/lang-rust'
import { go } from '@codemirror/lang-go'
import { json } from '@codemirror/lang-json'
import { yaml } from '@codemirror/lang-yaml'
import { html } from '@codemirror/lang-html'
import { css } from '@codemirror/lang-css'
import { sql } from '@codemirror/lang-sql'

export function langForExtension(ext: string): Extension | null {
  switch (ext.toLowerCase()) {
    case 'md':
    case 'markdown':
      return markdown()
    case 'js':
    case 'mjs':
    case 'cjs':
    case 'jsx':
      return javascript()
    case 'ts':
    case 'tsx':
      return javascript({ typescript: true, jsx: true })
    case 'py':
      return python()
    case 'rs':
      return rust()
    case 'go':
      return go()
    case 'json':
      return json()
    case 'yaml':
    case 'yml':
      return yaml()
    case 'html':
    case 'htm':
      return html()
    case 'css':
      return css()
    case 'sql':
      return sql()
    case 'txt':
    default:
      return null
  }
}
