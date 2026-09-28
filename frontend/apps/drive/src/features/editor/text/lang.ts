// frontend/src/components/editors/lang.ts
// Maps file extensions to CodeMirror 6 language extensions.
// Extensions not listed return null (plain-text mode).
import { type Extension } from '@codemirror/state'
import { Language, LanguageSupport, StreamLanguage } from '@codemirror/language'
import { markdown, markdownLanguage } from '@codemirror/lang-markdown'
import { javascript } from '@codemirror/lang-javascript'
import { python } from '@codemirror/lang-python'
import { rust } from '@codemirror/lang-rust'
import { go } from '@codemirror/lang-go'
import { json } from '@codemirror/lang-json'
import { yaml } from '@codemirror/lang-yaml'
import { html } from '@codemirror/lang-html'
import { css } from '@codemirror/lang-css'
import { sql } from '@codemirror/lang-sql'
import { cpp } from '@codemirror/lang-cpp'
import { java } from '@codemirror/lang-java'
import { php } from '@codemirror/lang-php'
import { xml } from '@codemirror/lang-xml'
import { shell } from '@codemirror/legacy-modes/mode/shell'
import { ruby } from '@codemirror/legacy-modes/mode/ruby'
import { toml } from '@codemirror/legacy-modes/mode/toml'
import { dockerFile } from '@codemirror/legacy-modes/mode/dockerfile'
import { perl } from '@codemirror/legacy-modes/mode/perl'
import { powerShell } from '@codemirror/legacy-modes/mode/powershell'
import { lua } from '@codemirror/legacy-modes/mode/lua'
import { swift } from '@codemirror/legacy-modes/mode/swift'

export function langForExtension(ext: string): Extension | null {
  switch (ext.toLowerCase()) {
    case 'md':
    case 'markdown':
      // GitHub-flavoured (tasks, strikethrough, tables), as the preview is;
      // fenced code blocks are highlighted in their language as you type.
      return markdown({ base: markdownLanguage, codeLanguages: languageForFence })
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
    case 'c':
    case 'h':
    case 'cpp':
    case 'cc':
    case 'cxx':
    case 'c++':
    case 'hpp':
    case 'hh':
    case 'hxx':
    case 'h++':
      return cpp()
    case 'java':
      return java()
    case 'php':
    case 'phtml':
      return php()
    case 'xml':
    case 'svg':
    case 'xsl':
    case 'xsd':
      return xml()
    case 'sh':
    case 'bash':
    case 'zsh':
    case 'fish':
      return StreamLanguage.define(shell)
    case 'rb':
    case 'rake':
    case 'gemspec':
      return StreamLanguage.define(ruby)
    case 'toml':
      return StreamLanguage.define(toml)
    case 'dockerfile':
    case 'containerfile':
      return StreamLanguage.define(dockerFile)
    case 'pl':
    case 'pm':
      return StreamLanguage.define(perl)
    case 'ps1':
    case 'psm1':
      return StreamLanguage.define(powerShell)
    case 'lua':
      return StreamLanguage.define(lua)
    case 'swift':
      return StreamLanguage.define(swift)
    case 'txt':
    default:
      return null
  }
}

/** Names a fence may give a language by, beyond the file extensions above. */
const FENCE_NAMES: Record<string, string> = {
  javascript: 'js',
  node: 'js',
  typescript: 'ts',
  python: 'py',
  python3: 'py',
  rust: 'rs',
  golang: 'go',
  jsonc: 'json',
  json5: 'json',
  shell: 'sh',
  console: 'sh',
  shellscript: 'sh',
  ruby: 'rb',
  docker: 'dockerfile',
  powershell: 'ps1',
  perl: 'pl',
  html5: 'html',
  postgres: 'sql',
  postgresql: 'sql',
  mysql: 'sql',
  sqlite: 'sql',
}

const fenceCache = new Map<string, Language | null>()

/**
 * The language of a fenced code block (```` ```python ````), by its info
 * string's first word, or null (plain). Markdown inside Markdown stays plain.
 */
export function languageForFence(info: string): Language | null {
  const word = info.trim().split(/\s+/)[0]?.toLowerCase() ?? ''
  const cached = fenceCache.get(word)
  if (cached !== undefined) return cached
  const ext = FENCE_NAMES[word] ?? word
  const support = ext === 'md' || ext === 'markdown' ? null : langForExtension(ext)
  const language = support instanceof LanguageSupport ? support.language : support instanceof Language ? support : null
  fenceCache.set(word, language)
  return language
}
