// frontend/src/components/editors/lang.ts
// Maps file extensions to CodeMirror 6 language extensions.
// Extensions not listed return null (plain-text mode).
import { type Extension } from '@codemirror/state'
import { StreamLanguage } from '@codemirror/language'
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
