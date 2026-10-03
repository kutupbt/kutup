// Colours for code on a thumbnail. A card shows code at a few pixels a
// letter, so a small tokenizer is enough (and keeps highlight.js out of the
// preview worker): comments, strings, numbers, keywords and function names,
// with the comment style picked by the fence's language.

export type TokenKind = 'plain' | 'comment' | 'string' | 'number' | 'keyword' | 'function'

export interface Token {
  text: string
  kind: TokenKind
}

/** Carried from line to line: inside a block comment. */
export interface TokenState {
  inBlockComment: boolean
}

const HASH_COMMENTS = new Set([
  'py', 'python', 'python3', 'sh', 'bash', 'zsh', 'fish', 'shell', 'console', 'rb', 'ruby',
  'yaml', 'yml', 'toml', 'pl', 'perl', 'r', 'dockerfile', 'docker', 'ps1', 'powershell', 'make', 'makefile', 'nix',
])
const DASH_COMMENTS = new Set(['sql', 'postgres', 'postgresql', 'mysql', 'sqlite', 'lua', 'haskell', 'hs'])

const KEYWORDS = new Set([
  // Shared by many languages.
  'if', 'else', 'for', 'while', 'do', 'return', 'break', 'continue', 'switch', 'case', 'default',
  'try', 'catch', 'finally', 'throw', 'new', 'class', 'import', 'export', 'from', 'as', 'in', 'of',
  'true', 'false', 'null', 'void', 'this', 'self', 'super', 'static', 'public', 'private', 'protected',
  'async', 'await', 'yield', 'extends', 'implements', 'interface', 'enum', 'struct', 'type', 'const',
  // JavaScript / TypeScript.
  'function', 'let', 'var', 'typeof', 'instanceof', 'undefined', 'delete',
  // Python.
  'def', 'elif', 'except', 'raise', 'with', 'lambda', 'pass', 'not', 'and', 'or', 'is', 'global',
  'nonlocal', 'None', 'True', 'False',
  // Rust / Go / Swift / Kotlin.
  'fn', 'let', 'mut', 'pub', 'use', 'mod', 'impl', 'match', 'loop', 'where', 'trait', 'crate', 'move',
  'func', 'package', 'go', 'defer', 'select', 'chan', 'map', 'range', 'var', 'val', 'fun', 'guard', 'nil',
  // C family.
  'int', 'long', 'short', 'char', 'float', 'double', 'bool', 'unsigned', 'signed', 'sizeof', 'typedef',
  'namespace', 'template', 'virtual', 'override', 'final', 'abstract', 'string',
  // Shell.
  'then', 'fi', 'done', 'esac', 'echo', 'local', 'export', 'function',
  // SQL (as written, usually upper case).
  'SELECT', 'FROM', 'WHERE', 'INSERT', 'INTO', 'UPDATE', 'DELETE', 'CREATE', 'TABLE', 'JOIN', 'ON',
  'AND', 'OR', 'NOT', 'NULL', 'ORDER', 'BY', 'GROUP', 'LIMIT', 'VALUES', 'SET', 'AS', 'LEFT', 'INNER',
  'select', 'where', 'insert', 'into', 'update', 'create', 'table', 'join', 'order', 'by', 'group', 'limit', 'values',
])

interface CommentStyle {
  line: string[]
  block: boolean
}

function commentStyle(language: string | undefined): CommentStyle {
  const lang = (language ?? '').toLowerCase()
  if (HASH_COMMENTS.has(lang)) return { line: ['#'], block: false }
  if (DASH_COMMENTS.has(lang)) return { line: ['--'], block: lang !== 'lua' && lang !== 'haskell' && lang !== 'hs' }
  // Unknown or none: both common line styles.
  if (!lang) return { line: ['//', '#'], block: true }
  return { line: ['//'], block: true }
}

const IDENT_START = /[A-Za-z_$]/
const IDENT = /[\w$]/

/** One line's tokens; `state` carries a block comment into the next line. */
export function tokenizeLine(line: string, language: string | undefined, state: TokenState): Token[] {
  const style = commentStyle(language)
  const tokens: Token[] = []
  const push = (text: string, kind: TokenKind) => {
    if (!text) return
    const last = tokens[tokens.length - 1]
    if (last && last.kind === kind) last.text += text
    else tokens.push({ text, kind })
  }
  let i = 0
  while (i < line.length) {
    if (state.inBlockComment) {
      const end = line.indexOf('*/', i)
      if (end < 0) {
        push(line.slice(i), 'comment')
        return tokens
      }
      push(line.slice(i, end + 2), 'comment')
      state.inBlockComment = false
      i = end + 2
      continue
    }
    const rest = line.slice(i)
    if (style.line.some((m) => rest.startsWith(m))) {
      push(rest, 'comment')
      return tokens
    }
    if (style.block && rest.startsWith('/*')) {
      state.inBlockComment = true
      push('/*', 'comment')
      i += 2
      continue
    }
    const ch = line[i]!
    if (ch === '"' || ch === "'" || ch === '`') {
      let j = i + 1
      while (j < line.length && line[j] !== ch) j += line[j] === '\\' ? 2 : 1
      push(line.slice(i, Math.min(j + 1, line.length)), 'string')
      i = j + 1
      continue
    }
    if (/[0-9]/.test(ch) && !(i > 0 && IDENT.test(line[i - 1]!))) {
      const m = /^[0-9][0-9a-fA-FxXoObB._]*/.exec(rest)!
      push(m[0], 'number')
      i += m[0].length
      continue
    }
    if (IDENT_START.test(ch)) {
      let j = i + 1
      while (j < line.length && IDENT.test(line[j]!)) j++
      const word = line.slice(i, j)
      const next = /^\s*\(/.test(line.slice(j))
      push(word, KEYWORDS.has(word) ? 'keyword' : next ? 'function' : 'plain')
      i = j
      continue
    }
    push(ch, 'plain')
    i++
  }
  return tokens
}

/** The first `length` characters of a tokenized line (a card cuts long lines). */
export function cutTokens(tokens: Token[], length: number): Token[] {
  const out: Token[] = []
  let left = length
  for (const token of tokens) {
    if (left <= 0) break
    const text = token.text.slice(0, left)
    out.push({ text, kind: token.kind })
    left -= text.length
  }
  return out
}
