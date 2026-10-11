// Maps file extensions and code-fence names to CodeMirror 6 languages.
// Markdown (what notes are) is bundled; every other language is its own
// chunk, loaded when a file or a fenced code block needs it
// (docs/research/18-web-performance.md). Anything not listed is plain text.
import { type Extension } from '@codemirror/state'
import { LanguageDescription, LanguageSupport, StreamLanguage, type StreamParser } from '@codemirror/language'
import { markdown, markdownLanguage } from '@codemirror/lang-markdown'

/** A language from a legacy (stream) mode. */
function legacy<T>(load: () => Promise<StreamParser<T>>): () => Promise<LanguageSupport> {
  return async () => new LanguageSupport(StreamLanguage.define(await load()))
}

/** Every language beside Markdown, by file extension and by name. */
export const LANGUAGES: readonly LanguageDescription[] = [
  LanguageDescription.of({
    name: 'javascript',
    alias: ['js', 'node'],
    extensions: ['js', 'mjs', 'cjs', 'jsx'],
    load: () => import('@codemirror/lang-javascript').then((m) => m.javascript()),
  }),
  LanguageDescription.of({
    name: 'typescript',
    alias: ['ts'],
    extensions: ['ts', 'tsx'],
    load: () => import('@codemirror/lang-javascript').then((m) => m.javascript({ typescript: true, jsx: true })),
  }),
  LanguageDescription.of({
    name: 'python',
    alias: ['py', 'python3'],
    extensions: ['py'],
    load: () => import('@codemirror/lang-python').then((m) => m.python()),
  }),
  LanguageDescription.of({
    name: 'rust',
    alias: ['rs'],
    extensions: ['rs'],
    load: () => import('@codemirror/lang-rust').then((m) => m.rust()),
  }),
  LanguageDescription.of({
    name: 'go',
    alias: ['golang'],
    extensions: ['go'],
    load: () => import('@codemirror/lang-go').then((m) => m.go()),
  }),
  LanguageDescription.of({
    name: 'json',
    alias: ['jsonc', 'json5'],
    extensions: ['json'],
    load: () => import('@codemirror/lang-json').then((m) => m.json()),
  }),
  LanguageDescription.of({
    name: 'yaml',
    alias: ['yml'],
    extensions: ['yaml', 'yml'],
    load: () => import('@codemirror/lang-yaml').then((m) => m.yaml()),
  }),
  LanguageDescription.of({
    name: 'html',
    alias: ['htm', 'html5'],
    extensions: ['html', 'htm'],
    load: () => import('@codemirror/lang-html').then((m) => m.html()),
  }),
  LanguageDescription.of({
    name: 'css',
    extensions: ['css'],
    load: () => import('@codemirror/lang-css').then((m) => m.css()),
  }),
  LanguageDescription.of({
    name: 'sql',
    alias: ['postgres', 'postgresql', 'mysql', 'sqlite'],
    extensions: ['sql'],
    load: () => import('@codemirror/lang-sql').then((m) => m.sql()),
  }),
  LanguageDescription.of({
    name: 'cpp',
    alias: ['c', 'c++'],
    extensions: ['c', 'h', 'cpp', 'cc', 'cxx', 'c++', 'hpp', 'hh', 'hxx', 'h++'],
    load: () => import('@codemirror/lang-cpp').then((m) => m.cpp()),
  }),
  LanguageDescription.of({
    name: 'java',
    extensions: ['java'],
    load: () => import('@codemirror/lang-java').then((m) => m.java()),
  }),
  LanguageDescription.of({
    name: 'php',
    extensions: ['php', 'phtml'],
    load: () => import('@codemirror/lang-php').then((m) => m.php()),
  }),
  LanguageDescription.of({
    name: 'xml',
    extensions: ['xml', 'svg', 'xsl', 'xsd'],
    load: () => import('@codemirror/lang-xml').then((m) => m.xml()),
  }),
  LanguageDescription.of({
    name: 'shell',
    alias: ['sh', 'bash', 'zsh', 'fish', 'console', 'shellscript'],
    extensions: ['sh', 'bash', 'zsh', 'fish'],
    load: legacy(() => import('@codemirror/legacy-modes/mode/shell').then((m) => m.shell)),
  }),
  LanguageDescription.of({
    name: 'ruby',
    alias: ['rb'],
    extensions: ['rb', 'rake', 'gemspec'],
    load: legacy(() => import('@codemirror/legacy-modes/mode/ruby').then((m) => m.ruby)),
  }),
  LanguageDescription.of({
    name: 'toml',
    extensions: ['toml'],
    load: legacy(() => import('@codemirror/legacy-modes/mode/toml').then((m) => m.toml)),
  }),
  LanguageDescription.of({
    name: 'dockerfile',
    alias: ['docker', 'containerfile'],
    extensions: ['dockerfile', 'containerfile'],
    load: legacy(() => import('@codemirror/legacy-modes/mode/dockerfile').then((m) => m.dockerFile)),
  }),
  LanguageDescription.of({
    name: 'perl',
    alias: ['pl'],
    extensions: ['pl', 'pm'],
    load: legacy(() => import('@codemirror/legacy-modes/mode/perl').then((m) => m.perl)),
  }),
  LanguageDescription.of({
    name: 'powershell',
    alias: ['ps1'],
    extensions: ['ps1', 'psm1'],
    load: legacy(() => import('@codemirror/legacy-modes/mode/powershell').then((m) => m.powerShell)),
  }),
  LanguageDescription.of({
    name: 'lua',
    extensions: ['lua'],
    load: legacy(() => import('@codemirror/legacy-modes/mode/lua').then((m) => m.lua)),
  }),
  LanguageDescription.of({
    name: 'swift',
    extensions: ['swift'],
    load: legacy(() => import('@codemirror/legacy-modes/mode/swift').then((m) => m.swift)),
  }),
]

function byExtension(ext: string): LanguageDescription | null {
  const lower = ext.toLowerCase()
  return LANGUAGES.find((d) => d.extensions.includes(lower)) ?? null
}

/**
 * The language of a fenced code block (```` ```python ````), by its info
 * string's first word (a name or an extension), or null (plain). Markdown
 * inside Markdown stays plain. CodeMirror loads it when the block shows.
 */
export function languageForFence(info: string): LanguageDescription | null {
  const word = info.trim().split(/\s+/)[0]?.toLowerCase() ?? ''
  if (!word || word === 'md' || word === 'markdown') return null
  return LanguageDescription.matchLanguageName(LANGUAGES, word, false) ?? byExtension(word)
}

/** The editor language for a file with extension `ext`, loaded; null for plain text. */
export async function loadLanguage(ext: string): Promise<Extension | null> {
  const lower = ext.toLowerCase()
  if (lower === 'md' || lower === 'markdown') {
    // GitHub-flavoured (tasks, strikethrough, tables), as the preview is;
    // fenced code blocks are highlighted in their language as you type.
    return markdown({ base: markdownLanguage, codeLanguages: languageForFence })
  }
  const description = byExtension(lower)
  return description ? description.load() : null
}
