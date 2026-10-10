import { describe, expect, it } from 'vitest'
import { LanguageSupport } from '@codemirror/language'
import { languageForFence, loadLanguage } from './lang'

async function fenceLanguage(info: string): Promise<string | null> {
  const description = languageForFence(info)
  return description ? (await description.load()).language.name : null
}

describe('languageForFence', () => {
  it('finds a language by extension or by name', async () => {
    expect(await fenceLanguage('py')).toBe('python')
    expect(await fenceLanguage('python')).toBe('python')
    expect(await fenceLanguage('TypeScript')).toBe('typescript')
    expect(await fenceLanguage('rust')).toBe('rust')
    expect(await fenceLanguage('bash')).toBe('shell')
    expect(await fenceLanguage('postgres')).toBe('sql')
  })

  it('reads only the first word of the info string', async () => {
    expect(await fenceLanguage('js title="app.js"')).toBe('javascript')
  })

  it('leaves unknown languages, plain text and nested Markdown plain', () => {
    expect(languageForFence('')).toBeNull()
    expect(languageForFence('brainfuck')).toBeNull()
    expect(languageForFence('txt')).toBeNull()
    expect(languageForFence('markdown')).toBeNull()
  })
})

describe('loadLanguage', () => {
  it('loads a file language by its extension, and none for plain text', async () => {
    expect(((await loadLanguage('RS')) as LanguageSupport).language.name).toBe('rust')
    expect(((await loadLanguage('sh')) as LanguageSupport).language.name).toBe('shell')
    expect(await loadLanguage('txt')).toBeNull()
    expect(await loadLanguage('md')).not.toBeNull()
  })
})
