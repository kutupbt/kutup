import { describe, expect, it } from 'vitest'
import { languageForFence } from './lang'

describe('languageForFence', () => {
  it('finds a language by extension or by name', () => {
    expect(languageForFence('py')?.name).toBe('python')
    expect(languageForFence('python')?.name).toBe('python')
    expect(languageForFence('TypeScript')?.name).toBe('typescript')
    expect(languageForFence('rust')?.name).toBe('rust')
    expect(languageForFence('bash')?.name).toBe('shell')
  })

  it('reads only the first word of the info string', () => {
    expect(languageForFence('js title="app.js"')?.name).toBe('javascript')
  })

  it('leaves unknown languages, plain text and nested Markdown plain', () => {
    expect(languageForFence('')).toBeNull()
    expect(languageForFence('brainfuck')).toBeNull()
    expect(languageForFence('txt')).toBeNull()
    expect(languageForFence('markdown')).toBeNull()
  })
})
