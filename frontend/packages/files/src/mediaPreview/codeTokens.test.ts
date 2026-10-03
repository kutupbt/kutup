import { describe, expect, it } from 'vitest'
import { cutTokens, tokenizeLine, type Token } from './codeTokens'

const kinds = (tokens: Token[]) => tokens.filter((t) => t.text.trim()).map((t) => [t.text.trim(), t.kind])
const fresh = () => ({ inBlockComment: false })

describe('tokenizeLine', () => {
  it('colours Python keywords, functions, strings, numbers and # comments', () => {
    expect(kinds(tokenizeLine('def greet(name): return f"hi" * 2  # say', 'python', fresh()))).toEqual([
      ['def', 'keyword'], ['greet', 'function'], ['(name):', 'plain'], ['return', 'keyword'],
      ['f', 'plain'], ['"hi"', 'string'], ['*', 'plain'], ['2', 'number'], ['# say', 'comment'],
    ])
  })

  it('uses // and block comments in C-like languages, across lines', () => {
    const state = fresh()
    expect(kinds(tokenizeLine('const x = 1 // one', 'ts', state))).toEqual([['const', 'keyword'], ['x =', 'plain'], ['1', 'number'], ['// one', 'comment']])
    expect(kinds(tokenizeLine('/* start', 'js', state))).toEqual([['/* start', 'comment']])
    expect(state.inBlockComment).toBe(true)
    expect(kinds(tokenizeLine('end */ let y', 'js', state))).toEqual([['end */', 'comment'], ['let', 'keyword'], ['y', 'plain']])
    expect(state.inBlockComment).toBe(false)
  })

  it('reads # as code in C-like languages and -- as a comment in SQL', () => {
    expect(tokenizeLine('#include <x>', 'c', fresh())[0]!.kind).not.toBe('comment')
    expect(kinds(tokenizeLine("SELECT 'a' -- note", 'sql', fresh()))).toEqual([['SELECT', 'keyword'], ["'a'", 'string'], ['-- note', 'comment']])
  })

  it('keeps escaped quotes inside strings and numbers inside names plain', () => {
    expect(kinds(tokenizeLine('"a\\"b" x2', 'js', fresh()))).toEqual([['"a\\"b"', 'string'], ['x2', 'plain']])
  })

  it('handles an unterminated string to the end of the line', () => {
    expect(kinds(tokenizeLine('"open', 'py', fresh()))).toEqual([['"open', 'string']])
  })
})

describe('cutTokens', () => {
  it('keeps the first characters, token by token', () => {
    const cut = cutTokens([{ text: 'def', kind: 'keyword' }, { text: ' greet', kind: 'function' }], 5)
    expect(cut).toEqual([{ text: 'def', kind: 'keyword' }, { text: ' g', kind: 'function' }])
  })
})
