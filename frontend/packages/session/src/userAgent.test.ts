import { describe, expect, it } from 'vitest'
import { describeClientFamily, parseUserAgent } from './userAgent'
import vectors from './userAgent.vectors.json'

describe('parseUserAgent', () => {
  it('parses every shared vector as the server does', () => {
    for (const { ua, ...family } of vectors) {
      expect(parseUserAgent(ua), ua).toEqual(family)
    }
  })

  it('admits what it does not know', () => {
    expect(parseUserAgent(null)).toEqual({ browser: null, browserMajor: null, os: null })
  })
})

describe('describeClientFamily', () => {
  it('names the browser with its major version, and the system', () => {
    expect(describeClientFamily({ browser: 'Firefox', browserMajor: 128, os: 'Linux' })).toBe('Firefox 128 on Linux')
    expect(describeClientFamily({ browser: 'Kutup CLI', browserMajor: 0, os: null })).toBe('Kutup CLI')
    expect(describeClientFamily({ browser: null, browserMajor: null, os: 'macOS' })).toBe('macOS')
    expect(describeClientFamily({ browser: null, browserMajor: null, os: null })).toBeNull()
  })
})
