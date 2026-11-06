import { describe, expect, it } from 'vitest'
import { describeUserAgent } from './userAgent'

describe('describeUserAgent', () => {
  it('names common browsers and systems', () => {
    expect(
      describeUserAgent('Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0'),
    ).toEqual({ browser: 'Firefox', os: 'Linux' })
    expect(
      describeUserAgent(
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36 Edg/140.0',
      ),
    ).toEqual({ browser: 'Edge', os: 'Windows' })
    expect(
      describeUserAgent(
        'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1',
      ),
    ).toEqual({ browser: 'Safari', os: 'iOS' })
  })

  it('admits what it does not know', () => {
    expect(describeUserAgent(null)).toEqual({ browser: null, os: null })
    expect(describeUserAgent('curl/8.0')).toEqual({ browser: null, os: null })
  })
})
