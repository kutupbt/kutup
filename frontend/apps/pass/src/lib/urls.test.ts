import { describe, expect, it } from 'vitest'
import { isAdditionalUrl, openableUrl } from './urls'

describe('extra URLs', () => {
  it('names the KP2A_URL fields', () => {
    expect(isAdditionalUrl('KP2A_URL')).toBe(true)
    expect(isAdditionalUrl('KP2A_URL_3')).toBe(true)
    expect(isAdditionalUrl('kp2a_url_1')).toBe(false)
    expect(isAdditionalUrl('URL')).toBe(false)
  })

  it('opens only http and https', () => {
    expect(openableUrl(' https://bank.example/login ')).toBe('https://bank.example/login')
    expect(openableUrl('HTTP://x.example')).toBe('HTTP://x.example')
    expect(openableUrl('javascript:alert(1)')).toBeNull()
    expect(openableUrl('data:text/html,<b>x</b>')).toBeNull()
    expect(openableUrl('bank.example')).toBeNull()
    expect(openableUrl('https://a b')).toBeNull()
  })
})
