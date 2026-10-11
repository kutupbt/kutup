import { describe, expect, it } from 'vitest'
import { unsubscribeMethods } from './unsubscribe'

const raw = (headers: string) => new TextEncoder().encode(`From: n@l.example\r\n${headers}\r\n\r\nbody`)

describe('unsubscribe methods', () => {
  it('read one click, a web page and an email', () => {
    expect(
      unsubscribeMethods(raw('List-Unsubscribe: <https://l.example/u?id=1>,\r\n <mailto:leave@l.example?subject=stop%20me>\r\nList-Unsubscribe-Post: List-Unsubscribe=One-Click')),
    ).toEqual({
      oneClick: 'https://l.example/u?id=1',
      http: 'https://l.example/u?id=1',
      mailto: { to: 'leave@l.example', subject: 'stop me', body: 'Please, unsubscribe me' },
    })
  })

  it('offer no one click without List-Unsubscribe-Post, nor http links', () => {
    expect(unsubscribeMethods(raw('List-Unsubscribe: <https://l.example/u>'))).toEqual({ http: 'https://l.example/u' })
    expect(unsubscribeMethods(raw('List-Unsubscribe: <http://l.example/u>'))).toBeNull()
    expect(unsubscribeMethods(raw('Subject: hi'))).toBeNull()
  })
})
