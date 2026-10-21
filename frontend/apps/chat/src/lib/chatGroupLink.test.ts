import { describe, expect, it } from 'vitest'
import { chatGroupLinkFragment } from './chatGroupLink'

function fragment(bytes: number[]): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

describe('chatGroupLinkFragment', () => {
  const link = fragment([1, ...new Array<number>(88).fill(7), ...new TextEncoder().encode('home.example')])

  it('takes a pairwise link from a URL or as it is', () => {
    expect(chatGroupLinkFragment(`https://chat.home.example/join#${link}`)).toBe(link)
    expect(chatGroupLinkFragment(link)).toBe(link)
  })

  it('leaves anything else to the MLS links', () => {
    expect(chatGroupLinkFragment(fragment([2, ...new Array<number>(100).fill(7)]))).toBeNull()
    expect(chatGroupLinkFragment(fragment([1, 2, 3]))).toBeNull()
    expect(chatGroupLinkFragment('https://chat.home.example/join#not+a/link')).toBeNull()
  })
})
