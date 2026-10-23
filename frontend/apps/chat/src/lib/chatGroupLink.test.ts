import { describe, expect, it } from 'vitest'
import { chatGroupLinkFragment, groupLinkFragmentFromUrl } from './chatGroupLink'

function fragment(bytes: number[]): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

describe('chatGroupLinkFragment', () => {
  const link = fragment([1, ...new Array<number>(88).fill(7), ...new TextEncoder().encode('home.example')])

  it('takes a pairwise link from a URL or as it is', () => {
    expect(chatGroupLinkFragment(`https://chat.home.example/join#${link}`)).toBe(link)
    expect(chatGroupLinkFragment(link)).toBe(link)
  })

  it('takes nothing else', () => {
    expect(chatGroupLinkFragment(fragment([2, ...new Array<number>(100).fill(7)]))).toBeNull()
    expect(chatGroupLinkFragment(fragment([1, 2, 3]))).toBeNull()
    expect(chatGroupLinkFragment('https://chat.home.example/join#not+a/link')).toBeNull()
  })

  it('reads a group link URL of any server, and nothing else', () => {
    expect(groupLinkFragmentFromUrl(`https://chat.a.test/join#${link}`)).toBe(link)
    expect(groupLinkFragmentFromUrl(` https://chat.b.test/join/#${link} `)).toBe(link)
    expect(groupLinkFragmentFromUrl(`https://chat.b.test/c/x#${link}`)).toBeNull()
    expect(groupLinkFragmentFromUrl('https://chat.b.test/join#short')).toBeNull()
    expect(groupLinkFragmentFromUrl(`javascript:alert(1)//join#${link}`)).toBeNull()
    expect(groupLinkFragmentFromUrl(link)).toBeNull()
  })
})
