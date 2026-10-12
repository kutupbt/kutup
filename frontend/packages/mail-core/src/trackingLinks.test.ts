import { describe, expect, it } from 'vitest'
import { cleanTrackingLink } from './trackingLinks'

describe('cleanTrackingLink', () => {
  it('takes out campaign tags and click identifiers, and keeps the rest', () => {
    const cleaned = cleanTrackingLink('https://shop.example/item?id=7&utm_source=news&utm_medium=email&fbclid=abc#top')
    expect(cleaned?.cleaned).toBe('https://shop.example/item?id=7#top')
    expect(cleaned?.removed).toEqual(['utm_source', 'utm_medium', 'fbclid'])
  })

  it('leaves the query out when nothing stays', () => {
    expect(cleanTrackingLink('http://example.org/a?UTM_Campaign=x&mc_eid=1')?.cleaned).toBe('http://example.org/a')
  })

  it('keeps encoded parameters as they were', () => {
    expect(cleanTrackingLink('https://example.org/s?q=a%20b&next=%2Fx&gclid=1')?.cleaned).toBe('https://example.org/s?q=a%20b&next=%2Fx')
  })

  it('leaves clean links, other schemes and broken links alone', () => {
    expect(cleanTrackingLink('https://example.org/a?id=1')).toBeNull()
    expect(cleanTrackingLink('mailto:a@example.org?utm_source=x')).toBeNull()
    expect(cleanTrackingLink('not a link')).toBeNull()
  })
})
