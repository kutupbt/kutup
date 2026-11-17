import { describe, expect, it } from 'vitest'
import { emlName } from './mailExport'

describe('export file names', () => {
  it('names a message by when it came and its subject, safe and unique', () => {
    const taken = new Set<string>()
    expect(emlName({ receivedAt: '2026-11-06T14:05:09Z', subject: 'Re: a/b: "plan"?' }, taken)).toBe('2026-11-06 14-05 Re_ a_b_ _plan__.eml')
    expect(emlName({ receivedAt: '2026-11-06T14:05:09Z', subject: 'Re: a/b: "plan"?' }, taken)).toBe('2026-11-06 14-05 Re_ a_b_ _plan__ (2).eml')
    expect(emlName({ receivedAt: '2026-11-06T14:05:09Z', subject: '' }, taken)).toBe('2026-11-06 14-05 no subject.eml')
    expect(emlName({ receivedAt: '2026-11-06T14:05:09Z', subject: 'x'.repeat(200) }, taken)).toHaveLength('2026-11-06 14-05 '.length + 80 + '.eml'.length)
  })
})
