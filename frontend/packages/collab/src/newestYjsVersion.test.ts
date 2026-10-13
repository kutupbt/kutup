import { describe, expect, it } from 'vitest'
import { newestYjsVersion, type VersionRow } from './api'

const row = (id: string, kind: 'file' | 'yjs') => ({ id, kind }) as VersionRow

describe('the version a note or list opens from', () => {
  it('is the newest Yjs state, past any whole-file version', () => {
    expect(newestYjsVersion([row('f2', 'file'), row('y1', 'yjs'), row('y0', 'yjs')])?.id).toBe('y1')
  })

  it('is none when only whole-file versions exist (the original upload then)', () => {
    expect(newestYjsVersion([row('f1', 'file'), row('f0', 'file')])).toBeUndefined()
    expect(newestYjsVersion([])).toBeUndefined()
  })
})
