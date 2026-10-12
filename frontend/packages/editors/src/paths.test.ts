import { describe, expect, it } from 'vitest'
import { appFor, filePath, openedFrom } from './paths'

describe('appFor', () => {
  it('opens what is edited in Office', () => {
    for (const name of ['Notes.md', 'todo.txt', 'main.rs', 'Dockerfile', 'Report.docx', 'Budget.XLSX', 'Deck.pptx', 'Scan.pdf', 'Plan.excalidraw']) {
      expect(appFor(name), name).toBe('office')
    }
  })

  it('opens photos, videos, audio and other files in Drive', () => {
    for (const name of ['photo.jpg', 'logo.svg', 'clip.mp4', 'song.mp3', 'archive.zip', 'Report.doc', 'no-extension']) {
      expect(appFor(name), name).toBe('drive')
    }
    expect(appFor(null)).toBe('drive')
  })

  it('opens a place list in Maps', () => {
    expect(appFor('Trip.kutupmap')).toBe('maps')
  })

  it('opens a KeePass vault in Pass, unless it is on another server', () => {
    expect(appFor('Passwords.kdbx')).toBe('pass')
    expect(appFor('Team.KDBX', { source: 'shared' })).toBe('pass')
    expect(appFor('Passwords.kdbx', { source: 'remote', remoteShareId: 's1' })).toBe('drive')
    expect(appFor('Passwords.kdbx', { source: 'file', remoteFileShareId: 's2' })).toBe('drive')
    expect(appFor('.kdbx')).toBe('drive')
  })
})

describe('filePath', () => {
  it('is the same path in either app', () => {
    expect(filePath({ id: 'c1', source: 'owned' }, 'f1')).toBe('/file/c1/f1')
    expect(filePath({ id: 'c1', source: 'file' }, 'f1')).toBe('/shared/file/f1')
  })
})

describe('openedFrom', () => {
  it('knows only Drive and Office', () => {
    expect(openedFrom('drive')).toBe('drive')
    expect(openedFrom('office')).toBe('office')
    expect(openedFrom('https://evil.example')).toBeNull()
    expect(openedFrom(null)).toBeNull()
  })
})
