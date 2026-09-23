import { describe, expect, it, vi } from 'vitest'
import {
  canonicalVoiceNoteMimeType,
  formatVoiceNoteElapsed,
  preferredVoiceNoteMimeType,
  voiceNoteExtension,
  voiceNoteFilename,
} from './voice-note'

describe('voice-note browser helpers', () => {
  it('selects the first supported recording format and allows browser defaults', () => {
    const supported = vi.fn((mimeType: string) => mimeType === 'audio/ogg;codecs=opus')
    expect(preferredVoiceNoteMimeType(supported)).toBe('audio/ogg;codecs=opus')
    expect(supported).toHaveBeenCalledWith('audio/webm;codecs=opus')
    expect(preferredVoiceNoteMimeType(() => false)).toBeUndefined()
  })

  it('uses stable extensions for codec-qualified MIME values', () => {
    expect(canonicalVoiceNoteMimeType('Audio/WebM;codecs=opus')).toBe('audio/webm')
    expect(canonicalVoiceNoteMimeType('not a mime')).toBe('audio/webm')
    expect(voiceNoteExtension('audio/webm;codecs=opus')).toBe('webm')
    expect(voiceNoteExtension('audio/ogg; codecs=opus')).toBe('ogg')
    expect(voiceNoteExtension('audio/mp4')).toBe('m4a')
    expect(voiceNoteFilename('audio/mp4', 1234)).toBe('voice-note-1234.m4a')
  })

  it('formats a monotonic recording duration', () => {
    expect(formatVoiceNoteElapsed(-1)).toBe('0:00')
    expect(formatVoiceNoteElapsed(61_999)).toBe('1:01')
  })
})
