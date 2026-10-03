export const VOICE_NOTE_MAX_DURATION_MS = 10 * 60 * 1_000
export const VOICE_NOTE_MAX_PLAINTEXT_BYTES = 64 * 1024 * 1024

const MIME_PREFERENCES = [
  'audio/webm;codecs=opus',
  'audio/ogg;codecs=opus',
  'audio/mp4',
] as const

export function preferredVoiceNoteMimeType(
  isTypeSupported: (mimeType: string) => boolean,
): string | undefined {
  return MIME_PREFERENCES.find(mimeType => isTypeSupported(mimeType))
}

export function voiceNoteExtension(mimeType: string): string {
  switch (canonicalVoiceNoteMimeType(mimeType)) {
    case 'audio/ogg':
      return 'ogg'
    case 'audio/mp4':
      return 'm4a'
    case 'audio/mpeg':
      return 'mp3'
    case 'audio/wav':
      return 'wav'
    default:
      return 'webm'
  }
}

export function canonicalVoiceNoteMimeType(mimeType: string): string {
  const baseType = mimeType.split(';', 1)[0].trim().toLowerCase()
  return /^audio\/[a-z0-9.+-]+$/.test(baseType) ? baseType : 'audio/webm'
}

export function voiceNoteFilename(mimeType: string, createdAt = Date.now()): string {
  return `voice-note-${createdAt}.${voiceNoteExtension(mimeType)}`
}

export function formatVoiceNoteElapsed(durationMs: number): string {
  const totalSeconds = Math.max(0, Math.floor(durationMs / 1_000))
  const minutes = Math.floor(totalSeconds / 60)
  const seconds = totalSeconds % 60
  return `${minutes}:${seconds.toString().padStart(2, '0')}`
}
