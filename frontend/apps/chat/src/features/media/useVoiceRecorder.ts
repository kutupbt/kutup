import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import {
  VOICE_NOTE_MAX_DURATION_MS,
  VOICE_NOTE_MAX_PLAINTEXT_BYTES,
  canonicalVoiceNoteMimeType,
  preferredVoiceNoteMimeType,
  voiceNoteFilename,
} from '@kutup/chat-core/voice-note'
import { formatBytes } from '@kutup/ui/lib/format'

export type VoiceState = 'idle' | 'starting' | 'recording' | 'sending'

interface Session {
  recorder: MediaRecorder
  stream: MediaStream
  chunks: Blob[]
  bytes: number
  startedAt: number
  discard: boolean
}

/**
 * Record a voice note with the microphone and hand the finished file over.
 * The recording stops at ten minutes or the size limit; leaving (unmount,
 * another conversation) throws it away and releases the microphone.
 */
export function useVoiceRecorder({
  maxBytes,
  onRecorded,
}: {
  /** The server's attachment limit. */
  maxBytes: number
  onRecorded: (file: File, durationMs: number) => Promise<void>
}) {
  const { t, i18n } = useTranslation()
  const [state, setState] = useState<VoiceState>('idle')
  const [elapsedMs, setElapsedMs] = useState(0)
  const session = useRef<Session | null>(null)
  const ticker = useRef<number | null>(null)
  const mounted = useRef(true)
  const deliver = useRef(onRecorded)
  deliver.current = onRecorded

  const release = useCallback((current: Session) => {
    current.stream.getTracks().forEach((track) => track.stop())
    if (session.current === current) session.current = null
    if (ticker.current !== null) {
      window.clearInterval(ticker.current)
      ticker.current = null
    }
    if (mounted.current) setElapsedMs(0)
  }, [])

  const stop = useCallback(
    (discard: boolean) => {
      const current = session.current
      if (!current) return
      current.discard = discard
      if (!discard && mounted.current) setState('sending')
      if (current.recorder.state !== 'inactive') current.recorder.stop()
      else {
        release(current)
        if (mounted.current) setState('idle')
      }
    },
    [release],
  )

  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
      const current = session.current
      if (current) {
        current.discard = true
        if (current.recorder.state !== 'inactive') current.recorder.stop()
        current.stream.getTracks().forEach((track) => track.stop())
        session.current = null
      }
      if (ticker.current !== null) window.clearInterval(ticker.current)
    }
  }, [])

  const start = useCallback(async () => {
    if (state !== 'idle') return
    if (typeof MediaRecorder === 'undefined' || !navigator.mediaDevices?.getUserMedia) {
      toast.error(t('chat.voice.unsupported'))
      return
    }
    setState('starting')
    let stream: MediaStream | null = null
    try {
      stream = await navigator.mediaDevices.getUserMedia({
        audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
        video: false,
      })
      if (!mounted.current) {
        stream.getTracks().forEach((track) => track.stop())
        return
      }
      const preferred = preferredVoiceNoteMimeType((type) => MediaRecorder.isTypeSupported(type))
      const recorder = new MediaRecorder(stream, preferred ? { mimeType: preferred } : undefined)
      const limit = Math.min(maxBytes, VOICE_NOTE_MAX_PLAINTEXT_BYTES)
      const current: Session = { recorder, stream, chunks: [], bytes: 0, startedAt: Date.now(), discard: false }
      session.current = current
      recorder.ondataavailable = (event) => {
        if (event.data.size === 0 || current.discard) return
        current.bytes += event.data.size
        if (current.bytes > limit) {
          current.discard = true
          toast.error(t('chat.voice.tooLarge', { limit: formatBytes(limit, i18n.language) }))
          if (recorder.state !== 'inactive') recorder.stop()
          return
        }
        current.chunks.push(event.data)
      }
      recorder.onerror = () => {
        current.discard = true
        toast.error(t('chat.voice.failed'))
        if (recorder.state !== 'inactive') recorder.stop()
      }
      recorder.onstop = () => {
        const durationMs = Math.max(1, Date.now() - current.startedAt)
        release(current)
        if (current.discard) {
          if (mounted.current) setState('idle')
          return
        }
        const type = canonicalVoiceNoteMimeType(
          recorder.mimeType || preferred || current.chunks.find((chunk) => chunk.type)?.type || 'audio/webm',
        )
        const file = new File(current.chunks, voiceNoteFilename(type), { type })
        if (file.size === 0) {
          if (mounted.current) {
            setState('idle')
            toast.error(t('chat.voice.empty'))
          }
          return
        }
        void deliver
          .current(file, durationMs)
          .catch(() => undefined)
          .finally(() => {
            if (mounted.current) setState('idle')
          })
      }
      recorder.start(1_000)
      setElapsedMs(0)
      setState('recording')
      ticker.current = window.setInterval(() => {
        const elapsed = Date.now() - current.startedAt
        setElapsedMs(Math.min(elapsed, VOICE_NOTE_MAX_DURATION_MS))
        if (elapsed >= VOICE_NOTE_MAX_DURATION_MS && recorder.state !== 'inactive') {
          toast.info(t('chat.voice.maximumReached'))
          stop(false)
        }
      }, 250)
    } catch {
      stream?.getTracks().forEach((track) => track.stop())
      if (mounted.current) {
        setState('idle')
        toast.error(t('chat.voice.permissionFailed'))
      }
    }
  }, [state, maxBytes, release, stop, t, i18n.language])

  return { state, elapsedMs, start, stop: () => stop(false), cancel: () => stop(true) }
}
