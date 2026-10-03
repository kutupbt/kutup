import { useEffect, useRef, useState } from 'react'
import { Download, Loader2, Pause, Play, X } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Button } from '@kutup/ui/components/button'
import { cn } from '@kutup/ui/lib/cn'
import type { PrivateCiphertextCacheV1 } from '@kutup/files/mediaCache'
import { openCachedChatMediaV1 } from '@kutup/chat-core/media'
import type { ChatAttachmentDescriptorV1 } from '@kutup/chat-core/types'
import { formatVoiceNoteElapsed } from '@kutup/chat-core/voice-note'
import { ChatAttachmentPreview } from './ChatAttachmentPreview'

const PLAYBACK_RATES = [1, 1.25, 1.5, 2] as const
const PROGRESS_RING_RADIUS = 19
const PROGRESS_RING_LENGTH = 2 * Math.PI * PROGRESS_RING_RADIUS

export type VoiceNoteDownloadState = 'checking' | 'remote' | 'downloading' | 'available'

export function ChatVoiceNotePlayer({
  cache,
  attachment,
  downloadState,
  downloadProgress,
  disabled = false,
  onDownload,
  onCancel,
  onError,
  className,
}: {
  cache: PrivateCiphertextCacheV1
  attachment: ChatAttachmentDescriptorV1
  downloadState: VoiceNoteDownloadState
  downloadProgress: number
  disabled?: boolean
  onDownload: () => Promise<void>
  onCancel: () => void
  onError: () => void
  className?: string
}) {
  const { t } = useTranslation()
  const filename = attachment.filename
  const audioRef = useRef<HTMLAudioElement | null>(null)
  const pendingPositionRef = useRef<number | null>(null)
  const wasAvailableRef = useRef(downloadState === 'available')
  const [sourceUrl, setSourceUrl] = useState<string | null>(null)
  const [opening, setOpening] = useState(false)
  const [playing, setPlaying] = useState(false)
  const [currentTimeMs, setCurrentTimeMs] = useState(0)
  const [decodedDurationMs, setDecodedDurationMs] = useState(attachment.durationMs ?? 0)
  const [playbackRateIndex, setPlaybackRateIndex] = useState(0)
  const playbackRate = PLAYBACK_RATES[playbackRateIndex]
  const durationMs = decodedDurationMs || attachment.durationMs || 0
  const playbackProgress = durationMs > 0 ? Math.min(1, currentTimeMs / durationMs) : 0

  useEffect(
    () => () => {
      if (sourceUrl) URL.revokeObjectURL(sourceUrl)
    },
    [sourceUrl],
  )

  useEffect(() => {
    setSourceUrl(null)
    setOpening(false)
    setPlaying(false)
    setCurrentTimeMs(0)
    setDecodedDurationMs(attachment.durationMs ?? 0)
    setPlaybackRateIndex(0)
    pendingPositionRef.current = null
  }, [attachment.attachmentId, attachment.durationMs])

  useEffect(() => {
    if (downloadState === 'available') {
      wasAvailableRef.current = true
      return
    }
    if (!wasAvailableRef.current || !sourceUrl) return
    wasAvailableRef.current = false
    audioRef.current?.pause()
    setSourceUrl(null)
    setPlaying(false)
    setCurrentTimeMs(0)
    pendingPositionRef.current = null
  }, [downloadState, sourceUrl])

  const openAndPlay = async (position = playbackProgress) => {
    if (sourceUrl && audioRef.current) {
      if (Number.isFinite(audioRef.current.duration)) {
        audioRef.current.currentTime = position * audioRef.current.duration
      }
      void audioRef.current.play().catch(() => setPlaying(false))
      return
    }
    setOpening(true)
    try {
      const opened = await openCachedChatMediaV1(cache, attachment)
      if (opened.kind !== 'audio') throw new Error('attachment is not playable audio')
      pendingPositionRef.current = position
      setSourceUrl(URL.createObjectURL(opened.blob))
    } catch {
      onError()
    } finally {
      setOpening(false)
    }
  }

  const handlePrimaryAction = async () => {
    if (downloadState === 'downloading') {
      onCancel()
      return
    }
    if (downloadState === 'remote') {
      try {
        await onDownload()
      } catch (cause) {
        if (!(cause instanceof DOMException && cause.name === 'AbortError')) onError()
      }
      return
    }
    if (downloadState !== 'available' || opening) return
    if (!sourceUrl || !audioRef.current) {
      await openAndPlay(0)
    } else if (audioRef.current.paused) {
      void audioRef.current.play().catch(() => setPlaying(false))
    } else {
      audioRef.current.pause()
    }
  }

  const primaryLabel =
    downloadState === 'downloading'
      ? t('chat.attachments.cancelDownload', { filename })
      : downloadState === 'remote'
        ? t('chat.voice.download', { filename })
        : playing
          ? t('chat.voice.pause', { filename })
          : t('chat.voice.play', { filename })

  const status =
    downloadState === 'checking'
      ? t('chat.voice.preparing')
      : downloadState === 'remote'
        ? durationMs > 0
          ? formatVoiceNoteElapsed(durationMs)
          : t('chat.voice.voiceMessage')
        : downloadState === 'downloading'
          ? t('chat.voice.progress', { percent: Math.round(downloadProgress) })
          : `${formatVoiceNoteElapsed(currentTimeMs)} / ${formatVoiceNoteElapsed(durationMs)}`

  return (
    <div className={cn('flex min-w-0 flex-1 items-center gap-2', className)}>
      <div className="relative h-11 w-11 shrink-0">
        <Button
          type="button"
          size="icon"
          variant="secondary"
          className="h-11 w-11 rounded-full"
          disabled={disabled || downloadState === 'checking'}
          onClick={() => {
            void handlePrimaryAction()
          }}
          aria-label={primaryLabel}
        >
          {opening || downloadState === 'checking' ? (
            <Loader2 className="h-5 w-5 animate-spin" />
          ) : downloadState === 'remote' ? (
            <Download className="h-5 w-5" />
          ) : downloadState === 'downloading' ? (
            <X className="h-4 w-4" />
          ) : playing ? (
            <Pause className="h-5 w-5" />
          ) : (
            <Play className="ml-0.5 h-5 w-5" />
          )}
        </Button>
        {downloadState === 'downloading' && (
          <svg
            viewBox="0 0 44 44"
            className="pointer-events-none absolute inset-0 h-11 w-11 -rotate-90 text-primary"
            aria-hidden="true"
            data-testid="voice-note-download-progress"
          >
            <circle
              cx="22"
              cy="22"
              r={PROGRESS_RING_RADIUS}
              fill="none"
              stroke="currentColor"
              strokeOpacity="0.2"
              strokeWidth="3"
            />
            <circle
              cx="22"
              cy="22"
              r={PROGRESS_RING_RADIUS}
              fill="none"
              stroke="currentColor"
              strokeWidth="3"
              strokeLinecap="round"
              strokeDasharray={PROGRESS_RING_LENGTH}
              strokeDashoffset={
                PROGRESS_RING_LENGTH * (1 - Math.min(100, Math.max(0, downloadProgress)) / 100)
              }
            />
          </svg>
        )}
      </div>

      <div className="min-w-0 flex-1">
        <ChatAttachmentPreview
          attachment={attachment}
          progress={playbackProgress}
          onSeek={
            downloadState === 'available'
              ? (position) => {
                  void openAndPlay(position)
                }
              : undefined
          }
          activationLabel={t('chat.voice.seek', { filename })}
          disabled={downloadState !== 'available'}
        />
        <div className="mt-1 flex items-center justify-between gap-2 text-[11px] tabular-nums opacity-75">
          <span>{status}</span>
          <Button
            type="button"
            size="sm"
            variant="ghost"
            className="h-6 min-w-10 rounded-full px-2 text-[11px] font-semibold tabular-nums"
            disabled={disabled || downloadState !== 'available'}
            onClick={() => {
              const nextIndex = (playbackRateIndex + 1) % PLAYBACK_RATES.length
              const nextRate = PLAYBACK_RATES[nextIndex]
              setPlaybackRateIndex(nextIndex)
              if (audioRef.current) audioRef.current.playbackRate = nextRate
            }}
            aria-label={t('chat.voice.playbackSpeed', { rate: playbackRate })}
            title={t('chat.voice.changePlaybackSpeed')}
          >
            {playbackRate}×
          </Button>
        </div>
      </div>

      {sourceUrl && (
        <audio
          ref={audioRef}
          src={sourceUrl}
          preload="auto"
          className="sr-only"
          onLoadedMetadata={() => {
            const audio = audioRef.current
            if (!audio) return
            audio.playbackRate = playbackRate
            if (Number.isFinite(audio.duration)) {
              setDecodedDurationMs(audio.duration * 1_000)
              const position = pendingPositionRef.current ?? 0
              audio.currentTime = position * audio.duration
            }
          }}
          onCanPlay={() => {
            if (pendingPositionRef.current === null) return
            pendingPositionRef.current = null
            void audioRef.current?.play().catch(() => setPlaying(false))
          }}
          onTimeUpdate={() => setCurrentTimeMs((audioRef.current?.currentTime ?? 0) * 1_000)}
          onPlay={() => setPlaying(true)}
          onPause={() => setPlaying(false)}
          onEnded={() => {
            const audio = audioRef.current
            const endedAtMs =
              audio && Number.isFinite(audio.duration) && audio.duration > 0
                ? audio.duration * 1_000
                : durationMs
            if (endedAtMs > 0) {
              setDecodedDurationMs(endedAtMs)
              setCurrentTimeMs(endedAtMs)
            }
            setPlaying(false)
          }}
        />
      )}
    </div>
  )
}
