import { Download, FileText, Loader2, MoreHorizontal, Trash2 } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import {
  chatMediaViewerKindV1,
  clearCachedChatMediaV1,
  downloadChatMediaToCacheV1,
  isChatMediaAvailableInKutupV1,
  saveCachedChatMediaToDeviceV1,
} from '@kutup/chat-core/media'
import type { ChatAttachmentDescriptorV1 } from '@kutup/chat-core/types'
import type { PrivateCiphertextCacheV1 } from '@kutup/files/mediaCache'
import { freshAccessToken } from '@kutup/session/client'
import { Button } from '@kutup/ui/components/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@kutup/ui/components/dropdown-menu'
import { cn } from '@kutup/ui/lib/cn'
import { formatBytes } from '@kutup/ui/lib/format'
import { useChat } from '../../app/chatStore'
import { ChatAttachmentAction, type ChatAttachmentCacheState } from './ChatAttachmentAction'
import { ChatAttachmentPreview } from './ChatAttachmentPreview'
import { ChatAttachmentViewer } from './ChatAttachmentViewer'
import { ChatVoiceNotePlayer } from './ChatVoiceNotePlayer'

function aborted(error: unknown): boolean {
  return error instanceof DOMException && error.name === 'AbortError'
}

/**
 * An attachment inside its bubble. Nothing is fetched until asked: the
 * encrypted file is downloaded into this browser's private media cache,
 * checked, and opened from there (viewer for pictures, video, audio and
 * PDFs; a player for voice notes). "Save to device" writes the plaintext out;
 * "Clear local copy" drops the cached one. A deleted or expired message's
 * copy is dropped at once.
 */
export function AttachmentBody({
  attachment,
  outgoing,
  accepted,
  expiresAtMs,
  deleted,
}: {
  attachment: ChatAttachmentDescriptorV1
  outgoing: boolean
  /** Media from someone not accepted yet is not fetched. */
  accepted: boolean
  expiresAtMs?: number
  deleted: boolean
}) {
  const { t, i18n } = useTranslation()
  const { mediaCache: cache, service } = useChat()
  const [state, setState] = useState<ChatAttachmentCacheState>('checking')
  const [progress, setProgress] = useState(0)
  const [viewerOpen, setViewerOpen] = useState(false)
  const [saving, setSaving] = useState(false)
  const controller = useRef<AbortController | null>(null)
  const viewerKind = chatMediaViewerKindV1(attachment)
  const binding = useMemo(
    () => ({
      product: 'chat' as const,
      suite: attachment.suite,
      objectId: attachment.attachmentId,
      ciphertextBytes: attachment.ciphertextBytes,
      ciphertextSha256: attachment.ciphertextSha256,
    }),
    [attachment.suite, attachment.attachmentId, attachment.ciphertextBytes, attachment.ciphertextSha256],
  )

  useEffect(() => {
    let cancelled = false
    controller.current?.abort()
    setProgress(0)
    if (!cache) {
      setState('remote')
      return
    }
    setState('checking')
    void cache
      .getVerified(binding)
      .then((found) => !cancelled && setState(found !== null ? 'available' : 'remote'))
      .catch(() => !cancelled && setState('remote'))
    return () => {
      cancelled = true
      controller.current?.abort()
    }
  }, [binding, cache])

  // Deleted or expired: nothing of it stays in this browser.
  const gone = deleted || (expiresAtMs !== undefined && expiresAtMs <= Date.now())
  useEffect(() => {
    if (!gone || !cache) return
    controller.current?.abort()
    setViewerOpen(false)
    setState('remote')
    void cache.remove(binding).catch(() => undefined)
  }, [gone, cache, binding])

  async function ensureAvailable(): Promise<void> {
    if (!accepted || !cache) throw new Error('attachment is not available')
    if (state === 'available' || (await isChatMediaAvailableInKutupV1(cache, attachment))) {
      setState('available')
      return
    }
    const abort = new AbortController()
    controller.current = abort
    setState('downloading')
    setProgress(0)
    try {
      const token = await freshAccessToken()
      await downloadChatMediaToCacheV1(
        cache,
        attachment,
        token,
        (received, total) => setProgress(Math.floor((received / total) * 100)),
        abort.signal,
        expiresAtMs === undefined ? {} : { expiresAtMs },
        attachment.backupMediaId && service
          ? () => service.backupMediaCiphertext(attachment.backupMediaId!, token, abort.signal)
          : undefined,
      )
      setState('available')
    } catch (error) {
      setState('remote')
      throw error
    } finally {
      controller.current = null
    }
  }

  const failed = (error: unknown) => {
    if (!aborted(error)) toast.error(t('chat.attachments.downloadFailed'))
  }
  const open = () => {
    if (state === 'available' && viewerKind) setViewerOpen(true)
  }

  if (attachment.mediaClass === 'audio' && cache) {
    return (
      <ChatVoiceNotePlayer
        cache={cache}
        attachment={attachment}
        downloadState={state}
        downloadProgress={progress}
        disabled={!accepted || state === 'checking'}
        onDownload={ensureAvailable}
        onCancel={() => controller.current?.abort()}
        onError={() => toast.error(t('chat.voice.playFailed'))}
        className="min-w-60"
      />
    )
  }

  return (
    <div className="min-w-56 max-w-full">
      {attachment.preview ? (
        <ChatAttachmentPreview
          attachment={attachment}
          visible={accepted}
          className="-mx-1 mb-2 overflow-hidden rounded-xl"
          onActivate={() => (state === 'remote' ? void ensureAvailable().catch(failed) : open())}
          activationLabel={
            state === 'remote'
              ? t('chat.attachments.downloadInto', { filename: attachment.filename })
              : t('chat.attachments.open', { filename: attachment.filename })
          }
          activationMode={state === 'remote' ? 'download' : 'open'}
          disabled={!accepted || !cache || state === 'checking' || state === 'downloading' || (state === 'available' && !viewerKind)}
        />
      ) : null}
      <div className="flex items-center gap-3">
        <FileText className="size-7 shrink-0 opacity-80" aria-hidden />
        <span className="min-w-0 flex-1">
          <span className="block truncate font-medium">{attachment.filename}</span>
          <span className={cn('block text-[0.6875rem]', outgoing ? 'text-primary-foreground/75' : 'text-muted-foreground')}>
            {formatBytes(attachment.plaintextBytes, i18n.language)} ·{' '}
            {state === 'available'
              ? t('chat.attachments.inKutup')
              : state === 'downloading'
                ? t('chat.attachments.progress', { percent: progress })
                : t('chat.attachments.encrypted')}
          </span>
        </span>
        <ChatAttachmentAction
          attachment={attachment}
          cacheState={state}
          downloadProgress={progress}
          viewerKind={viewerKind}
          outgoing={outgoing}
          disabled={!accepted || !cache}
          onDownload={ensureAvailable}
          onCancel={() => controller.current?.abort()}
          onOpen={open}
          onError={() => toast.error(t('chat.attachments.downloadFailed'))}
        />
        {accepted && state === 'available' && cache ? (
          <CachedMenu
            cache={cache}
            attachment={attachment}
            outgoing={outgoing}
            saving={saving}
            onSave={() => {
              setSaving(true)
              void saveCachedChatMediaToDeviceV1(cache, attachment)
                .catch((error: unknown) => !aborted(error) && toast.error(t('chat.attachments.saveFailed')))
                .finally(() => setSaving(false))
            }}
            onClear={() => {
              setViewerOpen(false)
              void clearCachedChatMediaV1(cache, attachment)
                .then(() => setState('remote'))
                .catch(() => toast.error(t('chat.attachments.clearFailed')))
            }}
          />
        ) : null}
      </div>
      {attachment.caption ? <p className="mt-2 whitespace-pre-wrap break-words">{attachment.caption}</p> : null}
      {cache ? <ChatAttachmentViewer open={viewerOpen} onOpenChange={setViewerOpen} cache={cache} attachment={attachment} /> : null}
    </div>
  )
}

function CachedMenu({
  attachment,
  outgoing,
  saving,
  onSave,
  onClear,
}: {
  cache: PrivateCiphertextCacheV1
  attachment: ChatAttachmentDescriptorV1
  outgoing: boolean
  saving: boolean
  onSave: () => void
  onClear: () => void
}) {
  const { t } = useTranslation()
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          type="button"
          size="icon"
          variant="ghost"
          className={cn('size-8 shrink-0 rounded-full', outgoing && 'text-primary-foreground hover:bg-primary-foreground/15 hover:text-primary-foreground')}
          aria-label={t('chat.attachments.moreActions', { filename: attachment.filename })}
        >
          {saving ? <Loader2 className="animate-spin" /> : <MoreHorizontal />}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem disabled={saving} onSelect={onSave}>
          <Download />
          {t('chat.attachments.saveToDevice')}
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={onClear}>
          <Trash2 />
          {t('chat.attachments.clearLocal')}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
