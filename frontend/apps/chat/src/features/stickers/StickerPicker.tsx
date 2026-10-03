import { Loader2, Plus, Sticker, X } from 'lucide-react'
import { useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import type { ChatStickerV1 } from '@kutup/chat-core/types'
import { Button } from '@kutup/ui/components/button'
import { DropdownMenu, DropdownMenuContent, DropdownMenuTrigger } from '@kutup/ui/components/dropdown-menu'
import { refreshChat, useChat } from '../../app/chatStore'
import { chatErrorMessage } from '../../lib/errors'
import { stickerFromImage } from '../../lib/stickers'
import { useAccountState } from '../../state/useAccountState'

/**
 * "My stickers" in the composer: pick one to send it; add one from a
 * picture; remove one. The collection is this account's, synced to its
 * devices (see docs/chat-protocol.md).
 */
export function StickerPicker({ onSend, disabled }: { onSend: (sticker: ChatStickerV1) => void; disabled?: boolean }) {
  const { t } = useTranslation()
  const { service } = useChat()
  const { stickers } = useAccountState()
  const [open, setOpen] = useState(false)
  const [adding, setAdding] = useState(false)
  const input = useRef<HTMLInputElement>(null)

  async function add(file: File | undefined) {
    if (!file || !service) return
    setAdding(true)
    try {
      await service.saveSticker(await stickerFromImage(file))
      await refreshChat()
    } catch (error) {
      toast.error(error instanceof Error && error.message.includes('small enough') ? t('chat.stickers.tooBig') : chatErrorMessage(error, t))
    } finally {
      setAdding(false)
      if (input.current) input.current.value = ''
    }
  }

  async function remove(sticker: ChatStickerV1) {
    try {
      await service?.removeSticker(sticker.stickerId)
      await refreshChat()
    } catch (error) {
      toast.error(chatErrorMessage(error, t))
    }
  }

  return (
    <DropdownMenu open={open} onOpenChange={setOpen}>
      <DropdownMenuTrigger asChild>
        <Button type="button" variant="ghost" size="icon" className="size-9 shrink-0 rounded-full" disabled={disabled} aria-label={t('chat.stickers.open')} title={t('chat.stickers.open')} data-testid="chat-sticker-button">
          <Sticker />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" side="top" className="w-80 p-2" data-testid="chat-sticker-picker">
        <div className="mb-2 flex items-center justify-between">
          <p className="text-sm font-semibold">{t('chat.stickers.title')}</p>
          <input ref={input} type="file" accept="image/png,image/webp,image/jpeg,image/gif" hidden onChange={(e) => void add(e.target.files?.[0])} data-testid="chat-sticker-add-input" />
          <Button type="button" size="sm" variant="outline" disabled={adding} onClick={() => input.current?.click()}>
            {adding ? <Loader2 className="animate-spin" /> : <Plus />}
            {t('chat.stickers.add')}
          </Button>
        </div>
        {stickers.length === 0 ? (
          <p className="px-2 py-6 text-center text-sm text-muted-foreground">{t('chat.stickers.empty')}</p>
        ) : (
          <ul className="grid max-h-72 grid-cols-4 gap-1 overflow-y-auto">
            {stickers.map((sticker) => (
              <li key={sticker.stickerId} className="group/sticker relative">
                <button
                  type="button"
                  onClick={() => {
                    setOpen(false)
                    onSend(sticker)
                  }}
                  className="flex aspect-square w-full items-center justify-center rounded-lg p-1 outline-none hover:bg-muted focus-visible:ring-2 focus-visible:ring-ring"
                  aria-label={sticker.emoji ? t('chat.stickers.sendEmoji', { emoji: sticker.emoji }) : t('chat.stickers.send')}
                  data-testid="chat-sticker"
                >
                  <img src={`data:${sticker.contentType};base64,${sticker.data}`} alt="" className="max-h-full max-w-full object-contain" />
                </button>
                <button
                  type="button"
                  onClick={() => void remove(sticker)}
                  className="absolute right-0 top-0 hidden size-5 items-center justify-center rounded-full bg-background/90 text-muted-foreground shadow group-hover/sticker:flex"
                  aria-label={t('chat.stickers.remove')}
                >
                  <X className="size-3" />
                </button>
              </li>
            ))}
          </ul>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
