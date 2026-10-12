import { Smile } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useTheme } from 'next-themes'
import { Button } from '@kutup/ui/components/button'
import { Popover, PopoverContent, PopoverTrigger } from '@kutup/ui/components/popover'
import { Tooltip } from '@kutup/ui/components/tooltip'

/** The picker itself: emoji-mart (as Proton's ToolbarEmojiDropdown), loaded the first time it opens. */
function Picker({ onPick }: { onPick: (emoji: string) => void }) {
  const { i18n } = useTranslation()
  const { resolvedTheme } = useTheme()
  const host = useRef<HTMLDivElement>(null)
  const pick = useRef(onPick)
  pick.current = onPick
  useEffect(() => {
    let element: HTMLElement | null = null
    let gone = false
    void Promise.all([import('emoji-mart'), import('@emoji-mart/data')]).then(([{ Picker: EmojiMart }, { default: data }]) => {
      if (gone || !host.current) return
      element = new EmojiMart({
        data,
        locale: i18n.language.startsWith('tr') ? 'tr' : 'en',
        theme: resolvedTheme === 'dark' ? 'dark' : 'light',
        previewPosition: 'none',
        skinTonePosition: 'search',
        onEmojiSelect: (emoji: { native: string }) => pick.current(emoji.native),
      }) as unknown as HTMLElement
      host.current.appendChild(element)
    })
    return () => {
      gone = true
      element?.remove()
    }
  }, [i18n.language, resolvedTheme])
  return <div ref={host} className="min-h-[24rem] min-w-[22rem]" />
}

/** "Insert emoji" in the composer's toolbar. */
export function EmojiButton({ onPick, disabled }: { onPick: (emoji: string) => void; disabled?: boolean }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <Tooltip label={t('compose.emoji')}>
        <PopoverTrigger asChild>
          <Button variant="ghost" size="icon" className="size-8" aria-label={t('compose.emoji')} disabled={disabled}>
            <Smile />
          </Button>
        </PopoverTrigger>
      </Tooltip>
      <PopoverContent align="start" className="w-auto p-0">
        {open ? (
          <Picker
            onPick={(emoji) => {
              onPick(emoji)
              setOpen(false)
            }}
          />
        ) : null}
      </PopoverContent>
    </Popover>
  )
}
