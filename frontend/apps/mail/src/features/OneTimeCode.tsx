import { Copy } from 'lucide-react'
import { useEffect, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button } from '@kutup/ui/components/button'
import { Tooltip } from '@kutup/ui/components/tooltip'
import { cn } from '@kutup/ui/lib/cn'

// After the "Copied" toast, so the move's Undo toast follows it (Proton's 200 ms).
const AFTER_COPY_MS = 200

/**
 * Proton's OneTimeCodeCopyButton: the code, copied with a click; then the
 * message has served its purpose and goes to Trash (with Undo).
 */
export function OneTimeCodeButton({ code, onCopied, className, size = 'sm' }: { code: string; onCopied: () => void; className?: string; size?: 'sm' | 'default' }) {
  const { t } = useTranslation()
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null)
  // Copying moves the message away and unmounts this; the timer still fires once.
  useEffect(() => () => void (timer.current && clearTimeout(timer.current)), [])
  const label = t('oneTimeCode.copyAndTrash', { code })
  return (
    <Tooltip label={label}>
      <Button
        variant="outline"
        size={size}
        className={cn('gap-1.5 font-mono tabular-nums', size === 'sm' && 'h-7 px-2', className)}
        aria-label={label}
        onClick={(event) => {
          event.stopPropagation()
          event.preventDefault()
          void navigator.clipboard.writeText(code).then(
            () => {
              toast.success(t('oneTimeCode.copied', { code }))
              timer.current = setTimeout(() => {
                timer.current = null
                onCopied()
              }, AFTER_COPY_MS)
            },
            () => toast.error(t('oneTimeCode.copyFailed')),
          )
        }}
      >
        <Copy className="size-3.5" />
        {code}
      </Button>
    </Tooltip>
  )
}
