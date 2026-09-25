import { Loader2, Plus, X } from 'lucide-react'
import { useEffect, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { POLL_LIMITS, type ChatPollV1 } from '@kutup/chat-core/types'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'

const length = (value: string) => [...value.trim()].length

/** Signal's "Poll": a question, 2 to 10 options, one or several choices. */
export function NewPollDialog({
  open,
  onOpenChange,
  send,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  send: (poll: ChatPollV1) => Promise<void>
}) {
  const { t } = useTranslation()
  const [question, setQuestion] = useState('')
  const [options, setOptions] = useState(['', ''])
  const [allowMultiple, setAllowMultiple] = useState(false)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!open) return
    setQuestion('')
    setOptions(['', ''])
    setAllowMultiple(false)
  }, [open])

  const filled = options.map((option) => option.trim()).filter(Boolean)
  const duplicate = new Set(filled.map((option) => option.toLowerCase())).size !== filled.length
  const valid =
    length(question) > 0 &&
    length(question) <= POLL_LIMITS.question &&
    filled.length >= POLL_LIMITS.minOptions &&
    filled.every((option) => [...option].length <= POLL_LIMITS.option) &&
    !duplicate

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (!valid || busy) return
    setBusy(true)
    try {
      await send({ question: question.trim().replace(/\s+/gu, ' '), options: filled, ...(allowMultiple ? { allowMultiple } : {}) })
      onOpenChange(false)
    } catch {
      // Said already.
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={(next) => !busy && onOpenChange(next)}>
      <DialogContent className="sm:max-w-md" data-testid="chat-new-poll">
        <form onSubmit={(e) => void submit(e)} className="space-y-4">
          <DialogHeader>
            <DialogTitle>{t('chat.polls.newTitle')}</DialogTitle>
            <DialogDescription>{t('chat.polls.newDescription')}</DialogDescription>
          </DialogHeader>
          <Field label={t('chat.polls.question')} required>
            {(props) => (
              <Input {...props} autoFocus value={question} maxLength={POLL_LIMITS.question} onChange={(e) => setQuestion(e.target.value)} data-testid="chat-poll-question" />
            )}
          </Field>
          <div className="space-y-2">
            <p className="text-sm font-medium">{t('chat.polls.options')}</p>
            {options.map((option, index) => (
              <div key={index} className="flex items-center gap-2">
                <Input
                  value={option}
                  maxLength={POLL_LIMITS.option}
                  onChange={(e) => setOptions((current) => current.map((value, i) => (i === index ? e.target.value : value)))}
                  placeholder={t('chat.polls.option', { number: index + 1 })}
                  aria-label={t('chat.polls.option', { number: index + 1 })}
                  data-testid="chat-poll-option-input"
                />
                {options.length > POLL_LIMITS.minOptions ? (
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="shrink-0"
                    onClick={() => setOptions((current) => current.filter((_, i) => i !== index))}
                    aria-label={t('chat.polls.removeOption', { number: index + 1 })}
                  >
                    <X />
                  </Button>
                ) : null}
              </div>
            ))}
            {options.length < POLL_LIMITS.maxOptions ? (
              <Button type="button" variant="outline" size="sm" onClick={() => setOptions((current) => [...current, ''])} data-testid="chat-poll-add-option">
                <Plus />
                {t('chat.polls.addOption')}
              </Button>
            ) : null}
            {duplicate ? <p className="text-xs text-destructive">{t('chat.polls.duplicate')}</p> : null}
          </div>
          <label className="flex cursor-pointer items-center gap-2 text-sm">
            <Checkbox checked={allowMultiple} onCheckedChange={(value) => setAllowMultiple(value === true)} />
            {t('chat.polls.allowMultiple')}
          </label>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" disabled={!valid || busy} data-testid="chat-poll-send">
              {busy ? <Loader2 className="animate-spin" /> : null}
              {t('chat.polls.send')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
