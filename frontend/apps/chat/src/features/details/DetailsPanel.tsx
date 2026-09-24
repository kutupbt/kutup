import { ArrowLeft, Ban, Check, ShieldCheck, Timer } from 'lucide-react'
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import type { SafetyNumberV1 } from '@kutup/chat-core/types'
import { Button } from '@kutup/ui/components/button'
import { cn } from '@kutup/ui/lib/cn'
import { refreshChat, useChat } from '../../app/chatStore'
import { Avatar } from '../../components/Avatar'
import { DISAPPEARING_PRESETS } from '../../lib/disappearing'
import { chatErrorMessage } from '../../lib/errors'
import type { ConversationModel } from '../thread/useConversationModel'
import { GroupDetails } from './GroupDetails'
import { SafetyVerificationDialog } from './SafetyVerificationDialog'

/**
 * Everything about a conversation, as Signal Desktop's details panel: it
 * slides in over the timeline with a back arrow (Escape closes it). The
 * person or group on top, then disappearing messages, the safety number,
 * members for a group, and the actions that end something, in red, last.
 */
export function DetailsPanel({ open, onClose, model }: { open: boolean; onClose: () => void; model: ConversationModel }) {
  const { t } = useTranslation()
  const panel = useRef<HTMLElement>(null)

  // Closed, it is off screen and out of the tab order (`inert`, which React
  // 18's types do not know yet).
  useEffect(() => {
    panel.current?.toggleAttribute('inert', !open)
  }, [open])

  useEffect(() => {
    if (!open) return
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !document.querySelector('[role="dialog"], [role="menu"]')) onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onClose])

  return (
    <>
      <div
        aria-hidden
        onClick={onClose}
        className={cn('absolute inset-0 z-20 bg-foreground/20 transition-opacity duration-300', open ? 'opacity-100' : 'pointer-events-none opacity-0')}
      />
      <section
        aria-label={t('chat.details.title')}
        ref={panel}
        aria-hidden={!open}
        className={cn(
          'absolute inset-y-0 right-0 z-30 flex w-full flex-col bg-background shadow-xl transition-transform duration-300 ease-[cubic-bezier(0.17,0.17,0,1)] sm:max-w-md sm:border-l sm:border-border',
          open ? 'translate-x-0' : 'translate-x-full',
        )}
      >
        <header className="flex h-[3.25rem] shrink-0 items-center gap-2 border-b border-border px-2">
          <Button variant="ghost" size="icon" onClick={onClose} aria-label={t('chat.details.close')}>
            <ArrowLeft />
          </Button>
          <h2 className="text-sm font-semibold">{model.group || model.historyOnly ? t('chat.details.groupTitle') : t('chat.details.title')}</h2>
        </header>
        <div className="min-h-0 flex-1 overflow-y-auto">
          {open ? <DetailsBody model={model} /> : null}
        </div>
      </section>
    </>
  )
}

function DetailsBody({ model }: { model: ConversationModel }) {
  const { t } = useTranslation()
  return (
    <div className="pb-8">
      <div className="flex flex-col items-center gap-2 px-6 pb-6 pt-8 text-center">
        <Avatar name={model.title} image={model.profile?.avatar} contentType={model.profile?.avatarContentType} group={model.conversation.kind === 'group'} size={80} />
        <h3 className="mt-2 text-lg font-semibold">{model.title}</h3>
        {model.address && !model.note && model.profile?.displayName ? (
          <p className="break-all text-sm text-muted-foreground">{model.address}</p>
        ) : null}
        {model.note ? <p className="text-sm text-muted-foreground">{t('chat.noteToSelfDescription')}</p> : null}
        {model.group ? <p className="text-sm text-muted-foreground">{t('chat.group.members', { count: model.group.currentRoster.length })}</p> : null}
        {model.historyOnly ? <p className="text-sm text-muted-foreground">{t('chat.readOnly.history')}</p> : null}
      </div>

      {model.canSetTimer ? <DisappearingSection model={model} /> : null}
      {model.address && !model.note ? <SafetySection model={model} /> : null}
      {model.group ? <GroupDetails model={model} group={model.group} /> : null}
      {model.address && !model.note && model.contact ? <BlockSection model={model} /> : null}
    </div>
  )
}

export function Section({ title, children, testId }: { title: string; children: ReactNode; testId?: string }) {
  return (
    <section className="border-t border-border px-6 py-4" data-testid={testId}>
      <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">{title}</h4>
      {children}
    </section>
  )
}

function DisappearingSection({ model }: { model: ConversationModel }) {
  const { t } = useTranslation()
  const { service } = useChat()
  const [busy, setBusy] = useState(false)
  async function choose(seconds: number | undefined) {
    if (!service || busy || seconds === model.timerSeconds) return
    setBusy(true)
    try {
      const summary = await service.sendDisappearingTimer(model.conversation, seconds)
      if (summary.safetyNumberChanges.length > 0) toast.warning(t('chat.safetyNumberChanged'))
      await refreshChat()
    } catch (error) {
      toast.error(chatErrorMessage(error, t))
    } finally {
      setBusy(false)
    }
  }
  return (
    <Section title={t('chat.disappearing.setting')}>
      <p className="mb-3 flex items-start gap-2 text-sm text-muted-foreground">
        <Timer className="mt-0.5 size-4 shrink-0" aria-hidden />
        {t('chat.disappearing.explanation')}
      </p>
      <div role="radiogroup" aria-label={t('chat.disappearing.setting')} className="grid grid-cols-2 gap-1.5">
        {DISAPPEARING_PRESETS.map((option) => {
          const active = model.timerSeconds === option.seconds
          return (
            <button
              key={option.id}
              type="button"
              role="radio"
              aria-checked={active}
              disabled={busy}
              onClick={() => void choose(option.seconds)}
              className={cn(
                'flex items-center justify-between rounded-lg border px-3 py-2 text-sm transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-60',
                active ? 'border-primary bg-accent font-medium' : 'border-border hover:bg-muted',
              )}
            >
              {t(`chat.disappearing.presets.${option.id}`)}
              {active ? <Check className="size-4 text-primary" aria-hidden /> : null}
            </button>
          )
        })}
      </div>
    </Section>
  )
}

function SafetySection({ model }: { model: ConversationModel }) {
  const { t } = useTranslation()
  const { service } = useChat()
  const [safety, setSafety] = useState<SafetyNumberV1 | null>(null)
  const [open, setOpen] = useState(false)
  const peer = model.address!
  useEffect(() => {
    let cancelled = false
    setSafety(null)
    void service
      ?.safetyNumber(peer)
      .then((value) => !cancelled && setSafety(value))
      .catch(() => !cancelled && setSafety(null))
    return () => {
      cancelled = true
    }
  }, [service, peer])

  const verified = safety?.trust === 'Verified'
  return (
    <Section title={t('chat.safety.section')}>
      <p className="mb-3 flex items-start gap-2 text-sm text-muted-foreground">
        <ShieldCheck className={cn('mt-0.5 size-4 shrink-0', verified && 'text-status-ok')} aria-hidden />
        {verified
          ? t('chat.safety.verifiedStatus')
          : safety?.trust === 'Quarantined'
            ? t('chat.safety.changedStatus')
            : t('chat.safety.unverifiedStatus', { name: model.title })}
      </p>
      <Button variant="outline" className="w-full" disabled={!safety} onClick={() => setOpen(true)} data-testid="chat-safety-open">
        {t('chat.safety.view')}
      </Button>
      {safety ? (
        <SafetyVerificationDialog
          open={open}
          onOpenChange={setOpen}
          peer={peer}
          safety={safety}
          onVerify={async (payload: string) => {
            const next = await service!.verifySafetyNumber(peer, payload)
            setSafety(next)
            await refreshChat()
            return next
          }}
        />
      ) : null}
    </Section>
  )
}

function BlockSection({ model }: { model: ConversationModel }) {
  const { t } = useTranslation()
  const { service } = useChat()
  const [busy, setBusy] = useState(false)
  const blocked = model.contact?.state === 'blocked'
  const peer = model.address!
  async function toggle() {
    if (!service) return
    setBusy(true)
    try {
      if (blocked) await service.unblockContact(peer)
      else await service.blockContact(peer)
      await refreshChat()
    } catch (error) {
      toast.error(chatErrorMessage(error, t))
    } finally {
      setBusy(false)
    }
  }
  return (
    <section className="border-t border-border px-4 py-3">
      <Button
        variant="ghost"
        disabled={busy}
        onClick={() => void toggle()}
        className={cn('w-full justify-start', !blocked && 'text-destructive hover:bg-destructive/10 hover:text-destructive')}
      >
        <Ban />
        {blocked ? t('chat.requests.unblock') : t('chat.details.block', { name: model.title })}
      </Button>
    </section>
  )
}
