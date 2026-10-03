import { MessageSquare, Mic, MicOff, MonitorUp, Users, Video, VideoOff, X } from 'lucide-react'
import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Avatar } from '@kutup/ui/components/avatar'
import { KutupLogo } from '@kutup/ui/components/brand'
import { Button } from '@kutup/ui/components/button'
import { cn } from '@kutup/ui/lib/cn'

// What the one-to-one and the group call screens share: the frame (the
// brand, the call's title and status, the stage, the controls) and the side
// panel with the people in the call and the conversation's chat.

export type CallPanel = 'people' | 'chat'

/** Someone in the call, for the People list. */
export interface CallPerson {
  key: string
  name: string
  avatarName: string
  avatar?: string
  avatarContentType?: string
  /** Unknown for the other side of a one-to-one call, which does not say. */
  muted?: boolean
  cameraOn: boolean
  sharing: boolean
}

export function CallFrame({
  label,
  title,
  status,
  phase,
  testId,
  statusTestId,
  people,
  chat,
  panel,
  onPanel,
  controls,
  children,
}: {
  /** The dialog's accessible name. */
  label: string
  title: string
  status: string
  phase: string
  testId: string
  statusTestId: string
  people: CallPerson[]
  /** The call's chat, once there is something to chat in. */
  chat: ReactNode | null
  panel: CallPanel | null
  onPanel: (panel: CallPanel | null) => void
  controls: ReactNode
  children: ReactNode
}) {
  const { t } = useTranslation()
  return (
    <div
      className="fixed inset-0 z-50 flex flex-col bg-stage text-stage-foreground"
      role="dialog"
      aria-modal
      aria-label={label}
      data-testid={testId}
      data-phase={phase}
    >
      <header className="flex shrink-0 items-center gap-3 px-4 py-3">
        <span className="inline-flex shrink-0 items-center gap-2" data-testid="chat-call-brand">
          <KutupLogo size={20} />
          <span className="font-display text-base font-semibold tracking-tight">Kutup</span>
          <span className="text-base text-stage-muted">{t('apps.chat')}</span>
        </span>
        <span className="h-4 w-px shrink-0 bg-stage-active" aria-hidden />
        <h2 className="min-w-0 truncate font-semibold">{title}</h2>
        <span className="shrink-0 text-sm text-stage-muted" data-testid={statusTestId}>
          {status}
        </span>
      </header>
      <div className="relative flex min-h-0 flex-1">
        <div className="relative flex min-h-0 min-w-0 flex-1 flex-col">{children}</div>
        {panel ? (
          <aside
            className="absolute inset-0 z-10 flex min-h-0 flex-col bg-background text-foreground md:static md:w-[22rem] md:shrink-0 md:rounded-tl-xl md:border-l md:border-t md:border-border"
            aria-label={panel === 'people' ? t('chat.calls.people') : t('chat.calls.chatPanel')}
            data-testid="chat-call-panel"
            data-panel={panel}
          >
            <div className="flex shrink-0 items-center gap-1 border-b border-border px-2 py-1.5">
              <PanelTab active={panel === 'people'} onClick={() => onPanel('people')} testId="chat-call-tab-people">
                {t('chat.calls.peopleCount', { count: people.length })}
              </PanelTab>
              {chat ? (
                <PanelTab active={panel === 'chat'} onClick={() => onPanel('chat')} testId="chat-call-tab-chat">
                  {t('chat.calls.chatPanel')}
                </PanelTab>
              ) : null}
              <Button
                type="button"
                variant="ghost"
                size="icon"
                className="ml-auto"
                onClick={() => onPanel(null)}
                aria-label={t('chat.calls.closePanel')}
                data-testid="chat-call-panel-close"
              >
                <X />
              </Button>
            </div>
            {panel === 'chat' && chat ? (
              <div className="min-h-0 flex-1">{chat}</div>
            ) : (
              <ul className="min-h-0 flex-1 overflow-y-auto p-2" data-testid="chat-call-people">
                {people.map((person) => (
                  <li key={person.key} className="flex items-center gap-3 rounded-lg px-2 py-2" data-testid="chat-call-person" data-name={person.name}>
                    <Avatar name={person.avatarName} image={person.avatar} contentType={person.avatarContentType} size={32} />
                    <span className="min-w-0 flex-1 truncate text-sm">{person.name}</span>
                    {person.sharing ? (
                      <MonitorUp className="size-4 shrink-0 text-primary" aria-label={t('chat.calls.isSharing')} />
                    ) : null}
                    {person.cameraOn ? (
                      <Video className="size-4 shrink-0 text-muted-foreground" aria-label={t('chat.calls.cameraIsOn')} />
                    ) : (
                      <VideoOff className="size-4 shrink-0 text-muted-foreground" aria-label={t('chat.calls.cameraIsOff')} />
                    )}
                    {person.muted === undefined ? null : person.muted ? (
                      <MicOff className="size-4 shrink-0 text-muted-foreground" aria-label={t('chat.calls.micIsOff')} />
                    ) : (
                      <Mic className="size-4 shrink-0 text-muted-foreground" aria-label={t('chat.calls.micIsOn')} />
                    )}
                  </li>
                ))}
              </ul>
            )}
          </aside>
        ) : null}
      </div>
      {controls ? <div className="flex shrink-0 flex-wrap items-center justify-center gap-3 px-3 pb-8 pt-3 md:gap-4">{controls}</div> : null}
    </div>
  )
}

function PanelTab({ active, onClick, testId, children }: { active: boolean; onClick: () => void; testId: string; children: ReactNode }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cn(
        'rounded-md px-3 py-1.5 text-sm font-medium outline-none focus-visible:ring-2 focus-visible:ring-ring',
        active ? 'bg-muted text-foreground' : 'text-muted-foreground hover:bg-muted/60',
      )}
      data-testid={testId}
    >
      {children}
    </button>
  )
}

/** The buttons that open the side panel, for a call's controls. */
export function PanelButtons({
  panel,
  onPanel,
  chat,
  unread,
}: {
  panel: CallPanel | null
  onPanel: (panel: CallPanel | null) => void
  /** Whether the call has a chat. */
  chat: boolean
  /** Something was written that the person has not seen. */
  unread?: boolean
}) {
  const { t } = useTranslation()
  return (
    <>
      <RoundButton
        label={t('chat.calls.people')}
        pressed={panel === 'people'}
        onClick={() => onPanel(panel === 'people' ? null : 'people')}
        testId="chat-call-people-button"
      >
        <Users />
      </RoundButton>
      {chat ? (
        <RoundButton
          label={t('chat.calls.chatPanel')}
          pressed={panel === 'chat'}
          onClick={() => onPanel(panel === 'chat' ? null : 'chat')}
          testId="chat-call-chat-button"
        >
          <span className="relative">
            <MessageSquare />
            {unread ? <span className="absolute -right-1 -top-1 size-2.5 rounded-full bg-primary" data-testid="chat-call-chat-unread" /> : null}
          </span>
        </RoundButton>
      ) : null}
    </>
  )
}

export function RoundButton({
  label,
  onClick,
  children,
  tone,
  pressed,
  disabled,
  testId,
}: {
  label: string
  onClick: () => void
  children: ReactNode
  tone?: 'danger' | 'accept'
  pressed?: boolean
  disabled?: boolean
  testId: string
}) {
  return (
    <Button
      type="button"
      size="icon"
      onClick={onClick}
      disabled={disabled}
      aria-label={label}
      title={label}
      aria-pressed={pressed}
      className={cn(
        'size-12 rounded-full md:size-14 [&_svg]:size-5 md:[&_svg]:size-6',
        tone === 'danger' && 'bg-destructive text-destructive-foreground hover:bg-destructive/90',
        tone === 'accept' && 'bg-status-ok text-status-ok-foreground hover:bg-status-ok/90',
        !tone && (pressed ? 'bg-stage-foreground text-stage hover:bg-stage-foreground/90' : 'bg-stage-accent text-stage-foreground hover:bg-stage-active'),
      )}
      data-testid={testId}
    >
      {children}
    </Button>
  )
}
