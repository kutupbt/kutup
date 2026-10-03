import { Check } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Button } from '@kutup/ui/components/button'
import { cn } from '@kutup/ui/lib/cn'
import type { PollState } from '../../state/views'

/**
 * A poll in its bubble, as Signal shows it: the question, whether one or
 * several may be chosen, each option with its share and count (your choices
 * checked), the number of voters, and for its author "End poll". Once ended,
 * it only shows the result.
 */
export function PollBody({
  state,
  selfAddress,
  outgoing,
  canVote,
  nameOf,
  onVote,
  onEnd,
}: {
  state: PollState
  selfAddress: string
  outgoing: boolean
  canVote: boolean
  nameOf: (address: string) => string
  onVote: (options: number[]) => void
  onEnd?: () => void
}) {
  const { t } = useTranslation()
  const { poll, votes, ended } = state
  const mine = votes.get(selfAddress) ?? []
  const counts = poll.options.map((_, index) => [...votes.values()].filter((choice) => choice.includes(index)).length)
  const voters = votes.size
  const open = canVote && !ended

  function choose(index: number) {
    if (!open) return
    if (poll.allowMultiple) {
      onVote(mine.includes(index) ? mine.filter((i) => i !== index) : [...mine, index].sort((a, b) => a - b))
    } else {
      onVote(mine.includes(index) ? [] : [index])
    }
  }

  return (
    <div className="min-w-[15rem] max-w-sm space-y-2" data-testid="chat-poll">
      <p className="font-semibold">{poll.question}</p>
      <p className={cn('text-xs', outgoing ? 'opacity-80' : 'text-muted-foreground')}>
        {ended ? t('chat.polls.ended') : poll.allowMultiple ? t('chat.polls.chooseMany') : t('chat.polls.chooseOne')}
      </p>
      <ul className="space-y-1.5" role={poll.allowMultiple ? 'group' : 'radiogroup'} aria-label={poll.question}>
        {poll.options.map((option, index) => {
          const chosen = mine.includes(index)
          const share = voters > 0 ? counts[index] / voters : 0
          const who = [...votes.entries()].filter(([, choice]) => choice.includes(index)).map(([voter]) => nameOf(voter))
          return (
            <li key={index}>
              <button
                type="button"
                role={poll.allowMultiple ? 'checkbox' : 'radio'}
                aria-checked={chosen}
                disabled={!open}
                onClick={() => choose(index)}
                title={who.join(', ') || undefined}
                className={cn(
                  'relative flex w-full items-center gap-2 overflow-hidden rounded-lg border px-2.5 py-1.5 text-left text-sm outline-none',
                  'focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-default',
                  outgoing ? 'border-primary-foreground/30' : 'border-border',
                )}
                data-testid="chat-poll-option"
              >
                <span
                  aria-hidden
                  className={cn('absolute inset-y-0 left-0', outgoing ? 'bg-primary-foreground/20' : 'bg-primary/15')}
                  style={{ width: `${Math.round(share * 100)}%` }}
                />
                <span
                  aria-hidden
                  className={cn(
                    'relative flex size-4 shrink-0 items-center justify-center border',
                    poll.allowMultiple ? 'rounded' : 'rounded-full',
                    chosen ? (outgoing ? 'border-primary-foreground bg-primary-foreground text-primary' : 'border-primary bg-primary text-primary-foreground') : 'border-current opacity-60',
                  )}
                >
                  {chosen ? <Check className="size-3" /> : null}
                </span>
                <span className="relative min-w-0 flex-1 break-words">{option}</span>
                <span className="relative shrink-0 text-xs tabular-nums">{counts[index]}</span>
              </button>
            </li>
          )
        })}
      </ul>
      <div className="flex items-center justify-between gap-2">
        <span className={cn('text-xs', outgoing ? 'opacity-80' : 'text-muted-foreground')}>{t('chat.polls.voters', { count: voters })}</span>
        {onEnd && !ended ? (
          <Button type="button" size="sm" variant="ghost" className="h-7 px-2 text-xs" onClick={onEnd} data-testid="chat-poll-end">
            {t('chat.polls.end')}
          </Button>
        ) : null}
      </div>
    </div>
  )
}
