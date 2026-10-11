import { useRef, type KeyboardEvent, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { useMailSettings, useUpdateMailSettings, type MailSettings } from '@kutup/mail-core/api'
import { Alert } from '@kutup/ui/components/alert'
import { PageBody, PageHeader } from '@kutup/ui/components/page'
import { LoadingPanel } from '@kutup/ui/components/states'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { cn } from '@kutup/ui/lib/cn'

interface Card<T extends string> {
  value: T
  label: string
  preview: ReactNode
}

/** A radio group of picture cards, as Proton's layout cards; arrow keys move between them. */
function Cards<T extends string>({ label, hint, value, cards, disabled, onChange }: { label: string; hint: string; value: T; cards: Card<T>[]; disabled: boolean; onChange: (value: T) => void }) {
  const refs = useRef<(HTMLButtonElement | null)[]>([])
  function onKeyDown(e: KeyboardEvent, index: number) {
    const step = e.key === 'ArrowRight' || e.key === 'ArrowDown' ? 1 : e.key === 'ArrowLeft' || e.key === 'ArrowUp' ? -1 : 0
    if (!step) return
    e.preventDefault()
    const next = (index + step + cards.length) % cards.length
    refs.current[next]?.focus()
    onChange(cards[next].value)
  }
  return (
    <section className="space-y-2">
      <h2 className="text-sm font-medium">{label}</h2>
      <p className="text-sm text-muted-foreground">{hint}</p>
      <div role="radiogroup" aria-label={label} className="flex flex-wrap gap-3">
        {cards.map((card, index) => {
          const on = card.value === value
          return (
            <button
              key={card.value}
              ref={(el) => {
                refs.current[index] = el
              }}
              type="button"
              role="radio"
              aria-checked={on}
              tabIndex={on ? 0 : -1}
              disabled={disabled}
              onClick={() => !on && onChange(card.value)}
              onKeyDown={(e) => onKeyDown(e, index)}
              className={cn(
                'flex w-40 flex-col gap-2 rounded-lg border p-2 text-left text-sm transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-ring',
                on ? 'border-primary bg-primary/5 font-medium' : 'border-border hover:border-muted-foreground/50',
              )}
            >
              <span aria-hidden className="block h-20 overflow-hidden rounded border border-border bg-background p-1.5">
                {card.preview}
              </span>
              {card.label}
            </button>
          )
        })}
      </div>
    </section>
  )
}

const bar = 'rounded-sm bg-muted-foreground/25'

function ListLines({ rows, tight }: { rows: number; tight?: boolean }) {
  return (
    <span className={cn('flex flex-col', tight ? 'gap-0.5' : 'gap-1.5')}>
      {Array.from({ length: rows }, (_, i) => (
        <span key={i} className={cn('block', bar, tight ? 'h-1' : 'h-2')} />
      ))}
    </span>
  )
}

const columnPreview = (
  <span className="flex h-full gap-1.5">
    <span className="w-2/5">
      <ListLines rows={5} />
    </span>
    <span className="flex-1 rounded-sm bg-primary/15" />
  </span>
)
const rowPreview = (
  <span className="flex h-full flex-col gap-1.5">
    <ListLines rows={3} />
    <span className="flex-1 rounded-sm bg-primary/15" />
  </span>
)
const popupPreview = (
  <span className="relative block h-full">
    <ListLines rows={5} />
    <span className="absolute bottom-0 right-1 h-3/4 w-2/5 rounded-t-sm border border-primary/40 bg-primary/15" />
  </span>
)
const maximizedPreview = (
  <span className="relative block h-full">
    <ListLines rows={5} />
    <span className="absolute inset-1 rounded-sm border border-primary/40 bg-primary/15" />
  </span>
)

/** Settings → Appearance (Proton's Layouts section): inbox layout, composer, density. */
export function AppearanceSettingsPage() {
  const { t } = useTranslation()
  const settings = useMailSettings()
  const update = useUpdateMailSettings()
  if (settings.isPending) return <LoadingPanel label={t('common.loading')} />
  if (settings.isError) return <Alert variant="error">{apiErrorMessage(settings.error, t('common.tryAgain'))}</Alert>
  const save = (change: Partial<MailSettings>) =>
    update.mutate(change, {
      onSuccess: () => toast.success(t('general.saved')),
      onError: (error) => toast.error(apiErrorMessage(error, t('common.tryAgain'))),
    })
  return (
    <PageBody>
      <PageHeader title={t('appearance.title')} />
      <div className="space-y-8">
        <Cards
          label={t('appearance.layout')}
          hint={t('appearance.layoutHint')}
          value={settings.data.viewLayout}
          disabled={update.isPending}
          onChange={(viewLayout) => save({ viewLayout })}
          cards={[
            { value: 'column', label: t('appearance.column'), preview: columnPreview },
            { value: 'row', label: t('appearance.row'), preview: rowPreview },
          ]}
        />
        <Cards
          label={t('appearance.composer')}
          hint={t('appearance.composerHint')}
          value={settings.data.composerMode}
          disabled={update.isPending}
          onChange={(composerMode) => save({ composerMode })}
          cards={[
            { value: 'popup', label: t('appearance.popup'), preview: popupPreview },
            { value: 'maximized', label: t('appearance.maximized'), preview: maximizedPreview },
          ]}
        />
        <Cards
          label={t('appearance.density')}
          hint={t('appearance.densityHint')}
          value={settings.data.density}
          disabled={update.isPending}
          onChange={(density) => save({ density })}
          cards={[
            { value: 'comfortable', label: t('appearance.comfortable'), preview: <ListLines rows={5} /> },
            { value: 'compact', label: t('appearance.compact'), preview: <ListLines rows={9} tight /> },
          ]}
        />
      </div>
    </PageBody>
  )
}
