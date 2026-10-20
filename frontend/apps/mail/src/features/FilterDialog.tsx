import { useRef, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import {
  filterProblems,
  useApplyFilters,
  useCreateFilter,
  useFilters,
  useUpdateFilter,
  type FilterDraft,
  type FilterField,
  type MailFilter,
} from '@kutup/mail-core/filters'
import { flattenFolders, usePlaces } from '@kutup/mail-core/places'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { cn } from '@kutup/ui/lib/cn'
import { ConditionsEditor } from './ConditionsEditor'
import { emptyCondition } from './conditions'
import { describeFilter } from './filterText'

const STEPS = ['name', 'conditions', 'actions', 'preview'] as const
type Step = (typeof STEPS)[number]

const FIELDS: FilterField[] = ['subject', 'sender', 'recipient', 'attachments']
/** "Do not move" in the folder picker (Radix Select takes no empty value). */
const NO_MOVE = '__none__'

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <fieldset className="space-y-2">
      <legend className="text-sm font-medium">{title}</legend>
      {children}
    </fieldset>
  )
}

/**
 * Proton's filter wizard (`FilterModal`): Name, Conditions, Actions,
 * Preview. Conditions on the subject, sender, recipient or attachments with
 * contains, is exactly, begins with, ends with or matches (and their
 * negations), all or any; actions move, label, mark read, star.
 */
export function FilterDialog({ filter, onClose }: { filter?: MailFilter; onClose: () => void }) {
  const { t } = useTranslation()
  const places = usePlaces()
  const filters = useFilters()
  const create = useCreateFilter()
  const update = useUpdateFilter()
  const applyFilters = useApplyFilters()
  const [step, setStep] = useState<Step>('name')
  const [draft, setDraft] = useState<FilterDraft>(
    filter
      ? { name: filter.name, match: filter.match, conditions: filter.conditions, actions: filter.actions }
      : { name: '', match: 'all', conditions: [emptyCondition()], actions: {} },
  )
  const [applyExisting, setApplyExisting] = useState(false)
  const [error, setError] = useState<string | undefined>()
  const index = STEPS.indexOf(step)
  const problems = filterProblems(draft)
  const folders = places.data ? flattenFolders(places.data.tree) : []
  const labels = places.data?.labels ?? []
  const pending = create.isPending || update.isPending
  // One save at a time: isPending lags a click behind, and a new filter
  // keeps one id, so a second request is refused rather than a duplicate.
  const saving = useRef(false)
  const [newId] = useState(() => crypto.randomUUID())

  function next() {
    setError(undefined)
    if (step === 'name') {
      if (problems.includes('name')) return setError(t('filters.nameRequired'))
      const taken = filters.data?.some((f) => f.id !== filter?.id && f.name.trim().toLocaleLowerCase() === draft.name.trim().toLocaleLowerCase())
      if (taken) return setError(t('filters.nameTaken'))
    }
    if (step === 'conditions' && problems.includes('conditions')) return setError(t('filters.conditionsRequired'))
    if (step === 'actions' && problems.includes('actions')) return setError(t('filters.actionsRequired'))
    setStep(STEPS[index + 1])
  }

  function save() {
    if (saving.current) return
    saving.current = true
    const failed = (e: unknown) => {
      saving.current = false
      toast.error(apiErrorMessage(e, t('common.tryAgain')))
    }
    const saved = (id: string) => {
      toast.success(t(filter ? 'filters.updated' : 'filters.created', { name: draft.name.trim() }))
      if (applyExisting) {
        applyFilters.mutate([id], {
          onSuccess: () => toast(t('filters.applying')),
          onError: failed,
        })
      }
      onClose()
    }
    if (filter) update.mutate({ id: filter.id, ...draft }, { onSuccess: () => saved(filter.id), onError: failed })
    else create.mutate({ ...draft, id: newId }, { onSuccess: saved, onError: failed })
  }

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{t(filter ? 'filters.edit' : 'filters.add')}</DialogTitle>
          <DialogDescription>{t('filters.dialogHint')}</DialogDescription>
        </DialogHeader>
        <ol className="mb-4 flex gap-2 text-xs" aria-label={t('filters.steps')}>
          {STEPS.map((s, i) => (
            <li
              key={s}
              aria-current={s === step ? 'step' : undefined}
              className={cn('flex-1 border-t-2 pt-1', i <= index ? 'border-primary font-medium text-foreground' : 'border-border text-muted-foreground')}
            >
              {t(`filters.step.${s}`)}
            </li>
          ))}
        </ol>

        {step === 'name' ? (
          <Field label={t('filters.name')} error={error}>
            {(props) => (
              <Input
                {...props}
                autoFocus
                maxLength={100}
                value={draft.name}
                onChange={(e) => setDraft((d) => ({ ...d, name: e.target.value }))}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault()
                    next()
                  }
                }}
              />
            )}
          </Field>
        ) : null}

        {step === 'conditions' ? (
          <ConditionsEditor
            value={{ match: draft.match, conditions: draft.conditions }}
            onChange={(conditions) => setDraft((d) => ({ ...d, ...conditions }))}
            fields={FIELDS}
            error={error}
          />
        ) : null}

        {step === 'actions' ? (
          <div className="space-y-5">
            <Section title={t('filters.moveTo')}>
              <Select
                value={draft.actions.folder ?? NO_MOVE}
                onValueChange={(v) => setDraft((d) => ({ ...d, actions: { ...d.actions, folder: v === NO_MOVE ? undefined : v } }))}
              >
                <SelectTrigger className="w-72" aria-label={t('filters.moveTo')}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={NO_MOVE}>{t('filters.doNotMove')}</SelectItem>
                  {(['inbox', 'archive', 'spam', 'trash'] as const).map((f) => (
                    <SelectItem key={f} value={f}>
                      {t(`folders.${f}`)}
                    </SelectItem>
                  ))}
                  {folders.map((f) => (
                    <SelectItem key={f.id} value={`custom:${f.id}`}>
                      {`${' '.repeat(f.depth - 1)}${f.name}`}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Section>
            <Section title={t('filters.labelAs')}>
              {labels.length ? (
                <div className="flex flex-wrap gap-x-4 gap-y-2">
                  {labels.map((l) => {
                    const on = draft.actions.labels?.includes(l.id) ?? false
                    return (
                      <label key={l.id} className="flex items-center gap-2 text-sm">
                        <Checkbox
                          checked={on}
                          onCheckedChange={(checked) =>
                            setDraft((d) => {
                              const now = d.actions.labels ?? []
                              const labels = checked === true ? [...now, l.id] : now.filter((id) => id !== l.id)
                              return { ...d, actions: { ...d.actions, labels: labels.length ? labels : undefined } }
                            })
                          }
                        />
                        <span className="size-2.5 rounded-full" style={{ backgroundColor: l.color }} aria-hidden />
                        {l.name}
                      </label>
                    )
                  })}
                </div>
              ) : (
                <p className="text-sm text-muted-foreground">{t('places.noLabels')}</p>
              )}
            </Section>
            <Section title={t('filters.markAs')}>
              <div className="flex gap-4">
                {(['markRead', 'star'] as const).map((key) => (
                  <label key={key} className="flex items-center gap-2 text-sm">
                    <Checkbox
                      checked={draft.actions[key] ?? false}
                      onCheckedChange={(checked) => setDraft((d) => ({ ...d, actions: { ...d.actions, [key]: checked === true || undefined } }))}
                    />
                    {t(`filters.${key}`)}
                  </label>
                ))}
              </div>
            </Section>
            {error ? <p className="text-sm text-destructive">{error}</p> : null}
          </div>
        ) : null}

        {step === 'preview' ? (
          <div className="space-y-4">
            <p className="rounded-md border border-border bg-muted/40 p-3 text-sm">{describeFilter(draft, places.data, t)}</p>
            <p className="text-xs text-muted-foreground">{t('filters.previewHint')}</p>
            <label className="flex items-center gap-2 text-sm">
              <Checkbox checked={applyExisting} onCheckedChange={(on) => setApplyExisting(on === true)} />
              {t('filters.applyExisting')}
            </label>
          </div>
        ) : null}

        <DialogFooter className="sm:justify-between">
          <Button variant="outline" onClick={() => (index === 0 ? onClose() : setStep(STEPS[index - 1]))}>
            {index === 0 ? t('common.cancel') : t('common.back')}
          </Button>
          {step === 'preview' ? (
            <Button onClick={save} disabled={pending || problems.length > 0}>
              {t('common.save')}
            </Button>
          ) : (
            <Button onClick={next}>{t('filters.next')}</Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
