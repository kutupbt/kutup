import { lazy, Suspense, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { useCreateFilter, useFilters, useUpdateFilter, type MailFilter } from '@kutup/mail-core/filters'
import { usePlaces } from '@kutup/mail-core/places'
import { filterToSieve, SIEVE_FILTER_REQUIRE, sieveToFilters, type SieveImport } from '@kutup/mail-core/sieve'
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@kutup/ui/components/alert-dialog'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import type { SieveMark } from './SieveEditor'
import { sievePlaces } from './sieveFiles'
import { problemText } from './sieveProblems'

const SieveEditor = lazy(() => import('./SieveEditor'))

/** How long typing pauses before the script is checked. */
const CHECK_DELAY_MS = 300

/** What the script says, checked: the one filter it holds, or why it can't be saved. */
interface Checked {
  read: SieveImport
  /** The script holds no filter at all, or more than one. */
  count: 'none' | 'one' | 'several'
}

function check(script: string, places: ReturnType<typeof sievePlaces>): Checked {
  const read = sieveToFilters(script, places)
  const count = read.filters.length === 0 ? 'none' : read.filters.length === 1 ? 'one' : 'several'
  return { read, count }
}

/**
 * A filter written as Sieve (docs/plans/mail-sieve-editor.md), as Proton's
 * `AdvancedFilterModal`: a name and one script, checked as it is typed. Kutup
 * runs its own filters, so the script must be one filter Kutup can hold;
 * what is saved is that filter, and its script is written afresh the next
 * time (formatting and comments are not kept).
 */
export function SieveFilterDialog({ filter, onClose }: { filter?: MailFilter; onClose: () => void }) {
  const { t } = useTranslation()
  const places = usePlaces()
  const filters = useFilters()
  const create = useCreateFilter()
  const update = useUpdateFilter()
  const where = useMemo(() => sievePlaces(places.data), [places.data])
  const initial = useMemo(
    () => (filter ? filterToSieve(filter, where) : `${SIEVE_FILTER_REQUIRE}\n\n# ${t('sieve.editor.templateHint')}\n`),
    // eslint-disable-next-line react-hooks/exhaustive-deps -- written once, when the dialog opens with the places known
    [places.isSuccess],
  )
  const [name, setName] = useState(filter?.name ?? '')
  const [script, setScript] = useState<string | null>(null)
  const text = script ?? initial
  const [checked, setChecked] = useState<Checked>(() => check(initial, where))
  const [nameError, setNameError] = useState<string | undefined>()
  const [asking, setAsking] = useState(false)
  const saving = useRef(false)
  const [newId] = useState(() => crypto.randomUUID())
  const pending = create.isPending || update.isPending

  useEffect(() => {
    const timer = setTimeout(() => setChecked(check(text, where)), CHECK_DELAY_MS)
    return () => clearTimeout(timer)
  }, [text, where])

  const marks: SieveMark[] = useMemo(() => checked.read.problems.map((p) => ({ from: p.from, to: p.to, message: problemText(p, t) })), [checked, t])
  const scriptError =
    checked.read.problems.length > 0
      ? undefined
      : checked.count === 'none'
        ? t('sieve.editor.noFilter')
        : checked.count === 'several'
          ? t('sieve.editor.oneFilter')
          : undefined
  const valid = checked.read.problems.length === 0 && checked.count === 'one'
  const dirty = name !== (filter?.name ?? '') || (script !== null && script !== initial)

  function close() {
    if (dirty && !pending) setAsking(true)
    else onClose()
  }

  function save() {
    if (saving.current) return
    const trimmed = name.trim()
    if (!trimmed) return setNameError(t('filters.nameRequired'))
    const taken = filters.data?.some((f) => f.id !== filter?.id && f.name.trim().toLocaleLowerCase() === trimmed.toLocaleLowerCase())
    if (taken) return setNameError(t('filters.nameTaken'))
    setNameError(undefined)
    // Saved as checked now, not as the last pause in typing left it.
    const now = check(text, where)
    setChecked(now)
    if (now.read.problems.length > 0 || now.count !== 'one') return
    const [read] = now.read.filters
    const draft = { name: trimmed, match: read.match, conditions: read.conditions, actions: read.actions }
    saving.current = true
    const failed = (e: unknown) => {
      saving.current = false
      toast.error(apiErrorMessage(e, t('common.tryAgain')))
    }
    const saved = () => {
      toast.success(t(filter ? 'filters.updated' : 'filters.created', { name: trimmed }))
      onClose()
    }
    if (filter) update.mutate({ id: filter.id, ...draft }, { onSuccess: saved, onError: failed })
    else create.mutate({ ...draft, id: newId }, { onSuccess: saved, onError: failed })
  }

  return (
    <>
      <Dialog open onOpenChange={(open) => !open && close()}>
        <DialogContent className="flex h-svh max-h-svh w-full max-w-none flex-col sm:h-auto sm:max-h-[90vh] sm:max-w-3xl" data-testid="sieve-filter-dialog">
          <DialogHeader>
            <DialogTitle>{t(filter ? 'sieve.editor.editTitle' : 'sieve.editor.addTitle')}</DialogTitle>
            <DialogDescription>{t('sieve.editor.description')}</DialogDescription>
          </DialogHeader>
          <Field label={t('filters.name')} error={nameError}>
            {(props) => <Input {...props} autoFocus={!filter} maxLength={100} value={name} onChange={(e) => setName(e.target.value)} />}
          </Field>
          <div className="flex min-h-64 flex-1 flex-col gap-1 sm:h-80 sm:flex-none">
            {places.isSuccess ? (
              <Suspense fallback={<p className="text-sm text-muted-foreground">{t('common.loading')}</p>}>
                <SieveEditor value={initial} onChange={setScript} marks={marks} label={t('sieve.script')} />
              </Suspense>
            ) : (
              <p className="text-sm text-muted-foreground">{t('common.loading')}</p>
            )}
          </div>
          <p className="text-xs text-muted-foreground">{t('sieve.editor.notKept')}</p>
          <div role="status" aria-live="polite" className="max-h-32 overflow-y-auto text-sm" data-testid="sieve-filter-problems">
            {checked.read.problems.length > 0 ? (
              <ul className="list-disc space-y-1 pl-4 text-destructive">
                {checked.read.problems.map((problem, i) => (
                  <li key={i}>{problemText(problem, t)}</li>
                ))}
              </ul>
            ) : scriptError ? (
              <p className="text-destructive">{scriptError}</p>
            ) : null}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={close} disabled={pending}>
              {t('common.cancel')}
            </Button>
            <Button onClick={save} disabled={pending || !valid}>
              {t('common.save')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <AlertDialog open={asking} onOpenChange={setAsking}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('sieve.editor.discardTitle')}</AlertDialogTitle>
            <AlertDialogDescription>{t('sieve.editor.discardBody')}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('sieve.editor.keepEditing')}</AlertDialogCancel>
            <Button variant="destructive" onClick={onClose}>
              {t('sieve.editor.discard')}
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
