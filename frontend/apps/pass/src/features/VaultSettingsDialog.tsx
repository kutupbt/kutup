import { Gauge, KeyRound } from 'lucide-react'
import { useEffect, useId, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@kutup/ui/components/tabs'
import { Textarea } from '@kutup/ui/components/textarea'
import { defaultKdf, kdfProblem, KDF_LIMITS, scaledForTarget } from '../lib/kdf'
import type { VaultSession } from '../sync/vaultSession'
import { timeKdf } from '../vault/client'
import type { KdfInput, KdfMinimums, VaultView } from '../vault/types'

export type SettingsTab = 'general' | 'encryption' | 'security'

const MIB = 1024 * 1024
const KINDS: KdfInput['kind'][] = ['argon2id', 'argon2d', 'aesKdf']

/**
 * A vault's settings (docs/plans/pass-gaps-2.md, P2), as KeePassXC's
 * Database settings: General (description, default user name, recycle bin,
 * history limits), Encryption (key derivation with a one-second benchmark,
 * compression) and Security (the key, through its own dialog).
 */
export function VaultSettingsDialog({
  open,
  onOpenChange,
  session,
  view,
  minimums,
  tab,
  onTabChange,
  onChangeKey,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  session: VaultSession
  view: VaultView
  minimums: KdfMinimums
  tab: SettingsTab
  onTabChange: (tab: SettingsTab) => void
  onChangeKey: (() => void) | null
}) {
  const { t } = useTranslation()
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>{t('settings.title')}</DialogTitle>
          <DialogDescription>{t('settings.description')}</DialogDescription>
        </DialogHeader>
        <Tabs value={tab} onValueChange={(value) => onTabChange(value as SettingsTab)} className="mt-2">
          <TabsList>
            <TabsTrigger value="general">{t('settings.general')}</TabsTrigger>
            <TabsTrigger value="encryption">{t('settings.encryption')}</TabsTrigger>
            {onChangeKey ? <TabsTrigger value="security">{t('settings.security')}</TabsTrigger> : null}
          </TabsList>
          <TabsContent value="general">{open ? <GeneralTab session={session} view={view} onDone={() => onOpenChange(false)} /> : null}</TabsContent>
          <TabsContent value="encryption">{open ? <EncryptionTab session={session} view={view} minimums={minimums} onDone={() => onOpenChange(false)} /> : null}</TabsContent>
          {onChangeKey ? (
            <TabsContent value="security" className="space-y-3 pt-2">
              <p className="text-sm text-muted-foreground">{t('settings.securityDescription')}</p>
              <Button
                variant="outline"
                onClick={() => {
                  onOpenChange(false)
                  onChangeKey()
                }}
              >
                <KeyRound />
                {t('changeKey.open')}
              </Button>
            </TabsContent>
          ) : null}
        </Tabs>
      </DialogContent>
    </Dialog>
  )
}

/** A whole number from a field, or null when it isn't one. */
function whole(text: string): number | null {
  const value = Number(text)
  return text.trim() !== '' && Number.isInteger(value) ? value : null
}

function GeneralTab({ session, view, onDone }: { session: VaultSession; view: VaultView; onDone: () => void }) {
  const { t } = useTranslation()
  const id = useId()
  const [description, setDescription] = useState(view.description)
  const [userName, setUserName] = useState(view.defaultUserName)
  const [bin, setBin] = useState(view.recycleBinEnabled)
  const [itemsLimited, setItemsLimited] = useState(view.historyMaxItems !== null)
  const [items, setItems] = useState(String(view.historyMaxItems ?? 10))
  const [sizeLimited, setSizeLimited] = useState(view.historyMaxSize !== null)
  const [sizeMib, setSizeMib] = useState(String(view.historyMaxSize === null ? 6 : Math.max(1, Math.round(view.historyMaxSize / MIB))))
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const itemCount = whole(items)
  const sizeCount = whole(sizeMib)
  const itemsBad = itemsLimited && (itemCount === null || itemCount < 0 || itemCount > 1000)
  const sizeBad = sizeLimited && (sizeCount === null || sizeCount < 1 || sizeCount > 1024)
  const maxItems = itemsLimited ? itemCount : null
  const maxSize = sizeLimited && sizeCount !== null ? sizeCount * MIB : null
  // A lower limit trims every entry's history when saved.
  const trims =
    (maxItems !== null && (view.historyMaxItems === null || maxItems < view.historyMaxItems)) ||
    (maxSize !== null && (view.historyMaxSize === null || maxSize < view.historyMaxSize))

  return (
    <form
      className="space-y-4 pt-2"
      onSubmit={(event) => {
        event.preventDefault()
        if (itemsBad || sizeBad) return
        setPending(true)
        setError(null)
        session
          .apply({
            op: 'updateVault',
            name: view.name,
            description,
            defaultUserName: userName,
            recycleBinEnabled: bin,
            history: { maxItems, maxSize },
          })
          .then(
            () => {
              toast.success(t('settings.saved'))
              onDone()
            },
            () => setError(t('entry.saveFailed')),
          )
          .finally(() => setPending(false))
      }}
    >
      <Field label={t('settings.vaultDescription')}>{(field) => <Textarea {...field} value={description} onChange={(e) => setDescription(e.target.value)} rows={3} />}</Field>
      <Field label={t('settings.defaultUserName')} description={t('settings.defaultUserNameHint')}>
        {(field) => <Input {...field} value={userName} onChange={(e) => setUserName(e.target.value)} maxLength={256} />}
      </Field>
      <div className="flex items-start gap-2">
        <Checkbox id={`${id}-bin`} checked={bin} onCheckedChange={(v) => setBin(v === true)} />
        <label htmlFor={`${id}-bin`} className="text-sm">
          {t('settings.recycleBin')}
          <span className="block text-muted-foreground">{t('settings.recycleBinHint')}</span>
        </label>
      </div>
      <fieldset className="space-y-3">
        <legend className="text-sm font-medium">{t('settings.history')}</legend>
        <div className="flex items-center gap-2">
          <Checkbox id={`${id}-items`} checked={itemsLimited} onCheckedChange={(v) => setItemsLimited(v === true)} />
          <label htmlFor={`${id}-items`} className="text-sm">
            {t('settings.historyItems')}
          </label>
          <Input className="ml-auto w-24" type="number" min={0} max={1000} step={1} inputMode="numeric" value={items} onChange={(e) => setItems(e.target.value)} disabled={!itemsLimited} aria-label={t('settings.historyItems')} aria-invalid={itemsBad} />
        </div>
        <div className="flex items-center gap-2">
          <Checkbox id={`${id}-size`} checked={sizeLimited} onCheckedChange={(v) => setSizeLimited(v === true)} />
          <label htmlFor={`${id}-size`} className="text-sm">
            {t('settings.historySize')}
          </label>
          <Input className="ml-auto w-24" type="number" min={1} max={1024} step={1} inputMode="numeric" value={sizeMib} onChange={(e) => setSizeMib(e.target.value)} disabled={!sizeLimited} aria-label={t('settings.historySize')} aria-invalid={sizeBad} />
        </div>
        {itemsBad || sizeBad ? <p className="text-sm text-destructive">{t('settings.historyRange')}</p> : null}
        {trims && !itemsBad && !sizeBad ? <Alert variant="warn">{t('settings.historyTrims')}</Alert> : null}
      </fieldset>
      {error ? <Alert variant="error">{error}</Alert> : null}
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onDone} disabled={pending}>
          {t('common.cancel')}
        </Button>
        <Button type="submit" loading={pending} disabled={itemsBad || sizeBad}>
          {t('common.save')}
        </Button>
      </DialogFooter>
    </form>
  )
}

function EncryptionTab({ session, view, minimums, onDone }: { session: VaultSession; view: VaultView; minimums: KdfMinimums; onDone: () => void }) {
  const { t } = useTranslation()
  const id = useId()
  const [kdf, setKdf] = useState<KdfInput>(view.kdf ?? defaultKdf('argon2id', minimums))
  const [compression, setCompression] = useState(view.compression)
  const [timing, setTiming] = useState(false)
  const [measured, setMeasured] = useState<number | null>(null)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => setMeasured(null), [kdf])

  const problem = kdfProblem(kdf, minimums)
  const number = (text: string) => (text.trim() === '' ? Number.NaN : Number(text))
  const benchmark = () => {
    if (problem === 'outOfRange') return
    setTiming(true)
    setError(null)
    // One run as set, then the passes or rounds for about a second.
    void timeKdf(kdf)
      .then((ms) => {
        const next = scaledForTarget(kdf, ms, minimums)
        setKdf(next)
        return timeKdf(next)
      })
      .then((ms) => setMeasured(ms))
      .catch(() => setError(t('settings.benchmarkFailed')))
      .finally(() => setTiming(false))
  }

  return (
    <form
      className="space-y-4 pt-2"
      onSubmit={(event) => {
        event.preventDefault()
        if (problem) return
        setPending(true)
        setError(null)
        session
          .apply({ op: 'setVaultConfig', kdf, compression, minimums })
          .then(
            () => {
              toast.success(t('settings.saved'))
              onDone()
            },
            () => setError(t('entry.saveFailed')),
          )
          .finally(() => setPending(false))
      }}
    >
      <Field label={t('settings.kdf')}>
        {(field) => (
          <Select value={kdf.kind} onValueChange={(kind) => setKdf(defaultKdf(kind as KdfInput['kind'], minimums))}>
            <SelectTrigger id={field.id}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {KINDS.map((kind) => (
                <SelectItem key={kind} value={kind}>
                  {t(`settings.kdfKind.${kind}`)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
      </Field>
      {kdf.kind === 'aesKdf' ? (
        <Field label={t('settings.rounds')} description={t('settings.aesHint')}>
          {(field) => <Input {...field} type="number" min={minimums.aesKdfRounds} max={KDF_LIMITS.aesKdfRounds} step={1} inputMode="numeric" value={Number.isNaN(kdf.rounds) ? '' : kdf.rounds} onChange={(e) => setKdf({ ...kdf, rounds: number(e.target.value) })} />}
        </Field>
      ) : (
        <div className="grid gap-3 sm:grid-cols-3">
          <Field label={t('settings.memory')}>
            {(field) => <Input {...field} type="number" min={minimums.argon2MemoryMib} max={KDF_LIMITS.argon2MemoryMib} step={1} inputMode="numeric" value={Number.isNaN(kdf.memoryMib) ? '' : kdf.memoryMib} onChange={(e) => setKdf({ ...kdf, memoryMib: number(e.target.value) })} />}
          </Field>
          <Field label={t('settings.iterations')}>
            {(field) => <Input {...field} type="number" min={minimums.argon2Iterations} max={KDF_LIMITS.argon2Iterations} step={1} inputMode="numeric" value={Number.isNaN(kdf.iterations) ? '' : kdf.iterations} onChange={(e) => setKdf({ ...kdf, iterations: number(e.target.value) })} />}
          </Field>
          <Field label={t('settings.parallelism')}>
            {(field) => <Input {...field} type="number" min={1} max={KDF_LIMITS.argon2Parallelism} step={1} inputMode="numeric" value={Number.isNaN(kdf.parallelism) ? '' : kdf.parallelism} onChange={(e) => setKdf({ ...kdf, parallelism: number(e.target.value) })} />}
          </Field>
        </div>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <Button type="button" variant="outline" size="sm" onClick={benchmark} loading={timing} disabled={problem === 'outOfRange'}>
          <Gauge />
          {t('settings.benchmark')}
        </Button>
        {measured !== null ? <span className="text-sm text-muted-foreground">{t('settings.measured', { seconds: (measured / 1000).toFixed(1) })}</span> : null}
      </div>
      {problem === 'belowMinimum' ? (
        <Alert variant="error">
          {t('settings.belowMinimum', { memory: minimums.argon2MemoryMib, iterations: minimums.argon2Iterations, rounds: minimums.aesKdfRounds.toLocaleString() })}
        </Alert>
      ) : null}
      {problem === 'outOfRange' ? <Alert variant="error">{t('settings.outOfRange')}</Alert> : null}
      <p className="text-sm text-muted-foreground">{t('settings.slowWarning')}</p>
      <div className="flex items-start gap-2">
        <Checkbox id={`${id}-compression`} checked={compression} onCheckedChange={(v) => setCompression(v === true)} />
        <label htmlFor={`${id}-compression`} className="text-sm">
          {t('settings.compression')}
        </label>
      </div>
      {error ? <Alert variant="error">{error}</Alert> : null}
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onDone} disabled={pending}>
          {t('common.cancel')}
        </Button>
        <Button type="submit" loading={pending} disabled={problem !== null || timing}>
          {t('common.save')}
        </Button>
      </DialogFooter>
    </form>
  )
}
