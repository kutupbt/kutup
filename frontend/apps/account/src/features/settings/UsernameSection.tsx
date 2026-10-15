import { useEffect, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { foldName } from '@kutup/crypto/accountRename'
import { OneUseSecret } from '@kutup/session/reauth'
import { useRequiredSession } from '@kutup/session/store'
import { Alert } from '@kutup/ui/components/alert'
import { Badge } from '@kutup/ui/components/badge'
import { Button } from '@kutup/ui/components/button'
import { Card, CardContent } from '@kutup/ui/components/card'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { Mono } from '@kutup/ui/components/mono'
import { Section } from '@kutup/ui/components/page'
import { PasswordInput } from '@kutup/ui/components/password-input'
import { Skeleton } from '@kutup/ui/components/skeleton'
import { formatInstant, isFuture } from '@kutup/ui/lib/format'
import {
  checkName,
  USERNAME,
  useAccountNames,
  useDropName,
  useNameWindows,
  useRenameAccount,
  type AccountName,
  type NameCheck,
} from './rename'
import { nameErrorMessage } from './nameErrors'

/** The account's username, how to change it, and the names it holds. */
export function UsernameSection() {
  const { t } = useTranslation()
  const session = useRequiredSession()
  const [renaming, setRenaming] = useState<string | null>(null)

  return (
    <Section title={t('settings.account.username.title')} description={t('settings.account.username.description')}>
      <Card>
        <CardContent className="flex flex-wrap items-center gap-3 p-5">
          <div className="min-w-0 flex-1">
            {session.username ? <Mono>{session.username}</Mono> : t('settings.account.noUsername')}
          </div>
          <Button variant="outline" onClick={() => setRenaming('')} disabled={!session.username}>
            {t('settings.account.username.change')}
          </Button>
        </CardContent>
      </Card>
      <HeldNames onTakeBack={(name) => setRenaming(name)} />
      {renaming !== null ? (
        <RenameDialog initialName={renaming} onClose={() => setRenaming(null)} current={session.username ?? ''} address={session.address} />
      ) : null}
    </Section>
  )
}

type Checked = { state: 'idle' } | { state: 'checking' } | { state: 'same' } | { state: 'failed' } | { state: 'done'; result: NameCheck }

/** Checks the typed name a moment after typing stops. */
function useNameCheck(name: string, current: string): Checked {
  const [checked, setChecked] = useState<Checked>({ state: 'idle' })
  useEffect(() => {
    if (!USERNAME.test(name)) {
      setChecked({ state: 'idle' })
      return
    }
    setChecked({ state: 'checking' })
    const controller = new AbortController()
    const timer = window.setTimeout(() => {
      void (async () => {
        try {
          if ((await foldName(name)) === (await foldName(current))) {
            if (!controller.signal.aborted) setChecked({ state: 'same' })
            return
          }
          const result = await checkName(name, controller.signal)
          if (!controller.signal.aborted) setChecked({ state: 'done', result })
        } catch {
          if (!controller.signal.aborted) setChecked({ state: 'failed' })
        }
      })()
    }, 350)
    return () => {
      controller.abort()
      window.clearTimeout(timer)
    }
  }, [name, current])
  return checked
}

function RenameDialog({ initialName, current, address, onClose }: { initialName: string; current: string; address: string; onClose: () => void }) {
  const { t, i18n } = useTranslation()
  const [name, setName] = useState(initialName)
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const typed = name.trim()
  const checked = useNameCheck(typed, current)
  const windows = useNameWindows()
  const rename = useRenameAccount()
  const domain = address.slice(address.lastIndexOf('@') + 1)
  const available = checked.state === 'done' && checked.result.available ? checked.result : null

  const status = (() => {
    if (typed === '') return null
    if (!USERNAME.test(typed)) return { tone: 'error' as const, text: t('settings.account.rename.reason.invalid') }
    switch (checked.state) {
      case 'checking':
        return { tone: 'muted' as const, text: t('settings.account.rename.checking') }
      case 'same':
        return { tone: 'error' as const, text: t('settings.account.rename.same') }
      case 'failed':
        return { tone: 'error' as const, text: t('settings.account.rename.checkFailed') }
      case 'done': {
        const result = checked.result
        if (result.available) {
          return { tone: 'ok' as const, text: t(result.takeBack ? 'settings.account.rename.takeBack' : 'settings.account.rename.available') }
        }
        const reason = ['taken', 'held', 'reserved', 'invalid'].includes(result.reason) ? result.reason : 'taken'
        return { tone: 'error' as const, text: t(`settings.account.rename.reason.${reason}`) }
      }
      default:
        return null
    }
  })()

  const submit = async (event: FormEvent) => {
    event.preventDefault()
    if (!available || password === '' || rename.isPending) return
    setError(null)
    // A held name comes back as it was spelled, signed so: only when that
    // spelling is the name typed (folded), never another the server names.
    const spelling = available.takeBack ? available.spelling : undefined
    if (spelling && (await foldName(spelling)) !== (await foldName(typed))) {
      setError(t('settings.account.rename.failed'))
      return
    }
    const secret = new OneUseSecret(password)
    setPassword('')
    rename.mutate(
      { name: spelling ?? typed, needsKey: available.needsKey, password: secret },
      {
        onSuccess: (renamed) => {
          toast.success(t('settings.account.rename.done', { name: renamed.username }))
          onClose()
        },
        onError: (err) => setError(nameErrorMessage(t, err, i18n.language, t('settings.account.rename.failed'))),
      },
    )
  }

  return (
    <Dialog open onOpenChange={(open) => (!open && !rename.isPending ? onClose() : undefined)}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>{t('settings.account.rename.title')}</DialogTitle>
          <DialogDescription>{t('settings.account.rename.description')}</DialogDescription>
        </DialogHeader>
        <form className="mt-4 space-y-4" onSubmit={(event) => void submit(event)} noValidate>
          <Field label={t('settings.account.rename.newName')} description={t('settings.account.rename.hint')} required>
            {(field) => (
              <Input
                {...field}
                value={name}
                onChange={(e) => setName(e.target.value.toLowerCase())}
                autoComplete="off"
                autoCapitalize="none"
                spellCheck={false}
                autoFocus
              />
            )}
          </Field>
          {status ? (
            <p
              role="status"
              className={
                status.tone === 'ok' ? 'text-sm text-status-ok' : status.tone === 'error' ? 'text-sm text-destructive' : 'text-sm text-muted-foreground'
              }
            >
              {status.text}
              {available ? (
                <>
                  {' '}
                  {t('settings.account.rename.newAddress')} <Mono>{`${available.takeBack && available.spelling ? available.spelling : typed}@${domain}`}</Mono>
                </>
              ) : null}
            </p>
          ) : null}
          {available ? (
            windows.data ? (
              <Alert variant="warn">
                {t('settings.account.rename.warning', {
                  address,
                  receive: t('settings.account.rename.days', { count: windows.data.oldAddressReceiveDays }),
                  hold: t('settings.account.rename.days', { count: windows.data.nameHoldDays }),
                })}
              </Alert>
            ) : windows.isError ? (
              <Alert variant="error">{t('settings.account.rename.windowsFailed')}</Alert>
            ) : (
              <Skeleton className="h-16 w-full" />
            )
          ) : null}
          <Field label={t('settings.security.currentPassword')} required>
            {(field) => (
              <PasswordInput {...field} value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
            )}
          </Field>
          {error ? <Alert variant="error">{error}</Alert> : null}
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={onClose} disabled={rename.isPending}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" loading={rename.isPending} disabled={!available || !windows.data || password === ''}>
              {t('settings.account.rename.submit')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

/** The names the account left and still holds, each with its dates. */
function HeldNames({ onTakeBack }: { onTakeBack: (name: string) => void }) {
  const { t, i18n } = useTranslation()
  const names = useAccountNames()
  const drop = useDropName()
  const [dropping, setDropping] = useState<AccountName | null>(null)
  const session = useRequiredSession()
  const domain = session.address.slice(session.address.lastIndexOf('@') + 1)
  const held = names.data?.filter((name) => name.state === 'held') ?? []

  if (names.isPending) return <Skeleton className="mt-3 h-12 w-full" />
  if (names.isError) return <Alert variant="error">{t('settings.account.names.failed')}</Alert>
  if (held.length === 0) return null
  return (
    <div className="mt-4 space-y-2">
      <h3 className="text-sm font-medium">{t('settings.account.names.title')}</h3>
      <p className="text-sm text-muted-foreground">{t('settings.account.names.description')}</p>
      <Card>
        <CardContent className="p-0">
          <ul className="divide-y divide-border" aria-label={t('settings.account.names.title')}>
            {held.map((name) => {
              const receiving = isFuture(name.receiveUntil)
              return (
                <li key={name.name} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-5 py-3 text-sm">
                  <Mono>{`${name.name}@${domain}`}</Mono>
                  {receiving ? (
                    <Badge variant="neutral">
                      {t('settings.account.names.receivesUntil', { date: formatInstant(name.receiveUntil, i18n.language) })}
                    </Badge>
                  ) : (
                    <Badge>{t('settings.account.names.notReceiving')}</Badge>
                  )}
                  {name.freeAt ? (
                    <span className="text-muted-foreground">
                      {t('settings.account.names.freeAt', { date: formatInstant(name.freeAt, i18n.language) })}
                    </span>
                  ) : null}
                  <span className="ml-auto flex gap-2">
                    <Button variant="ghost" size="sm" onClick={() => onTakeBack(name.name)}>
                      {t('settings.account.names.takeBack')}
                    </Button>
                    {receiving ? (
                      <Button variant="outline" size="sm" onClick={() => setDropping(name)}>
                        {t('settings.account.names.drop')}
                      </Button>
                    ) : null}
                  </span>
                </li>
              )
            })}
          </ul>
        </CardContent>
      </Card>
      <ConfirmDestructive
        open={dropping !== null}
        onOpenChange={(open) => {
          if (!open) {
            setDropping(null)
            drop.reset()
          }
        }}
        title={t('settings.account.names.dropTitle', { address: dropping ? `${dropping.name}@${domain}` : '' })}
        description={t('settings.account.names.dropDescription', {
          date: formatInstant(dropping?.freeAt, i18n.language) ?? '',
        })}
        warning={t('settings.account.names.dropWarning')}
        submit={t('settings.account.names.drop')}
        pending={drop.isPending}
        error={drop.error ?? undefined}
        errorFallback={nameErrorMessage(t, drop.error, i18n.language, t('settings.account.names.errors.failed'))}
        passwordLabel={t('settings.security.currentPassword')}
        onConfirm={(password) => {
          if (!dropping) return
          const address = `${dropping.name}@${domain}`
          drop.mutate(
            { name: dropping.name, password: new OneUseSecret(password) },
            {
              onSuccess: () => {
                toast.success(t('settings.account.names.dropped', { address }))
                setDropping(null)
              },
            },
          )
        }}
      />
    </div>
  )
}
