import { MoreHorizontal } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import {
  addressStatuses,
  defaultAddressId,
  useAddAddress,
  useAddressDomains,
  useDeleteAddress,
  useDisableAddress,
  useEnableAddress,
  useGenerateMissingKeys,
  useOrderAddresses,
  useOwnAddresses,
  type AddressStatus,
} from '@kutup/mail-core/addresses'
import type { OwnAddressRow } from '@kutup/mail-core/api'
import { Alert } from '@kutup/ui/components/alert'
import { Badge } from '@kutup/ui/components/badge'
import { Button } from '@kutup/ui/components/button'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@kutup/ui/components/dropdown-menu'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { LoadingPanel } from '@kutup/ui/components/states'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@kutup/ui/components/table'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'

const BADGE: Record<AddressStatus, 'ok' | 'neutral' | 'warn' | 'danger'> = {
  default: 'neutral',
  active: 'ok',
  disabled: 'danger',
  missingKeys: 'warn',
}

/**
 * Settings → Identity and addresses → Addresses (Proton's): the account's
 * addresses in its order, their statuses, and Proton's actions: Generate
 * missing keys, Enable, Set as default, Disable, Delete address.
 */
export function AddressesSection() {
  const { t } = useTranslation()
  const addresses = useOwnAddresses()
  const domains = useAddressDomains()
  const order = useOrderAddresses()
  const enable = useEnableAddress()
  const disable = useDisableAddress()
  const remove = useDeleteAddress()
  const generate = useGenerateMissingKeys()
  const add = useAddAddress()
  const [adding, setAdding] = useState(false)
  const [disabling, setDisabling] = useState<OwnAddressRow | null>(null)
  const [deleting, setDeleting] = useState<OwnAddressRow | null>(null)
  const [missing, setMissing] = useState<OwnAddressRow[] | null>(null)

  if (addresses.isPending) return <LoadingPanel label={t('common.loading')} />
  if (addresses.isError) return <Alert variant="error">{apiErrorMessage(addresses.error, t('common.tryAgain'))}</Alert>
  const rows = addresses.data
  const defaultId = defaultAddressId(rows)
  const failed = (e: unknown) => toast.error(apiErrorMessage(e, t('common.tryAgain')))

  function setDefault(row: OwnAddressRow) {
    const ids = [row.id, ...rows.filter((r) => r.id !== row.id).map((r) => r.id)]
    order.mutate(ids, { onError: failed })
  }

  return (
    <section className="max-w-3xl space-y-3" aria-labelledby="addresses-heading">
      <div className="flex items-center justify-between gap-3">
        <h2 id="addresses-heading" className="text-base font-semibold">
          {t('addresses.title')}
        </h2>
        {domains.data?.length ? (
          <Button size="sm" onClick={() => setAdding(true)}>
            {t('addresses.add')}
          </Button>
        ) : null}
      </div>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>{t('addresses.address')}</TableHead>
            <TableHead>{t('addresses.status')}</TableHead>
            <TableHead className="w-12">
              <span className="sr-only">{t('addresses.actions')}</span>
            </TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((row) => {
            const isDefault = row.id === defaultId
            const custom = row.domainId !== null
            const statuses = addressStatuses(row, isDefault)
            const missingKeys = statuses.includes('missingKeys')
            // Proton's actions, in its order; none for the account's own address.
            const actions: { label: string; run: () => void; danger?: boolean }[] = []
            if (missingKeys) actions.push({ label: t('addresses.generateKeys'), run: () => setMissing([row]) })
            if (row.disabled) {
              actions.push({
                label: t('addresses.enable'),
                run: () => enable.mutate(row, { onSuccess: () => toast.success(t('addresses.enabled')), onError: failed }),
              })
            }
            if (!isDefault && !row.disabled && !missingKeys) actions.push({ label: t('addresses.setDefault'), run: () => setDefault(row) })
            if (custom && !row.disabled && !isDefault) actions.push({ label: t('addresses.disable'), run: () => setDisabling(row) })
            if (custom && !isDefault) actions.push({ label: t('addresses.delete'), run: () => setDeleting(row), danger: true })
            return (
              <TableRow key={row.id} data-testid="address-row">
                <TableCell className="font-medium">{row.address}</TableCell>
                <TableCell>
                  <span className="flex flex-wrap gap-1">
                    {statuses.map((status) => (
                      <Badge key={status} variant={BADGE[status]}>
                        {t(`addresses.statuses.${status}`)}
                      </Badge>
                    ))}
                  </span>
                </TableCell>
                <TableCell>
                  {actions.length ? (
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon" aria-label={t('addresses.actionsFor', { address: row.address })}>
                          <MoreHorizontal className="size-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        {actions.map((action) => (
                          <DropdownMenuItem key={action.label} className={action.danger ? 'text-destructive' : undefined} onSelect={action.run}>
                            {action.label}
                          </DropdownMenuItem>
                        ))}
                      </DropdownMenuContent>
                    </DropdownMenu>
                  ) : null}
                </TableCell>
              </TableRow>
            )
          })}
        </TableBody>
      </Table>

      <AddAddressDialog open={adding} onOpenChange={setAdding} add={add} domains={domains.data ?? []} />

      <ConfirmDestructive
        open={disabling !== null}
        onOpenChange={(open) => !open && setDisabling(null)}
        title={t('addresses.disableTitle')}
        description={t('addresses.disableBody', { address: disabling?.address ?? '' })}
        warning={t('addresses.disableSure')}
        submit={t('addresses.disableSubmit')}
        pending={disable.isPending}
        error={disable.error}
        errorFallback={t('common.tryAgain')}
        onConfirm={() =>
          disabling &&
          disable.mutate(disabling, {
            onSuccess: () => {
              setDisabling(null)
              toast.success(t('addresses.disabled'))
            },
          })
        }
      />

      <ConfirmDestructive
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={t('addresses.deleteTitle')}
        description={t('addresses.deleteBody', { address: deleting?.address ?? '' })}
        warning={t('addresses.deleteSure')}
        submit={t('addresses.deleteSubmit')}
        pending={remove.isPending}
        error={remove.error}
        errorFallback={t('common.tryAgain')}
        onConfirm={() =>
          deleting &&
          remove.mutate(deleting, {
            onSuccess: () => {
              setDeleting(null)
              toast.success(t('addresses.deleted'))
            },
          })
        }
      />

      <Dialog open={missing !== null} onOpenChange={(open) => !open && setMissing(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('addresses.generateKeys')}</DialogTitle>
          </DialogHeader>
          <p className="text-sm text-muted-foreground">{t('addresses.generateKeysInfo')}</p>
          <ul className="list-disc pl-5 text-sm">
            {(missing ?? []).map((row) => (
              <li key={row.id}>{row.address}</li>
            ))}
          </ul>
          {generate.isError ? <Alert variant="error">{apiErrorMessage(generate.error, t('common.tryAgain'))}</Alert> : null}
          <DialogFooter>
            <Button variant="outline" onClick={() => setMissing(null)}>
              {t('common.close')}
            </Button>
            <Button
              loading={generate.isPending}
              onClick={() =>
                missing &&
                generate.mutate(missing, {
                  onSuccess: () => {
                    setMissing(null)
                    toast.success(t('addresses.keysCreated'))
                  },
                })
              }
            >
              {t('addresses.submit')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </section>
  )
}

/** Proton's AddressModal: a name on one of the account's verified custom domains. */
function AddAddressDialog({
  open,
  onOpenChange,
  add,
  domains,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  add: ReturnType<typeof useAddAddress>
  domains: { id: string; name: string }[]
}) {
  const { t } = useTranslation()
  const [local, setLocal] = useState('')
  const [domainId, setDomainId] = useState('')
  const domain = domainId || domains[0]?.id || ''
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) {
          setLocal('')
          add.reset()
        }
        onOpenChange(next)
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('addresses.addTitle')}</DialogTitle>
        </DialogHeader>
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault()
            add.mutate(
              { local: local.trim(), domainId: domain },
              {
                onSuccess: () => {
                  setLocal('')
                  onOpenChange(false)
                  toast.success(t('addresses.added'))
                },
              },
            )
          }}
        >
          <Field label={t('addresses.address')}>
            {(props) => (
              <div className="flex items-center gap-2">
                <Input {...props} value={local} placeholder={t('addresses.address')} onChange={(e) => setLocal(e.target.value)} required />
                {domains.length > 1 ? (
                  <Select value={domain} onValueChange={setDomainId}>
                    <SelectTrigger className="w-48" data-testid="add-address-domain">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {domains.map((d) => (
                        <SelectItem key={d.id} value={d.id}>
                          @{d.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                ) : (
                  <span className="text-sm text-muted-foreground">@{domains[0]?.name}</span>
                )}
              </div>
            )}
          </Field>
          {add.isError ? <Alert variant="error">{apiErrorMessage(add.error, t('common.tryAgain'))}</Alert> : null}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" loading={add.isPending} disabled={!local.trim() || !domain}>
              {t('addresses.save')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
