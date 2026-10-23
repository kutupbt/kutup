import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { useOwnAddresses } from '@kutup/mail-core/addresses'
import { useCatchAll, type MailDomain } from '@kutup/mail-core/domains'
import { Badge } from '@kutup/ui/components/badge'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { LoadingPanel } from '@kutup/ui/components/states'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@kutup/ui/components/table'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { cn } from '@kutup/ui/lib/cn'

/**
 * Proton's catch-all modal: the domain's addresses, at most one ticked;
 * mail to any other name on the domain goes to it. Only an enabled address
 * can be it.
 */
export function CatchAllDialog({ domain, onClose }: { domain: MailDomain; onClose: () => void }) {
  const { t } = useTranslation()
  const addresses = useOwnAddresses()
  const catchAll = useCatchAll()
  const rows = (addresses.data ?? []).filter((row) => row.domainId === domain.id)

  function choose(addressId: string, on: boolean) {
    catchAll.mutate(
      { id: domain.id, addressId: on ? addressId : null },
      {
        onSuccess: () => toast.success(t('domains.catchAll.updated')),
        onError: (e) => toast.error(apiErrorMessage(e, t('common.tryAgain'))),
      },
    )
  }

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent data-testid="catch-all-dialog">
        <DialogHeader>
          <DialogTitle>{t('domains.catchAll.title')}</DialogTitle>
          <DialogDescription>{t('domains.catchAll.description')}</DialogDescription>
        </DialogHeader>
        {addresses.isPending ? (
          <LoadingPanel label={t('common.loading')} />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-10">
                  <span className="sr-only">{t('domains.catchAll.column')}</span>
                </TableHead>
                <TableHead>{t('addresses.address')}</TableHead>
                <TableHead>{t('addresses.status')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((row) => {
                const keyless = row.keys.length === 0 && row.keyList === null
                const usable = !row.disabled && !keyless
                return (
                  <TableRow key={row.id}>
                    <TableCell>
                      <Checkbox
                        aria-label={t('domains.catchAll.choose', { address: row.address })}
                        checked={domain.catchAllAddressId === row.id}
                        disabled={!usable || catchAll.isPending}
                        onCheckedChange={(checked) => choose(row.id, checked === true)}
                      />
                    </TableCell>
                    <TableCell className={cn(!usable && 'text-muted-foreground')}>{row.address}</TableCell>
                    <TableCell>
                      {keyless ? (
                        <Badge variant="warn">{t('addresses.statuses.missingKeys')}</Badge>
                      ) : row.disabled ? (
                        <Badge variant="danger">{t('addresses.statuses.disabled')}</Badge>
                      ) : (
                        <Badge variant="ok">{t('domains.catchAll.enabled')}</Badge>
                      )}
                    </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            {t('common.close')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
