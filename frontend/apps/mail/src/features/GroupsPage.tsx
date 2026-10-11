import { Inbox, Settings2, Users } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { useMailAccount } from '@kutup/mail-core/api'
import { useMyGroups } from '@kutup/mail-core/groups'
import { GroupDialog } from '@kutup/mail-core/ui/GroupDialog'
import { useRequiredSession } from '@kutup/session/store'
import { Alert } from '@kutup/ui/components/alert'
import { Badge } from '@kutup/ui/components/badge'
import { Button } from '@kutup/ui/components/button'
import { PageBody, PageHeader } from '@kutup/ui/components/page'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'

/**
 * The groups you belong to (docs/plans/mail-groups.md): distribution lists,
 * whose mail lands in your own inbox, and shared mailboxes, which open beside
 * it. Owners and managers run their members and settings here.
 */
export function GroupsPage() {
  const { t } = useTranslation()
  const session = useRequiredSession()
  const account = useMailAccount()
  const groups = useMyGroups()
  const [open, setOpen] = useState<string | null>(null)

  return (
    <PageBody>
      <PageHeader title={t('mailGroups.title')} description={t('mailGroups.pageDescription')} />
      {groups.isPending ? (
        <LoadingPanel label={t('common.loading')} />
      ) : groups.isError ? (
        <Alert variant="error">{apiErrorMessage(groups.error, t('common.tryAgain'))}</Alert>
      ) : groups.data.length === 0 ? (
        <EmptyState title={t('mailGroups.emptyTitle')} description={t('mailGroups.emptyDescription')} />
      ) : (
        <ul className="divide-y divide-border rounded-lg border border-border">
          {groups.data.map((group) => (
            <li key={group.id} className="flex flex-wrap items-center gap-3 px-4 py-3">
              <Users className="size-4 shrink-0 text-muted-foreground" aria-hidden />
              <span className="min-w-0 flex-1">
                <span className="block truncate font-medium">{group.displayName || group.address}</span>
                <span className="block truncate text-xs text-muted-foreground">
                  {group.address} · {t(`mailGroups.kind.${group.kind}`)} · {t('mailGroups.membersCount', { count: group.memberCount })}
                </span>
              </span>
              {group.myRole ? <Badge variant="neutral">{t(`mailGroups.role.${group.myRole}`)}</Badge> : null}
              {group.kind === 'shared' ? (
                <Button variant="outline" size="sm" asChild>
                  <Link to={`/g/${group.id}/inbox`}>
                    <Inbox />
                    {t('mailGroups.openMailbox')}
                  </Link>
                </Button>
              ) : null}
              <Button variant="ghost" size="sm" onClick={() => setOpen(group.id)}>
                <Settings2 />
                {group.myRole === 'owner' || group.myRole === 'manager' ? t('mailGroups.manage') : t('mailGroups.viewMembers')}
              </Button>
            </li>
          ))}
        </ul>
      )}
      {open ? (
        <GroupDialog
          groupId={open}
          ownKeys={account.data ? [account.data.key, ...account.data.olderKeys] : null}
          administrator={session.isAdmin}
          onClose={() => setOpen(null)}
        />
      ) : null}
    </PageBody>
  )
}
