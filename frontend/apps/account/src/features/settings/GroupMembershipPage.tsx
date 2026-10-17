import { Inbox, Settings2, Users } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMailAccount } from '@kutup/mail-core/api'
import { useMyGroups, type MailGroup } from '@kutup/mail-core/groups'
import { GroupDialog } from '@kutup/mail-core/ui/GroupDialog'
import { appUrl } from '@kutup/session/apps'
import { useRequiredSession } from '@kutup/session/store'
import { Alert } from '@kutup/ui/components/alert'
import { Badge } from '@kutup/ui/components/badge'
import { Button } from '@kutup/ui/components/button'
import { PageBody, PageHeader } from '@kutup/ui/components/page'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'

/**
 * The Mail groups you belong to (docs/plans/mail-groups.md), as Proton's
 * Group membership: distribution lists, whose mail lands in your own inbox,
 * and shared mailboxes, which open in Mail. Owners and managers run their
 * members and settings here; members see who is in it.
 */
export function GroupMembershipPage() {
  const { t } = useTranslation()
  const session = useRequiredSession()
  const account = useMailAccount()
  const groups = useMyGroups()
  const [open, setOpen] = useState<string | null>(null)

  return (
    <PageBody>
      <PageHeader title={t('groupMembership.title')} description={t('groupMembership.description')} />
      {groups.isPending ? (
        <LoadingPanel label={t('common.loading')} />
      ) : groups.isError ? (
        <Alert variant="error">{apiErrorMessage(groups.error, t('common.tryAgain'))}</Alert>
      ) : groups.data.length === 0 ? (
        <EmptyState title={t('groupMembership.emptyTitle')} description={t('groupMembership.emptyDescription')} />
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
                  <a href={appUrl('mail', `/g/${group.id}/inbox`)}>
                    <Inbox />
                    {t('mailGroups.openMailbox')}
                  </a>
                </Button>
              ) : null}
              <Button variant="ghost" size="sm" onClick={() => setOpen(group.id)}>
                <Settings2 />
                {manages(group) ? t('mailGroups.manage') : t('mailGroups.viewMembers')}
              </Button>
            </li>
          ))}
        </ul>
      )}
      {open ? (
        <GroupDialog
          groupId={open}
          ownKeys={account.data?.groupHolder ?? null}
          administrator={session.isAdmin}
          onClose={() => setOpen(null)}
        />
      ) : null}
    </PageBody>
  )
}

function manages(group: MailGroup): boolean {
  return group.myRole === 'owner' || group.myRole === 'manager'
}
