import { Users } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import type { MailGroup } from '@kutup/mail-core/groups'
import { SidebarNavLink } from '@kutup/ui/components/app-shell'

/**
 * The sidebar's Groups item, only for a member of a group (as Proton shows
 * Group membership only to members) and not while the list loads. The page
 * itself, opened directly, keeps its empty state.
 */
export function GroupsNavLink({ groups }: { groups: readonly MailGroup[] | undefined }) {
  const { t } = useTranslation()
  if (!groups?.length) return null
  return <SidebarNavLink to="/groups" icon={<Users />} label={t('mailGroups.title')} />
}
