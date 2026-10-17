import { Users } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useMyGroups } from '@kutup/mail-core/groups'
import { SidebarNavLink } from '@kutup/ui/components/app-shell'

/**
 * Group membership in the settings menu, only for a member of a group and
 * not while the list loads (Proton: available when memberships is not
 * empty). The page opened directly keeps its empty state.
 */
export function GroupMembershipNavLink() {
  const { t } = useTranslation()
  const groups = useMyGroups()
  if (!groups.data?.length) return null
  return <SidebarNavLink to="/settings/groups" icon={<Users />} label={t('nav.groupMembership')} />
}
