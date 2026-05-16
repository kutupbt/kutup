import { useTranslation } from 'react-i18next'

/**
 * Admin-role pill — only renders when the user is an admin. Non-admins get
 * nothing (the absence of the pill is the signal, per the design).
 */
export function RolePill({ isAdmin }: { isAdmin: boolean }) {
  const { t } = useTranslation()
  if (!isAdmin) return null
  return (
    <span className="text-[10px] font-bold tracking-[0.04em] uppercase bg-primary-faint text-primary px-1.5 py-0.5 rounded-md">
      {t('mobile.admin.rolePillAdmin', 'Admin')}
    </span>
  )
}
