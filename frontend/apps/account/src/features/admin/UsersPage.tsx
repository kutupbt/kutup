import { Plus, ShieldCheck } from 'lucide-react'
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useNavigate } from 'react-router-dom'
import type { UserRow } from '@kutup/session/api-types'
import { Alert } from '@kutup/ui/components/alert'
import { Badge } from '@kutup/ui/components/badge'
import { Button } from '@kutup/ui/components/button'
import { Card } from '@kutup/ui/components/card'
import { Input } from '@kutup/ui/components/input'
import { PageBody, PageHeader } from '@kutup/ui/components/page'
import { Skeleton } from '@kutup/ui/components/skeleton'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@kutup/ui/components/table'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { formatBytes } from '@kutup/ui/lib/format'
import { useAdminStats, useAdminUsers } from './api'

function Stat({ label, value, detail }: { label: string; value: string | null; detail?: string | null }) {
  return (
    <Card className="p-4">
      <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{label}</p>
      <div className="mt-1 font-display text-2xl font-semibold">{value ?? <Skeleton className="h-8 w-20" />}</div>
      {detail ? <p className="mt-0.5 text-xs text-muted-foreground">{detail}</p> : null}
    </Card>
  )
}

export function UserStatus({ user }: { user: UserRow }) {
  const { t } = useTranslation()
  if (!user.isActive) return <Badge variant="neutral">{t('admin.users.disabled')}</Badge>
  if (user.isFirstLogin) return <Badge variant="warn">{t('admin.users.awaitingSetup')}</Badge>
  return <Badge variant="ok">{t('admin.users.active')}</Badge>
}

export function UsersPage() {
  const { t, i18n } = useTranslation()
  const navigate = useNavigate()
  const stats = useAdminStats()
  const users = useAdminUsers()
  const [query, setQuery] = useState('')
  const lang = i18n.language

  // Names are the one thing admins search by; the list is small enough to filter here.
  const rows = useMemo(() => {
    const q = query.trim().toLowerCase()
    const all = users.data ?? []
    return q ? all.filter((u) => u.email.toLowerCase().includes(q) || u.username.toLowerCase().includes(q)) : all
  }, [users.data, query])

  const capacity = stats.data?.storageTotalBytes
    ? t('admin.overview.ofCapacity', { total: formatBytes(stats.data.storageTotalBytes, lang) })
    : null

  return (
    <PageBody>
      <PageHeader
        title={t('admin.users.title')}
        description={t('admin.users.description')}
        actions={
          <Button asChild>
            <Link to="/admin/users/new">
              <Plus />
              {t('admin.users.new')}
            </Link>
          </Button>
        }
      />

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label={t('admin.overview.users')} value={stats.data ? String(stats.data.totalUsers) : null}
          detail={stats.data ? t('admin.overview.activeUsers', { count: stats.data.activeUsers }) : null} />
        <Stat label={t('admin.overview.storage')} value={stats.data ? formatBytes(stats.data.totalStorageUsedBytes, lang) : null} detail={capacity} />
        <Stat label={t('admin.overview.files')} value={stats.data ? stats.data.totalFiles.toLocaleString(lang) : null} />
        <Stat label={t('admin.overview.folders')} value={stats.data ? stats.data.totalCollections.toLocaleString(lang) : null} />
      </div>
      {stats.isError ? <Alert variant="error">{apiErrorMessage(stats.error, t('common.tryAgain'))}</Alert> : null}

      <Card className="p-0">
        <div className="border-b border-border p-3">
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={t('admin.users.search')}
            aria-label={t('admin.users.search')}
            className="max-w-xs"
          />
        </div>
        {users.isPending ? <LoadingPanel label={t('common.loading')} /> : null}
        {users.isError ? (
          <div className="p-4">
            <Alert variant="error">{apiErrorMessage(users.error, t('common.tryAgain'))}</Alert>
          </div>
        ) : null}
        {users.data && rows.length === 0 ? (
          <EmptyState
            title={query ? t('admin.users.noMatchTitle') : t('admin.users.emptyTitle')}
            description={query ? t('admin.users.noMatchDescription', { query }) : t('admin.users.emptyDescription')}
          />
        ) : null}
        {rows.length > 0 ? (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('admin.users.columns.user')}</TableHead>
                  <TableHead>{t('admin.users.columns.status')}</TableHead>
                  <TableHead>{t('admin.users.columns.drive')}</TableHead>
                  <TableHead>{t('admin.users.columns.chat')}</TableHead>
                  <TableHead>{t('admin.users.columns.twoFactor')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((u) => (
                  <TableRow
                    key={u.id}
                    className="cursor-pointer"
                    onClick={() => void navigate(`/admin/users/${u.id}`)}
                  >
                    <TableCell>
                      <Link to={`/admin/users/${u.id}`} className="font-medium text-foreground hover:underline" onClick={(e) => e.stopPropagation()}>
                        {u.email}
                      </Link>
                      <p className="flex items-center gap-1.5 text-sm text-muted-foreground">
                        {u.username}
                        {u.isAdmin ? (
                          <span className="inline-flex items-center gap-0.5 text-xs text-primary">
                            <ShieldCheck className="size-3" />
                            {t('admin.users.admin')}
                          </span>
                        ) : null}
                      </p>
                    </TableCell>
                    <TableCell><UserStatus user={u} /></TableCell>
                    <TableCell className="whitespace-nowrap text-sm">
                      {formatBytes(u.storageUsedBytes, lang)} / {formatBytes(u.storageQuotaBytes, lang)}
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-sm">
                      {formatBytes(u.chatStorageUsedBytes, lang)} / {formatBytes(u.chatStorageQuotaBytes, lang)}
                    </TableCell>
                    <TableCell className="text-sm">{u.totpEnabled ? t('admin.users.on') : t('admin.users.off')}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        ) : null}
      </Card>
    </PageBody>
  )
}
