import { useTranslation } from 'react-i18next'
import { Icon, ICONS } from '@/components/mobile/Icon'
import { useAdminSettings, useUpdateAdminSettings, useAdminStats } from '@/api/hooks/useAdmin'
import { formatBytes } from '@/lib/format'
import { cn } from '@/lib/utils'
import { AdminFederationPolicyCard } from '@/components/admin/AdminFederationPolicyCard'

/**
 * AdminSettingsTab — Settings surface for the desktop admin redesign.
 *
 * The page combines general site settings with the unified federation control
 * plane. Defaults / Security toggles / Danger zone still need backend
 * support and remain hidden.
 *
 * What IS rendered:
 *  - **Registration** — single toggle, wired to `useUpdateAdminSettings`.
 *  - **Federation** — per-feature modes, trust floors, peer trust, and domain rules.
 *  - **Storage backend** — driver (static label, SeaweedFS S3-compatible),
 *    a real "Storage used: X of Y · Z free" row + bar if the new
 *    `storageTotalBytes` value is configured (env-var `STORAGE_TOTAL_BYTES`),
 *    and a static "Encryption: AES-256-GCM (per-file)" row.
 */
export function AdminSettingsTab() {
  const { t } = useTranslation()
  const { data: settings } = useAdminSettings()
  const update = useUpdateAdminSettings()
  const { data: stats } = useAdminStats()

  const publicReg = !!settings?.registrationEnabled

  // Storage card "used": prefer the real SeaweedFS-probe figure
  // (storageBackendUsedBytes — actual on-disk bytes); fall back to the DB
  // sum of per-account usage when no probe is available. A non-zero
  // backend figure means the probe ran, so both numbers are real.
  const backendUsed = stats?.storageBackendUsedBytes ?? 0
  const dbUsed = stats?.totalStorageUsedBytes ?? 0
  const haveProbe = backendUsed > 0
  const totalUsed = haveProbe ? backendUsed : dbUsed
  const totalCapacity = stats?.storageTotalBytes ?? 0
  const havePct = totalCapacity > 0
  const pct = havePct ? Math.min((totalUsed / totalCapacity) * 100, 100) : 0
  const free = havePct ? Math.max(0, totalCapacity - totalUsed) : 0
  const over = pct > 75

  return (
    <div className="px-8 py-6 max-w-[800px]">
      {/* Registration */}
      <SettingsCard
        title={t('admin.settings.registrationTitle', 'Registration')}
        description={t(
          'admin.settings.registrationDesc',
          'Control who can sign up for this Kutup instance.',
        )}
      >
        <SettingsRow
          label={t('mobile.admin.settings.publicReg', 'Public registration')}
          sub={t(
            'mobile.admin.settings.publicRegSub',
            'Anyone can create an account from the sign-up page',
          )}
          last
        >
          <Switch
            value={publicReg}
            disabled={update.isPending || !settings}
            onChange={() => update.mutate({ registrationEnabled: !publicReg })}
          />
        </SettingsRow>
      </SettingsCard>

      <AdminFederationPolicyCard className="mb-5" />

      {/* Storage backend */}
      <SettingsCard
        title={t('admin.settings.storageTitle', 'Storage backend')}
        description={t(
          'admin.settings.storageDesc',
          'Read-only — change via your kutup.yml config / env vars.',
        )}
      >
        <SettingsRow label={t('admin.settings.driver', 'Driver')}>
          <span className="text-[13px] text-text-primary font-medium">
            {t('admin.settings.driverValue', 'SeaweedFS · S3-compatible')}
          </span>
        </SettingsRow>

        {/* Storage used row — only renders the bar when capacity is configured */}
        <div className="px-[18px] py-3.5 border-b border-border-light">
          <div className="flex items-start justify-between mb-2">
            <div>
              <div className="text-[13.5px] font-medium text-text-primary">
                {haveProbe
                  ? t('admin.settings.storageUsedDisk', 'Storage used (disk)')
                  : t('admin.settings.storageUsed', 'Storage used')}
              </div>
              <div className="text-[12px] text-text-tertiary mt-0.5">
                {havePct
                  ? t('admin.settings.storageUsedBody', '{{used}} of {{total}} · {{free}} free', {
                      used: formatBytes(totalUsed),
                      total: formatBytes(totalCapacity),
                      free: formatBytes(free),
                    })
                  : t(
                      'admin.settings.storageUsedUnknown',
                      'Capacity unknown — set STORAGE_TOTAL_BYTES or SEAWEEDFS_MASTER_URL to display.',
                    )}
              </div>
            </div>
            {havePct && (
              <span
                className={cn(
                  'text-[14px] font-semibold',
                  over ? 'text-warning' : 'text-text-primary',
                )}
              >
                {pct.toFixed(0)}%
              </span>
            )}
          </div>
          {havePct && (
            <div className="h-[6px] bg-surface-sunken rounded-[3px] overflow-hidden">
              <div
                className={cn('h-full rounded-[3px]', over ? 'bg-warning' : 'bg-primary')}
                style={{ width: `${Math.max(pct, 2)}%` }}
              />
            </div>
          )}
        </div>

        <SettingsRow label={t('admin.settings.storageEncryption', 'Encryption')} last>
          <span className="text-[13px] text-success font-medium inline-flex items-center gap-1">
            <Icon d={ICONS.lock} size={12} />
            AES-256-GCM (per-file)
          </span>
        </SettingsRow>
      </SettingsCard>

      <p className="text-[12px] text-text-tertiary mt-4">
        {t(
          'admin.settings.moreSoonNote',
          'More admin controls — required 2FA, quota defaults, danger-zone actions — land as the backend grows.',
        )}
      </p>
    </div>
  )
}

/* ── SettingsCard ───────────────────────────────────────────────── */

interface SettingsCardProps {
  title: string
  description?: string
  children: React.ReactNode
}

function SettingsCard({ title, description, children }: SettingsCardProps) {
  return (
    <div className="bg-surface border border-border-light rounded-[var(--radius-lg)] overflow-hidden mb-5">
      <div className="px-[18px] py-3.5 border-b border-border-light">
        <div className="text-[14px] font-semibold text-text-primary">{title}</div>
        {description && (
          <div className="text-[12.5px] text-text-tertiary mt-0.5">{description}</div>
        )}
      </div>
      {children}
    </div>
  )
}

/* ── SettingsRow ────────────────────────────────────────────────── */

interface SettingsRowProps {
  label: string
  sub?: string
  children: React.ReactNode
  last?: boolean
}

function SettingsRow({ label, sub, children, last }: SettingsRowProps) {
  return (
    <div
      className={cn(
        'flex items-center gap-4 px-[18px] py-3.5',
        !last && 'border-b border-border-light',
      )}
    >
      <div className="flex-1 min-w-0">
        <div className="text-[13.5px] font-medium text-text-primary">{label}</div>
        {sub && <div className="text-[12px] text-text-tertiary mt-0.5">{sub}</div>}
      </div>
      <div className="shrink-0">{children}</div>
    </div>
  )
}

/* ── Switch ─────────────────────────────────────────────────────── */

interface SwitchProps {
  value: boolean
  onChange: () => void
  disabled?: boolean
}

function Switch({ value, onChange, disabled }: SwitchProps) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={value}
      onClick={onChange}
      disabled={disabled}
      className={cn(
        'w-[42px] h-6 rounded-xl p-0.5 flex items-center transition-colors cursor-pointer shrink-0',
        value ? 'bg-primary' : 'bg-border',
        disabled && 'opacity-50 cursor-not-allowed',
      )}
    >
      <div
        className="w-5 h-5 rounded-full bg-white shadow-sm transition-transform"
        style={{ transform: value ? 'translateX(18px)' : 'translateX(0)' }}
      />
    </button>
  )
}
