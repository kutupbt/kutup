import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Icon, ICONS } from '@/components/mobile/Icon'
import { Surface } from '@/components/ui/surface'
import { useAdminSettings, useUpdateAdminSettings } from '@/api/hooks/useAdmin'
import { AdminFederationPolicyCard } from '@/components/admin/AdminFederationPolicyCard'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'

const GIB = 1024 * 1024 * 1024
const MAX_RETENTION_DAYS = 3650

function validRetentionDays(value: string): boolean {
  const days = Number(value)
  return Number.isInteger(days) && days >= 0 && days <= MAX_RETENTION_DAYS
}

/**
 * MobileAdminSettingsTab — responsive controls for registration and the
 * unified federation control plane.
 *
 *   Registration
 *     ▢ Public registration   [switch]
 *
 * The design's other groups (Defaults / Security / Storage backend /
 * Danger zone) need backend additions before we can ship them — see the
 * PR 12 section of the plan file for the full list. They're explicitly
 * NOT rendered here so the page doesn't lie about what the backend can do.
 */
export function MobileAdminSettingsTab() {
  const { t } = useTranslation()
  const { data: settings } = useAdminSettings()
  const update = useUpdateAdminSettings()
  const [chatQuotaGiB, setChatQuotaGiB] = useState('2')
  const [mailboxRetentionDays, setMailboxRetentionDays] = useState('30')
  const [mediaRetentionDays, setMediaRetentionDays] = useState('45')

  useEffect(() => {
    if (!settings) return
    setChatQuotaGiB(String(settings.defaultChatStorageQuotaBytes / GIB))
    setMailboxRetentionDays(String(settings.chatMailboxRetentionDays))
    setMediaRetentionDays(String(settings.chatMediaDeliveryRetentionDays))
  }, [settings])

  const publicReg = !!settings?.registrationEnabled

  return (
    <div className="px-3.5 pt-4 pb-8">
      <div className="text-[11.5px] font-semibold tracking-[0.06em] uppercase text-text-tertiary px-1 pb-2">
        {t('mobile.admin.settings.registrationGroup', 'Registration')}
      </div>
      <Surface className="mb-4">
        <div className="flex items-center gap-3 px-3.5 py-3">
          <div className="w-[30px] h-[30px] rounded-[9px] bg-surface-sunken text-text-secondary flex items-center justify-center shrink-0">
            <Icon d={ICONS.userPlus} size={15} />
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-[13.5px] font-medium text-text-primary">
              {t('mobile.admin.settings.publicReg', 'Public registration')}
            </div>
            <div className="text-[11.5px] text-text-tertiary mt-0.5">
              {t(
                'mobile.admin.settings.publicRegSub',
                'Anyone can create an account from the sign-up page',
              )}
            </div>
          </div>
          {/* iOS-style toggle */}
          <button
            type="button"
            role="switch"
            aria-checked={publicReg}
            onClick={() => update.mutate({ registrationEnabled: !publicReg })}
            disabled={update.isPending}
            className={
              'w-[42px] h-6 rounded-xl p-0.5 flex items-center transition-colors cursor-pointer shrink-0 ' +
              (publicReg ? 'bg-primary' : 'bg-border')
            }
          >
            <div
              className="w-5 h-5 rounded-full bg-white shadow-sm transition-transform"
              style={{ transform: publicReg ? 'translateX(18px)' : 'translateX(0)' }}
            />
          </button>
        </div>
      </Surface>

      <div className="text-[11.5px] font-semibold tracking-[0.06em] uppercase text-text-tertiary px-1 pb-2">
        {t('mobile.admin.settings.chatStorageGroup', 'Chat storage')}
      </div>
      <Surface className="mb-4">
        <div className="px-3.5 py-3 space-y-2">
          <div>
            <div className="text-[13.5px] font-medium text-text-primary">
              {t('admin.settings.defaultChatQuota', 'New account quota')}
            </div>
            <div className="text-[11.5px] text-text-tertiary mt-0.5">
              {t(
                'admin.settings.defaultChatQuotaMobileSub',
                'Encrypted Chat history and media; existing accounts are unchanged.',
              )}
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Input
              type="number"
              min="0.01"
              step="0.25"
              value={chatQuotaGiB}
              onChange={(event) => setChatQuotaGiB(event.target.value)}
            />
            <span className="text-xs text-text-tertiary">GiB</span>
            <Button
              size="sm"
              disabled={
                update.isPending ||
                !Number.isFinite(Number(chatQuotaGiB)) ||
                Number(chatQuotaGiB) <= 0
              }
              onClick={() =>
                update.mutate({
                  defaultChatStorageQuotaBytes: Math.round(Number(chatQuotaGiB) * GIB),
                })
              }
            >
              {t('common.save', 'Save')}
            </Button>
          </div>
        </div>
        <div className="border-t border-border-light px-3.5 py-3 space-y-2">
          <div>
            <div className="text-[13.5px] font-medium text-text-primary">
              {t('admin.settings.messageDeliveryRetention', 'Message delivery retention')}
            </div>
            <div className="text-[11.5px] text-text-tertiary mt-0.5">
              {t(
                'admin.settings.messageDeliveryRetentionMobileSub',
                'Unread message ciphertext; 0 keeps it indefinitely.',
              )}
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Input
              type="number"
              min="0"
              max={MAX_RETENTION_DAYS}
              step="1"
              value={mailboxRetentionDays}
              onChange={(event) => setMailboxRetentionDays(event.target.value)}
            />
            <span className="text-xs text-text-tertiary">{t('common.days', 'days')}</span>
            <Button
              size="sm"
              disabled={update.isPending || !validRetentionDays(mailboxRetentionDays)}
              onClick={() => update.mutate({
                chatMailboxRetentionDays: Number(mailboxRetentionDays),
              })}
            >
              {t('common.save', 'Save')}
            </Button>
          </div>
        </div>
        <div className="border-t border-border-light px-3.5 py-3 space-y-2">
          <div>
            <div className="text-[13.5px] font-medium text-text-primary">
              {t('admin.settings.mediaDeliveryRetention', 'Media delivery retention')}
            </div>
            <div className="text-[11.5px] text-text-tertiary mt-0.5">
              {t(
                'admin.settings.mediaDeliveryRetentionMobileSub',
                'Temporary delivery copies only; 0 keeps them indefinitely.',
              )}
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Input
              type="number"
              min="0"
              max={MAX_RETENTION_DAYS}
              step="1"
              value={mediaRetentionDays}
              onChange={(event) => setMediaRetentionDays(event.target.value)}
            />
            <span className="text-xs text-text-tertiary">{t('common.days', 'days')}</span>
            <Button
              size="sm"
              disabled={update.isPending || !validRetentionDays(mediaRetentionDays)}
              onClick={() => update.mutate({
                chatMediaDeliveryRetentionDays: Number(mediaRetentionDays),
              })}
            >
              {t('common.save', 'Save')}
            </Button>
          </div>
        </div>
      </Surface>

      <AdminFederationPolicyCard compact className="mb-4" />

      <p className="text-[12px] text-text-tertiary px-1">
        {t(
          'mobile.admin.settings.moreSoonNote',
          'More admin controls — required 2FA, storage backend, and danger-zone actions — land as the backend grows. The desktop /admin page covers anything missing here.',
        )}
      </p>
    </div>
  )
}
