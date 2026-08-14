import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { Loader2 } from 'lucide-react'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { useUpdateUser } from '@/api/hooks/useAdmin'
import { cn } from '@/lib/utils'
import type { UserRow } from '@/types/api'

/**
 * AdminEditQuotaDialog edits the independent Drive and Chat storage limits.
 *
 * Layout matches the design's create-user dialog quota presets row: a row
 * of preset chips (1 / 5 / 10 / 50 / 100 GB) above a free-form input. The
 * input is the source of truth; clicking a preset just sets the input.
 * Both values are committed in one idempotent admin update.
 *
 * Note the disabled-state nuance: we keep the button enabled even when
 * `gb === currentGB` (some admins want to nudge by 0 to refresh the row);
 * the underlying mutation is idempotent and cheap.
 */

const PRESETS_GB = [1, 5, 10, 50, 100] as const
const GB = 1024 * 1024 * 1024

interface AdminEditQuotaDialogProps {
  user: UserRow | null
  onClose: () => void
}

export function AdminEditQuotaDialog({ user, onClose }: AdminEditQuotaDialogProps) {
  const { t } = useTranslation()
  const updateUser = useUpdateUser()
  const [driveGb, setDriveGb] = useState('')
  const [chatGb, setChatGb] = useState('')

  // Reset the input whenever a new user is targeted
  useEffect(() => {
    if (user) {
      setDriveGb(String(user.storageQuotaBytes / GB))
      setChatGb(String(user.chatStorageQuotaBytes / GB))
    }
  }, [user])

  if (!user) return null

  const drive = parseFloat(driveGb)
  const chat = parseFloat(chatGb)
  const valid = Number.isFinite(drive) && drive > 0 && Number.isFinite(chat) && chat > 0

  async function save() {
    if (!user || !valid) return
    await updateUser.mutateAsync({
      id: user.id,
      body: {
        storageQuotaBytes: Math.round(drive * GB),
        chatStorageQuotaBytes: Math.round(chat * GB),
      },
    })
    onClose()
  }

  return (
    <Dialog open={user !== null} onOpenChange={(open) => { if (!open) onClose() }}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t('admin.editQuota.title', 'Edit storage quotas')}</DialogTitle>
          <DialogDescription>
            {t('admin.editQuota.desc', 'For {{email}} — applies immediately.', {
              email: user.email,
            })}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <QuotaInput
            label={t('admin.editQuota.drive', 'Drive storage')}
            value={driveGb}
            onChange={setDriveGb}
            autoFocus
          />
          <QuotaInput
            label={t('admin.editQuota.chat', 'Chat history and media')}
            value={chatGb}
            onChange={setChatGb}
          />
        </div>

        <DialogFooter>
          <Button variant="outline" type="button" onClick={onClose}>
            {t('admin.editQuota.cancel', 'Cancel')}
          </Button>
          <Button
            type="button"
            onClick={save}
            disabled={!valid || updateUser.isPending}
          >
            {updateUser.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
            {t('admin.editQuota.save', 'Save')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function QuotaInput({
  label,
  value,
  onChange,
  autoFocus = false,
}: {
  label: string
  value: string
  onChange: (value: string) => void
  autoFocus?: boolean
}) {
  return (
    <div className="space-y-2">
      <div className="text-sm font-medium text-text-primary">{label}</div>
      <div className="flex gap-1.5">
        {PRESETS_GB.map((preset) => (
          <button
            key={preset}
            type="button"
            onClick={() => onChange(String(preset))}
            className={cn(
              'flex-1 h-8 rounded-lg text-[12px] font-medium cursor-pointer border transition-colors',
              parseFloat(value) === preset
                ? 'bg-primary text-white border-primary'
                : 'bg-surface text-text-primary border-border hover:bg-surface-raised',
            )}
          >
            {preset} GB
          </button>
        ))}
      </div>
      <div className="flex items-center gap-2">
        <Input
          type="number"
          min="0.01"
          step="0.01"
          value={value}
          onChange={(event) => onChange(event.target.value)}
          placeholder="2"
          autoFocus={autoFocus}
        />
        <span className="text-sm text-text-tertiary">GB</span>
      </div>
    </div>
  )
}
