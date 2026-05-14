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
 * AdminEditQuotaDialog — small dialog for editing a single user's storage
 * quota. Opens from the per-row ⋯ menu's "Edit quota" action.
 *
 * Layout matches the design's create-user dialog quota presets row: a row
 * of preset chips (1 / 5 / 10 / 50 / 100 GB) above a free-form input. The
 * input is the source of truth; clicking a preset just sets the input.
 * Save calls `useUpdateUser` with `storageQuotaBytes`.
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
  const [gb, setGb] = useState('')

  // Reset the input whenever a new user is targeted
  useEffect(() => {
    if (user) setGb(String(user.storageQuotaBytes / GB))
  }, [user])

  if (!user) return null

  const n = parseFloat(gb)
  const valid = !isNaN(n) && n > 0

  async function save() {
    if (!user || !valid) return
    await updateUser.mutateAsync({
      id: user.id,
      body: { storageQuotaBytes: Math.round(n * GB) },
    })
    onClose()
  }

  return (
    <Dialog open={user !== null} onOpenChange={(open) => { if (!open) onClose() }}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t('admin.editQuota.title', 'Edit storage quota')}</DialogTitle>
          <DialogDescription>
            {t('admin.editQuota.desc', 'For {{email}} — applies immediately.', {
              email: user.email,
            })}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3">
          <div className="flex gap-1.5">
            {PRESETS_GB.map((p) => {
              const active = parseFloat(gb) === p
              return (
                <button
                  key={p}
                  type="button"
                  onClick={() => setGb(String(p))}
                  className={cn(
                    'flex-1 h-9 rounded-lg text-[12.5px] font-medium cursor-pointer border transition-colors',
                    active
                      ? 'bg-primary text-white border-primary'
                      : 'bg-surface text-text-primary border-border hover:bg-surface-raised',
                  )}
                >
                  {p} GB
                </button>
              )
            })}
          </div>
          <div className="flex items-center gap-2">
            <Input
              type="number"
              min="1"
              step="1"
              value={gb}
              onChange={(e) => setGb(e.target.value)}
              placeholder={t('admin.editQuota.placeholder', 'e.g. 25')}
              autoFocus
            />
            <span className="text-sm text-text-tertiary">GB</span>
          </div>
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
