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
import { useRotateTempPassword, useWipeUser } from '@/api/hooks/useAdmin'
import type { UserRow } from '@/types/api'

/**
 * The two admin "password reset" dialogs — deliberately separate actions,
 * never one "Reset password" button (design:
 * `docs/research/10-admin-password-reset.md`):
 *
 *  - **RotateTempPasswordDialog** — replaces the temp password of an account
 *    still in first-login state (no key material yet, destroys nothing).
 *  - **WipeUserDialog** — the destructive reset for a user who lost both
 *    password and recovery phrase: purges all data + keys, resets the
 *    account to first-login. Requires typing the user's email to confirm.
 */

interface DialogProps {
  user: UserRow | null
  onClose: () => void
}

export function RotateTempPasswordDialog({ user, onClose }: DialogProps) {
  const { t } = useTranslation()
  const rotate = useRotateTempPassword()
  const [password, setPassword] = useState('')

  useEffect(() => {
    if (user) setPassword('')
  }, [user])

  if (!user) return null
  const valid = password.length >= 8

  async function save() {
    if (!user || !valid) return
    await rotate.mutateAsync({ id: user.id, tempPassword: password })
    onClose()
  }

  return (
    <Dialog open={user !== null} onOpenChange={(open) => { if (!open) onClose() }}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>
            {t('admin.rotateTemp.title', 'Rotate temporary password')}
          </DialogTitle>
          <DialogDescription>
            {t(
              'admin.rotateTemp.desc',
              '{{email}} hasn’t completed setup yet, so no data is at risk. Set a new temporary password and share it with the user out-of-band.',
              { email: user.email },
            )}
          </DialogDescription>
        </DialogHeader>

        <Input
          type="text"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder={t('admin.rotateTemp.placeholder', 'New temporary password (min 8 chars)')}
          autoFocus
        />

        <DialogFooter>
          <Button variant="outline" type="button" onClick={onClose}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button type="button" onClick={save} disabled={!valid || rotate.isPending}>
            {rotate.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
            {t('admin.rotateTemp.confirm', 'Rotate password')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

export function WipeUserDialog({ user, onClose }: DialogProps) {
  const { t } = useTranslation()
  const wipe = useWipeUser()
  const [password, setPassword] = useState('')
  const [confirmEmail, setConfirmEmail] = useState('')

  useEffect(() => {
    if (user) {
      setPassword('')
      setConfirmEmail('')
    }
  }, [user])

  if (!user) return null
  const valid = password.length >= 8 && confirmEmail.trim().toLowerCase() === user.email.toLowerCase()

  async function save() {
    if (!user || !valid) return
    await wipe.mutateAsync({ id: user.id, tempPassword: password })
    onClose()
  }

  return (
    <Dialog open={user !== null} onOpenChange={(open) => { if (!open) onClose() }}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t('admin.wipe.title', 'Wipe {{email}}?', { email: user.email })}</DialogTitle>
          <DialogDescription>
            {t(
              'admin.wipe.desc',
              'Erases ALL of this user’s files and encryption keys — kutup’s end-to-end encryption means there is no backdoor and this cannot be undone. The account itself stays, reset to first-login with the temporary password below. Only for a user who lost both their password and their recovery phrase.',
            )}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3">
          <Input
            type="text"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder={t('admin.wipe.passwordPlaceholder', 'New temporary password (min 8 chars)')}
            autoFocus
          />
          <div>
            <div className="text-[12px] text-text-tertiary mb-1.5">
              {t('admin.wipe.confirmLabel', 'Type {{email}} to confirm', { email: user.email })}
            </div>
            <Input
              type="text"
              value={confirmEmail}
              onChange={(e) => setConfirmEmail(e.target.value)}
              placeholder={user.email}
            />
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" type="button" onClick={onClose}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button
            type="button"
            variant="destructive"
            onClick={save}
            disabled={!valid || wipe.isPending}
          >
            {wipe.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
            {t('admin.wipe.confirm', 'Wipe account')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
