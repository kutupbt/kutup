import { Check } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { toast } from 'sonner'
import { useDeleteGroup, useSaveGroup } from '@kutup/contacts-core/api'
import type { ContactGroup } from '@kutup/contacts-core/model'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Input } from '@kutup/ui/components/input'
import { Label } from '@kutup/ui/components/label'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { cn } from '@kutup/ui/lib/cn'

/** Proton's label palette, near enough: distinct in light and dark. */
export const GROUP_COLORS = ['#8080ff', '#db60d6', '#ec3e7c', '#f78400', '#5ec7b7', '#97c9c1', '#415df0', '#179fd9', '#1da583', '#9e329a'] as const

/** Creates a group, or renames, recolours or deletes one. */
export function GroupDialog({ open, onOpenChange, group }: { open: boolean; onOpenChange: (open: boolean) => void; group?: ContactGroup }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const save = useSaveGroup()
  const remove = useDeleteGroup()
  const [name, setName] = useState('')
  const [color, setColor] = useState<string>(GROUP_COLORS[0])
  const [confirming, setConfirming] = useState(false)

  useEffect(() => {
    if (!open) return
    setName(group?.name ?? '')
    setColor(group?.color ?? GROUP_COLORS[Math.floor(Math.random() * GROUP_COLORS.length)])
    save.reset()
    // eslint-disable-next-line react-hooks/exhaustive-deps -- reset once per opening
  }, [open, group])

  return (
    <>
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{group ? t('groups.editTitle') : t('groups.newTitle')}</DialogTitle>
          </DialogHeader>
          <form
            className="mt-4 space-y-4"
            onSubmit={(e) => {
              e.preventDefault()
              if (!name.trim()) return
              save.mutate(
                { id: group?.id, name: name.trim(), color },
                { onSuccess: () => { toast.success(group ? t('groups.saved') : t('groups.created')); onOpenChange(false) } },
              )
            }}
          >
            <div className="space-y-1.5">
              <Label htmlFor="group-name">{t('groups.name')}</Label>
              <Input id="group-name" value={name} onChange={(e) => setName(e.target.value)} maxLength={100} autoFocus required />
            </div>
            <fieldset className="space-y-2">
              <legend className="text-sm font-medium">{t('groups.color')}</legend>
              <div className="flex flex-wrap gap-2">
                {GROUP_COLORS.map((option) => (
                  <button
                    key={option}
                    type="button"
                    onClick={() => setColor(option)}
                    aria-label={option}
                    aria-pressed={color === option}
                    className={cn('grid size-8 place-items-center rounded-full text-white ring-offset-2 ring-offset-background', color === option && 'ring-2 ring-ring')}
                    style={{ background: option }}
                  >
                    {color === option ? <Check className="size-4" aria-hidden /> : null}
                  </button>
                ))}
              </div>
            </fieldset>
            {save.error ? <Alert variant="error">{apiErrorMessage(save.error, t('groups.saveFailed'))}</Alert> : null}
            <DialogFooter className="sm:justify-between">
              {group ? (
                <Button type="button" variant="ghost" onClick={() => setConfirming(true)}>{t('groups.delete')}</Button>
              ) : <span />}
              <div className="flex gap-2">
                <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>{t('common.cancel')}</Button>
                <Button type="submit" loading={save.isPending} disabled={!name.trim()}>{t('common.save')}</Button>
              </div>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
      {group ? (
        <ConfirmDestructive
          open={confirming}
          onOpenChange={setConfirming}
          title={t('groups.deleteTitle', { name: group.name })}
          description={t('groups.deleteDescription')}
          submit={t('groups.delete')}
          pending={remove.isPending}
          error={remove.error}
          errorFallback={t('groups.saveFailed')}
          onConfirm={() =>
            remove.mutate(group.id, {
              onSuccess: () => {
                setConfirming(false)
                onOpenChange(false)
                toast.success(t('groups.deleted'))
                void navigate('/')
              },
            })
          }
        />
      ) : null}
    </>
  )
}
