import { Globe, ImageUp, RotateCcw } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { cn } from '@kutup/ui/lib/cn'
import { ICON_TYPES, IconReadError, iconPngOf, iconSource, toIconPng } from '../lib/icons'
import { iconDomain, siteIconThroughKutup, useSiteIconsMode } from '../sync/siteIcons'
import type { VaultView } from '../vault/types'

/**
 * Gives an entry or a group its own picture (a KeePass custom icon, kept in
 * the vault): one the vault already has, an uploaded image, or, for an
 * entry, its website's icon through Kutup; or the default icon again.
 */
export function IconDialog({
  open,
  onOpenChange,
  name,
  view,
  current,
  address,
  onChoose,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** The entry's title or the group's name. */
  name: string
  view: VaultView
  /** The id of the picture it has now. */
  current: string | null
  /** An entry's URL, for its website's icon; none for a group. */
  address?: string
  /** A PNG (base64), or null for the default icon. */
  onChoose: (data: string | null) => Promise<void>
}) {
  const { t } = useTranslation()
  const upload = useRef<HTMLInputElement>(null)
  const mode = useSiteIconsMode()
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const domain = address ? iconDomain(address) : null

  useEffect(() => {
    if (open) setError(null)
  }, [open])

  const choose = async (data: () => Promise<string | null>) => {
    setPending(true)
    setError(null)
    try {
      await onChoose(await data())
      onOpenChange(false)
    } catch (failure) {
      setError(failure instanceof IconReadError ? t('icons.unreadable') : failure instanceof NoSiteIconError ? t('icons.noSiteIcon') : t('entry.saveFailed'))
    } finally {
      setPending(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={(next) => !pending && onOpenChange(next)}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t('icons.title', { name })}</DialogTitle>
          <DialogDescription>{t('icons.description')}</DialogDescription>
        </DialogHeader>
        <div className="mt-4 space-y-4">
          {view.customIcons.length > 0 ? (
            <section aria-labelledby="vault-icons-label" className="space-y-2">
              <h3 id="vault-icons-label" className="text-sm font-medium">
                {t('icons.inVault')}
              </h3>
              <ul className="grid max-h-48 grid-cols-8 gap-1.5 overflow-y-auto" aria-labelledby="vault-icons-label">
                {view.customIcons.map((icon, index) => (
                  <li key={icon.id}>
                    <button
                      type="button"
                      disabled={pending}
                      aria-pressed={icon.id === current}
                      aria-label={t('icons.pick', { number: index + 1 })}
                      onClick={() => void choose(() => iconPngOf(icon))}
                      className={cn('grid size-9 place-items-center rounded-md border border-border bg-muted hover:bg-accent', icon.id === current && 'ring-2 ring-primary')}
                    >
                      <img src={iconSource(icon)} alt="" className="size-6 object-contain" />
                    </button>
                  </li>
                ))}
              </ul>
            </section>
          ) : null}
          <div className="flex flex-wrap gap-2">
            <Button type="button" variant="outline" size="sm" disabled={pending} onClick={() => upload.current?.click()}>
              <ImageUp />
              {t('icons.upload')}
            </Button>
            {domain && mode === 'kutup' ? (
              <Button
                type="button"
                variant="outline"
                size="sm"
                disabled={pending}
                onClick={() =>
                  void choose(async () => {
                    const found = await siteIconThroughKutup(domain)
                    if (!found) throw new NoSiteIconError()
                    return toIconPng(await (await fetch(found)).blob())
                  })
                }
              >
                <Globe />
                {t('icons.fromWebsite')}
              </Button>
            ) : null}
            {current ? (
              <Button type="button" variant="outline" size="sm" disabled={pending} onClick={() => void choose(() => Promise.resolve(null))}>
                <RotateCcw />
                {t('icons.reset')}
              </Button>
            ) : null}
          </div>
          <input
            ref={upload}
            type="file"
            accept={ICON_TYPES}
            className="sr-only"
            tabIndex={-1}
            aria-label={t('icons.upload')}
            onChange={(e) => {
              const file = e.target.files?.[0]
              e.target.value = ''
              if (file) void choose(() => toIconPng(file))
            }}
          />
          {error ? <Alert variant="error">{error}</Alert> : null}
        </div>
        <DialogFooter className="mt-6">
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={pending}>
            {t('common.close')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

class NoSiteIconError extends Error {}
