import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Checkbox } from './checkbox'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from './dialog'
import { Label } from './label'

/** One shortcut: what it does and its keys (each shown as a key cap). */
export interface Shortcut {
  name: string
  keys: string[]
}

export interface ShortcutSection {
  name: string
  shortcuts: Shortcut[]
}

function Kbd({ children }: { children: string }) {
  return (
    <kbd className="inline-flex h-6 min-w-[1.5rem] items-center justify-center rounded border bg-muted px-1.5 font-mono text-xs text-foreground shadow-sm">
      {children}
    </kbd>
  )
}

/**
 * The account's switch for keyboard shortcuts in every app (Proton's
 * "Keyboard shortcuts" setting), for an app's own shortcuts list.
 */
export function ShortcutsSwitch({ enabled, onEnabledChange }: { enabled: boolean; onEnabledChange: (enabled: boolean) => Promise<void> }) {
  const { t } = useTranslation()
  const [failed, setFailed] = useState(false)
  return (
    <div className="flex items-start gap-2 rounded-md border p-3">
      <Checkbox
        id="shortcuts-enabled"
        checked={enabled}
        onCheckedChange={(value) => {
          setFailed(false)
          onEnabledChange(value === true).catch(() => setFailed(true))
        }}
        className="mt-0.5"
        data-testid="shortcuts-enabled"
      />
      <div className="space-y-0.5">
        <Label htmlFor="shortcuts-enabled">{t('shortcutsSetting.toggle')}</Label>
        <p className="text-xs text-muted-foreground">{t('shortcutsSetting.toggleHint')}</p>
        {failed ? (
          <p className="text-xs text-destructive" role="alert">
            {t('shortcutsSetting.saveFailed')}
          </p>
        ) : null}
      </div>
    </div>
  )
}

/**
 * An app's keyboard shortcuts and the account's switch for all of them
 * (Proton's shortcuts modal: `?` opens it). The switch is the account's: it
 * turns shortcuts on or off in every app.
 */
export function ShortcutsDialog({
  open,
  onOpenChange,
  sections,
  enabled,
  onEnabledChange,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  sections: ShortcutSection[]
  enabled: boolean
  onEnabledChange: (enabled: boolean) => Promise<void>
}) {
  const { t } = useTranslation()
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent data-testid="shortcuts-dialog">
        <DialogHeader>
          <DialogTitle>{t('shortcutsSetting.title')}</DialogTitle>
          <DialogDescription>{t('shortcutsSetting.description')}</DialogDescription>
        </DialogHeader>
        <ShortcutsSwitch enabled={enabled} onEnabledChange={onEnabledChange} />
        {sections.map((section) => (
          <section key={section.name} className="space-y-1">
            <h3 className="text-sm font-medium">{section.name}</h3>
            <ul className="divide-y divide-border">
              {section.shortcuts.map((shortcut) => (
                <li key={shortcut.name} className="flex items-center justify-between gap-4 py-2 text-sm">
                  <span>{shortcut.name}</span>
                  <span className="flex shrink-0 items-center gap-1">
                    {shortcut.keys.map((key, i) => (
                      <span key={key} className="flex items-center gap-1">
                        {i > 0 ? <span className="text-muted-foreground">{t('shortcutsSetting.or')}</span> : null}
                        <Kbd>{key}</Kbd>
                      </span>
                    ))}
                  </span>
                </li>
              ))}
            </ul>
          </section>
        ))}
      </DialogContent>
    </Dialog>
  )
}
