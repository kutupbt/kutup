import { Check, Pipette } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import {
  flattenFolders,
  heightOf,
  MAX_FOLDER_DEPTH,
  nameIsFree,
  PLACE_COLORS,
  useCreateFolder,
  useCreateLabel,
  useUpdateFolder,
  useUpdateLabel,
  type MailFolder,
  type MailLabel,
  type MailPlaces,
} from '@kutup/mail-core/places'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { cn } from '@kutup/ui/lib/cn'

/** What the dialog makes or edits. */
export type PlaceTarget =
  | { kind: 'folder'; folder?: MailFolder; parentId?: string | null; name?: string }
  | { kind: 'label'; label?: MailLabel; name?: string }

/** The top level in the location picker (Radix Select takes no empty value). */
const TOP = '__top__'

/**
 * Proton's "Create folder" / "Edit label" (`EditLabelModal`, `NewLabelForm`):
 * a name, a colour, and for a folder its location. Names are checked against
 * their siblings here, since the server only ever sees them sealed.
 */
export function PlaceDialog({
  target,
  places,
  onClose,
  onCreated,
}: {
  target: PlaceTarget
  places: MailPlaces
  onClose: () => void
  /** Told the new folder's or label's id (to file mail into it at once). */
  onCreated?: (id: string, name: string) => void
}) {
  const { t } = useTranslation()
  const createFolder = useCreateFolder()
  const updateFolder = useUpdateFolder()
  const createLabel = useCreateLabel()
  const updateLabel = useUpdateLabel()
  const editing = target.kind === 'folder' ? target.folder : target.label
  const [name, setName] = useState(editing?.name ?? target.name ?? '')
  const [color, setColor] = useState(editing?.color ?? PLACE_COLORS[Math.floor(Math.random() * PLACE_COLORS.length)])
  const [parent, setParent] = useState<string>(target.kind === 'folder' ? (target.folder?.parentId ?? target.parentId ?? TOP) : TOP)
  const [error, setError] = useState<string | undefined>()
  // A colour code being typed that is not one yet: nothing is saved until it is.
  const [codeInvalid, setCodeInvalid] = useState(false)
  const choose = (value: string) => {
    setColor(value)
    setCodeInvalid(false)
  }
  const pending = createFolder.isPending || updateFolder.isPending || createLabel.isPending || updateLabel.isPending

  // Where a folder may go: the top, or a folder shallow enough to hold it (and what it holds), never inside itself.
  const height = target.kind === 'folder' && target.folder ? heightOf(target.folder) : 1
  const inside = new Set(target.kind === 'folder' && target.folder ? flattenFolders([target.folder]).map((f) => f.id) : [])
  const locations = flattenFolders(places.tree).filter((f) => !inside.has(f.id) && f.depth + height <= MAX_FOLDER_DEPTH)

  const siblings =
    target.kind === 'folder'
      ? [...places.folders.values()].filter((f) => (f.parentId ?? TOP) === parent)
      : places.labels

  function submit() {
    if (codeInvalid) return
    const trimmed = name.trim()
    if (!trimmed) {
      setError(t('places.nameRequired'))
      return
    }
    if (trimmed.length > 100) {
      setError(t('places.nameTooLong'))
      return
    }
    if (!nameIsFree(trimmed, siblings, editing?.id)) {
      setError(t(target.kind === 'folder' ? 'places.folderNameTaken' : 'places.labelNameTaken'))
      return
    }
    const failed = (e: unknown) => toast.error(apiErrorMessage(e, t('common.tryAgain')))
    const done = (key: string) => {
      toast.success(t(key, { name: trimmed }))
      onClose()
    }
    if (target.kind === 'folder') {
      const parentId = parent === TOP ? null : parent
      if (target.folder) {
        updateFolder.mutate(
          {
            id: target.folder.id,
            ...(trimmed !== target.folder.name ? { name: trimmed } : {}),
            ...(color !== target.folder.color ? { color } : {}),
            ...(parentId !== target.folder.parentId ? { parentId } : {}),
          },
          { onSuccess: () => done('places.updated'), onError: failed },
        )
      } else {
        createFolder.mutate(
          { name: trimmed, color, parentId },
          {
            onSuccess: (id) => {
              onCreated?.(id, trimmed)
              done('places.created')
            },
            onError: failed,
          },
        )
      }
    } else if (target.label) {
      updateLabel.mutate(
        { id: target.label.id, ...(trimmed !== target.label.name ? { name: trimmed } : {}), ...(color !== target.label.color ? { color } : {}) },
        { onSuccess: () => done('places.updated'), onError: failed },
      )
    } else {
      createLabel.mutate(
        { name: trimmed, color },
        {
          onSuccess: (id) => {
            onCreated?.(id, trimmed)
            done('places.created')
          },
          onError: failed,
        },
      )
    }
  }

  const titleKey = target.kind === 'folder' ? (target.folder ? 'places.editFolder' : 'places.newFolder') : target.label ? 'places.editLabel' : 'places.newLabel'
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-md">
        <form
          onSubmit={(e) => {
            e.preventDefault()
            submit()
          }}
          className="space-y-4"
        >
          <DialogHeader>
            <DialogTitle>{t(titleKey)}</DialogTitle>
            {target.kind === 'folder' && !target.folder ? <DialogDescription>{t('places.newFolderHint')}</DialogDescription> : null}
          </DialogHeader>
          <Field label={t(target.kind === 'folder' ? 'places.folderName' : 'places.labelName')} error={error}>
            {(props) => (
              <Input
                {...props}
                autoFocus
                value={name}
                maxLength={100}
                onChange={(e) => {
                  setName(e.target.value)
                  setError(undefined)
                }}
              />
            )}
          </Field>
          {target.kind === 'folder' ? (
            <Field label={t('places.location')}>
              {(props) => (
                <Select
                  value={parent}
                  onValueChange={(value) => {
                    setParent(value)
                    setError(undefined)
                  }}
                >
                  <SelectTrigger id={props.id} aria-describedby={props['aria-describedby']}>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value={TOP}>{t('places.topLevel')}</SelectItem>
                    {locations.map((folder) => (
                      <SelectItem key={folder.id} value={folder.id}>
                        {`${'\u2003'.repeat(folder.depth - 1)}${folder.name}`}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            </Field>
          ) : null}
          <fieldset>
            <legend className="mb-2 text-sm font-medium">{t('places.color')}</legend>
            <div className="flex flex-wrap items-center gap-2">
              {PLACE_COLORS.map((value) => (
                <button
                  key={value}
                  type="button"
                  aria-label={value}
                  aria-pressed={color === value}
                  onClick={() => choose(value)}
                  className={cn('flex size-7 items-center justify-center rounded-full ring-offset-2 ring-offset-background', color === value && 'ring-2 ring-ring')}
                  style={{ backgroundColor: value }}
                >
                  {color === value ? <Check className="size-4 text-white" aria-hidden /> : null}
                </button>
              ))}
              <CustomColor color={color} onChange={choose} />
            </div>
            <ColorCode color={color} onChange={setColor} onInvalid={setCodeInvalid} />
          </fieldset>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" disabled={pending || codeInvalid}>
              {t('common.save')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

const HEX = /^#[0-9a-f]{6}$/

/** Dark or light ink on a colour, whichever reads (WCAG relative luminance). */
function inkOn(hex: string) {
  const [r, g, b] = [1, 3, 5].map((i) => {
    const c = parseInt(hex.slice(i, i + 2), 16) / 255
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4
  })
  return 0.2126 * r + 0.7152 * g + 0.0722 * b > 0.4 ? 'text-black' : 'text-white'
}

/**
 * Any colour besides the palette, from the system's colour picker: a
 * rainbow swatch until one is chosen, then that colour, ticked.
 */
function CustomColor({ color, onChange }: { color: string; onChange: (color: string) => void }) {
  const { t } = useTranslation()
  const custom = !(PLACE_COLORS as readonly string[]).includes(color)
  return (
    <label
      className={cn(
        'relative flex size-7 cursor-pointer items-center justify-center rounded-full ring-offset-2 ring-offset-background focus-within:ring-2 focus-within:ring-ring',
        custom && 'ring-2 ring-ring',
      )}
      style={{ background: custom ? color : 'conic-gradient(#ec3e7c, #f78400, #efc500, #3cbb3a, #1da4d4, #7c5cff, #ec3e7c)' }}
      title={t('places.customColor')}
    >
      <input
        type="color"
        className="absolute inset-0 size-full cursor-pointer opacity-0"
        aria-label={t('places.customColor')}
        value={color}
        onChange={(e) => onChange(e.target.value.toLowerCase())}
      />
      {custom ? <Check className={cn('size-4', inkOn(color))} aria-hidden /> : <Pipette className="size-3.5 text-white" aria-hidden />}
    </label>
  )
}

/** The chosen colour as a code (`#rrggbb`), to type or paste one exactly. */
function ColorCode({ color, onChange, onInvalid }: { color: string; onChange: (color: string) => void; onInvalid: (invalid: boolean) => void }) {
  const { t } = useTranslation()
  const [draft, setDraft] = useState(color)
  const [shown, setShown] = useState(color)
  // A swatch or the picker chose another colour: show its code.
  if (color !== shown) {
    setShown(color)
    setDraft(color)
  }
  const normal = (value: string) => (value.trim().startsWith('#') ? value.trim() : `#${value.trim()}`).toLowerCase()
  const invalid = !HEX.test(normal(draft))
  return (
    <Field label={t('places.colorCode')} error={invalid ? t('places.colorCodeInvalid') : undefined} className="mt-3">
      {(props) => (
        <Input
          {...props}
          value={draft}
          maxLength={7}
          spellCheck={false}
          autoComplete="off"
          className="max-w-32 font-mono"
          onChange={(e) => {
            setDraft(e.target.value)
            const next = normal(e.target.value)
            onInvalid(!HEX.test(next))
            if (HEX.test(next)) {
              setShown(next)
              onChange(next)
            }
          }}
        />
      )}
    </Field>
  )
}
