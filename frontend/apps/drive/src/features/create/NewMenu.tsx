import { Plus } from 'lucide-react'
import { Fragment } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@kutup/ui/components/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@kutup/ui/components/dropdown-menu'
import { useCurrentFolder } from '../drive/currentFolderContext'
import { useFolders } from '@kutup/drive-core/folders'
import { useCreateActions } from './useCreateActions'

/** The sidebar's New: into the folder on screen, or My Files elsewhere. */
export function NewMenu() {
  const { t } = useTranslation()
  const current = useCurrentFolder()
  const folders = useFolders()
  const target = current ?? folders.data?.root ?? null
  const { actions, busy, elements } = useCreateActions(target)

  if (actions.length === 0) {
    return (
      <Button variant="chrome" className="w-full justify-start border border-chrome-border" disabled>
        <Plus />
        {t('newMenu.new')}
      </Button>
    )
  }

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="chrome" className="w-full justify-start border border-chrome-border" loading={busy}>
            <Plus />
            {t('newMenu.new')}
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start" className="w-60">
          {actions.map((action) => (
            <Fragment key={action.id}>
              {action.separated ? <DropdownMenuSeparator /> : null}
              <DropdownMenuItem onSelect={action.onSelect}>
                {action.icon}
                {action.label}
              </DropdownMenuItem>
            </Fragment>
          ))}
        </DropdownMenuContent>
      </DropdownMenu>
      {elements}
    </>
  )
}
