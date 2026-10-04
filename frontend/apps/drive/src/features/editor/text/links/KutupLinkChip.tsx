import { Lock } from 'lucide-react'
import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { KindIcon } from '@kutup/drive-ui/KindIcon'
import { folderPath, openFile } from '../../../drive/paths'
import type { KutupItem } from './useKutupItems'

/**
 * A link to a Kutup item in a note's preview: its kind icon and current
 * name, opening it where it opens (an editor, a viewer, Maps, a folder).
 * An item this reader cannot see keeps the writer's link text, marked.
 */
export function KutupLinkChip({ item, ready, children }: { item: KutupItem | undefined; ready: boolean; children: ReactNode }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  if (!item) {
    return (
      <span
        className="kutup-link kutup-link-missing"
        title={ready ? t('editor.links.noAccess') : t('editor.links.loading')}
      >
        {ready ? <Lock className="size-3.5" aria-hidden /> : null}
        {children}
      </span>
    )
  }
  const open = () => {
    if (item.type === 'folder') void navigate(folderPath(item.folder))
    else openFile(navigate, item.folder, { id: item.id, name: item.name })
  }
  return (
    <button type="button" className="kutup-link" onClick={open} title={item.where ? `${item.name} · ${item.where}` : item.name}>
      <KindIcon kind={item.kind} className="size-4" />
      <span>{item.name}</span>
    </button>
  )
}
