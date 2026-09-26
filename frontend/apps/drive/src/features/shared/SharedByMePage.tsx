import { ExternalLink, UserPlus } from 'lucide-react'
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { FileShareDialog } from '@kutup/drive-ui/FileShareDialog'
import type { Folder } from '@kutup/drive-core/model'
import { useSharedByMe, type SharedByMeItem } from '@kutup/drive-core/sharedByMe'
import { Alert } from '@kutup/ui/components/alert'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { ShareDialog } from '../dialogs/ShareDialog'
import { LinkDialog } from '../dialogs/LinkDialog'
import { folderPath, openFile } from '../drive/paths'
import { Explorer } from '../explorer/Explorer'
import { useExplorerPrefs } from '../explorer/prefs'
import { filterItems, itemKey, sortItems, type ExplorerItem } from '../explorer/sort'
import { Toolbar } from '../explorer/Toolbar'

type Dialog = { kind: 'folder'; folder: Folder } | { kind: 'file'; key: string } | { kind: 'invite'; url: string; account: string } | null

/**
 * What you share: your folders shared with people or by link, and your files
 * shared by themselves, with who has them at a glance and their sharing a
 * click away (as Proton Drive's "Shared" section).
 */
export function SharedByMePage() {
  const { t, i18n } = useTranslation()
  const navigate = useNavigate()
  const shared = useSharedByMe()
  const [prefs, updatePrefs] = useExplorerPrefs()
  const [selection, setSelection] = useState<Set<string>>(new Set())
  const [dialog, setDialog] = useState<Dialog>(null)

  const byKey = useMemo(() => {
    const map = new Map<string, SharedByMeItem>()
    for (const item of shared.items) map.set(itemKey({ type: item.file ? 'file' : 'folder', id: item.file?.id ?? item.folder.id }), item)
    return map
  }, [shared.items])

  const items: ExplorerItem[] = useMemo(
    () =>
      shared.items.map((item) =>
        item.file
          ? {
              type: 'file' as const,
              id: item.file.id,
              name: item.file.name ?? t('drive.encrypted'),
              kind: item.file.kind,
              size: item.file.name ? item.file.size : null,
              modifiedAt: item.file.updatedAt,
            }
          : {
              type: 'folder' as const,
              id: item.folder.id,
              name: item.folder.isRoot ? t('nav.myFiles') : (item.folder.name ?? t('drive.encrypted')),
              kind: 'folder' as const,
              size: null,
              modifiedAt: item.folder.updatedAt,
              color: item.folder.color,
            },
      ),
    [shared.items, t],
  )
  const shown = sortItems(filterItems(items, prefs.kinds), prefs.sort, i18n.language)

  const open = (item: SharedByMeItem) => {
    if (item.file) openFile(navigate, item.folder, item.file)
    else void navigate(folderPath(item.folder))
  }
  const manage = (item: SharedByMeItem) =>
    setDialog(item.file ? { kind: 'file', key: itemKey({ type: 'file', id: item.file.id }) } : { kind: 'folder', folder: item.folder })

  const fileTarget = (() => {
    const item = dialog?.kind === 'file' ? byKey.get(dialog.key) : undefined
    return item?.file ? { folder: item.folder, file: item.file } : null
  })()

  if (shared.loading && shared.items.length === 0) return <LoadingPanel label={t('common.loading')} />

  return (
    <div className="flex min-h-[calc(100svh-3.5rem)] flex-col">
      <div className="sticky top-14 z-20 flex min-h-12 flex-wrap items-center gap-2 border-b border-border bg-background/95 px-3 py-1.5 backdrop-blur-sm md:px-6">
        <h1 className="min-w-0 flex-1 font-display text-lg font-semibold">{t('nav.sharedByMe')}</h1>
        <Toolbar prefs={prefs} update={updatePrefs} />
      </div>
      {shared.error ? (
        <div className="p-4">
          <Alert variant="error">{apiErrorMessage(shared.error, t('drive.loadFailed'))}</Alert>
        </div>
      ) : null}
      {shown.length === 0 ? (
        <EmptyState title={t('sharedByMe.emptyTitle')} description={t('sharedByMe.emptyDescription')} />
      ) : (
        <Explorer
          items={shown}
          view={prefs.view}
          sort={prefs.sort}
          onSortField={(field) =>
            updatePrefs(field === prefs.sort.field ? { dir: prefs.sort.dir === 'asc' ? 'desc' : 'asc' } : { field })
          }
          selection={selection}
          onSelectionChange={setSelection}
          subtitleFor={(item) => {
            const shared = byKey.get(itemKey(item))
            if (!shared) return null
            return [
              shared.people > 0 ? t('sharedByMe.people', { count: shared.people }) : null,
              shared.otherServers > 0 ? t('sharedByMe.otherServers', { count: shared.otherServers }) : null,
              shared.links > 0 ? t('sharedByMe.links', { count: shared.links }) : null,
            ]
              .filter(Boolean)
              .join(' · ')
          }}
          onOpen={(item) => {
            const shared = byKey.get(itemKey(item))
            if (shared) open(shared)
          }}
          actionsFor={(item) => {
            const shared = byKey.get(itemKey(item))
            if (!shared) return []
            return [
              { id: 'open', label: t('drive.actions.open'), icon: <ExternalLink />, onSelect: () => open(shared) },
              { id: 'share', label: t('sharedByMe.manage'), icon: <UserPlus />, onSelect: () => manage(shared) },
            ]
          }}
        />
      )}
      <ShareDialog
        folder={dialog?.kind === 'folder' ? dialog.folder : null}
        onClose={() => setDialog(null)}
        onInvite={(url, account) => setDialog({ kind: 'invite', url, account })}
      />
      <FileShareDialog target={fileTarget} onClose={() => setDialog(null)} />
      <LinkDialog
        link={dialog?.kind === 'invite' ? dialog.url : null}
        title={t('dialogs.invite.title')}
        description={t('dialogs.invite.description', { account: dialog?.kind === 'invite' ? dialog.account : '' })}
        warning={t('dialogs.invite.warning')}
        onClose={() => setDialog(null)}
      />
    </div>
  )
}
