import { useTranslation } from 'react-i18next'
import type { SharedFile } from '@kutup/drive-core/fileShares'
import { folderOwnerClaim } from '@kutup/drive-core/identityStatus'
import type { Folder } from '@kutup/drive-core/model'
import { IdentityWarningIcon } from '@kutup/drive-ui/IdentityWarning'
import type { FolderView, SharedWithMeFileView } from '@kutup/drive-source/source'
import { PersonLabel } from './PersonLabel'

/**
 * Who shared something with you, as "Shared with me" shows it: who passed it
 * on and whose it is, each with Kutup's warning when their keys are not the
 * ones you know (docs/plans/drive-identity-pins.md).
 */
export function KutupSharedFrom(props: { shared: SharedWithMeFileView } | { folder: FolderView }) {
  const { t } = useTranslation()
  if ('folder' in props) {
    const f = props.folder as Folder
    return f.ownerAccount ? (
      <>
        <PersonLabel account={f.ownerAccount} format={(name) => t('shared.from', { account: name })} />
        <IdentityWarningIcon account={f.ownerAccount} claimed={folderOwnerClaim(f)} />
      </>
    ) : null
  }
  const s = props.shared as SharedFile
  return (
    <>
      <PersonLabel account={s.sharerAccount} format={(name) => t('shared.from', { account: name })} />
      <IdentityWarningIcon account={s.sharerAccount} claimed={s.sharerClaim} />
      {s.sharerAccount !== s.ownerAccount ? (
        <>
          {' · '}
          <PersonLabel account={s.ownerAccount} format={(name) => t('shared.ownedBy', { account: name })} />
          <IdentityWarningIcon account={s.ownerAccount} claimed={s.ownerClaim} />
        </>
      ) : null}
    </>
  )
}
