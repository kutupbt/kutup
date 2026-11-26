import { useQuery } from '@tanstack/react-query'
import { Loader2, ShieldAlert, ShieldCheck, ShieldQuestion } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import type { ManifestSignerVerdict } from '@kutup/drive-core/manifestSigners'
import type { DriveFile, Folder } from '@kutup/drive-core/model'
import type { FileView, FolderView } from '@kutup/drive-source/source'
import { currentContentSignature } from '@kutup/editors/files/signature'
import { holdsYjsState } from '@kutup/editors/history'
import { cn } from '@kutup/ui/lib/cn'
import { claimOf, revisionOf, useHistory } from './details'

/**
 * Proton's signature banner: the signature on what the file holds now,
 * checked against the people you know (docs/plans/drive-identity-pins.md).
 */
export function KutupSignatureBanner({ folder: folderView, file: fileView }: { folder: FolderView; file: FileView }) {
  const folder = folderView as Folder
  const file = fileView as DriveFile
  const { local, versions, history, current } = useHistory(folder, file)
  const yjs = holdsYjsState(file.name)
  const checkable = Boolean(file.fileKey && file.content) && !yjs && (!local || (versions.isSuccess && !versions.isFetching) || versions.isError)
  const signature = useQuery({
    queryKey: ['details-signature', file.id, file.content?.revisionId, file.contentKeyGeneration, current?.id ?? null],
    enabled: checkable,
    retry: false,
    staleTime: 60_000,
    queryFn: () =>
      currentContentSignature(folder, file, (revisionId) => {
        if (history) return claimOf(file, history.find((e) => revisionOf(file, e) === revisionId))
        // No history here: the original upload is the uploader's.
        return revisionId === file.originalRevisionId && file.uploaderAccountId ? { accountId: file.uploaderAccountId } : null
      }),
  })
  if (!checkable) return null
  return (
    <SignatureVerdict
      pending={signature.isPending}
      failed={signature.isError}
      verdict={signature.data?.verdict ?? null}
      claimed={Boolean(signature.data?.claimed)}
      hidden={signature.isSuccess && signature.data === null}
    />
  )
}

function SignatureVerdict({
  pending,
  failed,
  verdict,
  claimed,
  hidden,
}: {
  pending: boolean
  failed: boolean
  verdict: ManifestSignerVerdict | null
  /** The history names who saved the content, so a good signature is theirs. */
  claimed: boolean
  hidden: boolean
}) {
  const { t } = useTranslation()
  if (hidden) return null
  let tone: 'ok' | 'bad' | 'muted' = 'muted'
  let text: string
  let Icon = ShieldQuestion
  if (pending) {
    text = t('details.signature.checking')
    Icon = Loader2
  } else if (failed || !verdict) {
    text = t('details.signature.failed')
  } else {
    switch (verdict.kind) {
      case 'verified':
        tone = 'ok'
        Icon = ShieldCheck
        text = claimed ? t('details.signature.verified') : t('details.signature.verifiedKey')
        break
      case 'unknown':
        text = t('details.signature.unknown')
        break
      case 'forged':
        tone = 'bad'
        Icon = ShieldAlert
        text = verdict.name ? t('identityCheck.content.forged', { name: verdict.name }) : t('identityCheck.content.forgedUnnamed')
        break
      case 'changed':
        tone = 'bad'
        Icon = ShieldAlert
        text = verdict.name ? t('identityCheck.content.changed', { name: verdict.name }) : t('identityCheck.content.changedUnnamed')
        break
      case 'authorMismatch':
        tone = 'bad'
        Icon = ShieldAlert
        text =
          verdict.name && verdict.claimed
            ? t('identityCheck.content.authorMismatch', { name: verdict.name, claimed: verdict.claimed })
            : verdict.name
              ? t('identityCheck.content.authorMismatchSigner', { name: verdict.name })
              : t('identityCheck.content.authorMismatchUnnamed')
        break
    }
  }
  return (
    <div
      className={cn(
        'mb-4 flex items-start gap-2 rounded-md border px-3 py-2 text-sm',
        tone === 'ok' && 'border-status-ok/40 bg-status-ok/10',
        tone === 'bad' && 'border-destructive/40 bg-destructive/10 text-destructive',
        tone === 'muted' && 'border-border bg-muted text-muted-foreground',
      )}
      role={tone === 'bad' ? 'alert' : undefined}
      data-testid="details-signature"
      data-verdict={pending ? 'pending' : failed || !verdict ? 'failed' : verdict.kind}
    >
      <Icon className={cn('mt-0.5 size-4 shrink-0', pending && 'animate-spin', tone === 'ok' && 'text-status-ok')} aria-hidden />
      <span>{text}</span>
    </div>
  )
}
