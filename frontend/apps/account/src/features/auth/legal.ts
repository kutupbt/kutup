// The operator's documents (docs/plans/server-personal-data.md, A3): the
// sign-up page asks for the current version of each required one, and a
// sign-in shows a newly required version once. Nothing published, nothing
// asked.

import { useQuery } from '@tanstack/react-query'
import type { useTranslation } from 'react-i18next'
import api from '@kutup/session/client'

/** A document's name: the operator's kind, as the pages know it, or the kind itself. */
export function documentName(t: ReturnType<typeof useTranslation>['t'], kind: string): string {
  return t(`legal.kinds.${kind}`, { defaultValue: kind.replaceAll('_', ' ') })
}

export interface LegalDocument {
  id: string
  /** The operator's kind: `terms`, `privacy_notice`, or a consent purpose. */
  kind: string
  version: string
  language: string
  url: string
  sha256: string
  requiredAtSignup: boolean
  publishedAt: string
}

/** The current documents: each kind's latest version, in every language. */
export function useCurrentDocuments() {
  return useQuery({
    queryKey: ['legal-documents'],
    queryFn: async () => (await api.get<LegalDocument[]>('/legal/documents')).data,
    staleTime: 5 * 60_000,
  })
}

/**
 * One document per kind, in `language` when it was published in it, else
 * English, else the first: what the person reads and confirms.
 */
export function oneEach(documents: LegalDocument[], language: string): LegalDocument[] {
  const base = language.split('-')[0]
  const kinds = [...new Set(documents.map((d) => d.kind))]
  return kinds.map((kind) => {
    const versions = documents.filter((d) => d.kind === kind)
    return (
      versions.find((d) => d.language === language) ??
      versions.find((d) => d.language.split('-')[0] === base) ??
      versions.find((d) => d.language === 'en') ??
      versions[0]
    )
  })
}

/** The required documents this account hasn't confirmed in their current version. */
export async function pendingDocuments(): Promise<LegalDocument[]> {
  return (await api.get<LegalDocument[]>('/user/legal/pending')).data
}

/**
 * The required documents an account hasn't confirmed in their current
 * version, or none: a failure to ask shows nothing, and the next sign-in asks
 * again.
 */
export async function documentsToConfirm(): Promise<LegalDocument[]> {
  try {
    return await pendingDocuments()
  } catch {
    return []
  }
}

export async function acknowledgeDocuments(ids: string[]): Promise<void> {
  await api.post('/user/legal/acknowledge', { documentIds: ids })
}
