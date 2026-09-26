import { isAxiosError } from 'axios'

export type UploadFailure = 'quota' | 'shareQuota' | 'forbidden' | 'network' | 'other'

interface TusLikeError {
  originalResponse?: { getStatus(): number; getBody(): string } | null
}

/**
 * The folder moved to a new key while the upload was prepared (its owner
 * removed someone): reload the folder and try again with the new key.
 */
export function isFolderKeyChanged(error: unknown): boolean {
  const tus = (error as TusLikeError | null)?.originalResponse
  if (tus) return tus.getStatus() === 409 && /folder (key )?changed/.test(tus.getBody() ?? '')
  return (
    isAxiosError(error) &&
    error.response?.status === 409 &&
    /folder (key )?changed/.test(JSON.stringify(error.response.data ?? ''))
  )
}

/**
 * Why an upload failed, from either transport: tus (local folders) reports
 * through `originalResponse`, the multipart proxy (federated folders) through
 * axios. The server says which quota a 413 hit.
 */
export function classifyUploadError(error: unknown): UploadFailure {
  let status: number | undefined
  let body = ''
  const tus = (error as TusLikeError | null)?.originalResponse
  if (tus) {
    status = tus.getStatus()
    body = tus.getBody() ?? ''
  } else if (isAxiosError(error)) {
    if (!error.response) return 'network'
    status = error.response.status
    body = JSON.stringify(error.response.data ?? '')
  } else if (error instanceof TypeError) {
    return 'network'
  }
  if (status === 413) return body.includes('share upload quota') ? 'shareQuota' : 'quota'
  if (status === 403) return 'forbidden'
  if (status === 0 || status === undefined) return error instanceof Error && /network|fetch/i.test(error.message) ? 'network' : 'other'
  return 'other'
}
