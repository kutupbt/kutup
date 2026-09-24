import { isAxiosError } from 'axios'

export type UploadFailure = 'quota' | 'shareQuota' | 'forbidden' | 'remoteTooLarge' | 'network' | 'other'

/**
 * A federated folder's server takes each file as one signed request, which
 * it holds in memory while checking it: the largest it accepts
 * (`FEDERATED_DRIVE_UPLOAD_LIMIT_BYTES` on the server, less room for the
 * envelopes and the encryption overhead).
 */
export const MAX_REMOTE_UPLOAD_BYTES = 255 * 1024 * 1024

export class RemoteUploadTooLargeError extends Error {
  constructor() {
    super('file too large for a federated folder')
    this.name = 'RemoteUploadTooLargeError'
  }
}

interface TusLikeError {
  originalResponse?: { getStatus(): number; getBody(): string } | null
}

/**
 * Why an upload failed, from either transport: tus (local folders) reports
 * through `originalResponse`, the multipart proxy (federated folders) through
 * axios. The server says which quota a 413 hit.
 */
export function classifyUploadError(error: unknown): UploadFailure {
  if (error instanceof RemoteUploadTooLargeError) return 'remoteTooLarge'
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
