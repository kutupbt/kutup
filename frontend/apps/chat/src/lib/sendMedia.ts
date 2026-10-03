import { fetchChatMediaV1, uploadChatMediaV1 } from '@kutup/chat-core/media'
import type { ChatService } from '@kutup/chat-core/service'
import type {
  ChatAttachmentDescriptorV1,
  ChatCapabilities,
  ChatMessageExtras,
  ConversationId,
  SendSummary,
} from '@kutup/chat-core/types'
import { freshAccessToken } from '@kutup/session/client'

/** Encrypt and upload one file, then send it to `conversation`. */
export async function uploadAndSend(
  service: ChatService,
  capabilities: ChatCapabilities,
  conversation: ConversationId,
  file: File,
  options: {
    durationMs?: number
    withoutPreview?: boolean
    timerSeconds?: number
    extras?: ChatMessageExtras
    onProgress?: (sent: number, total: number) => void
    signal?: AbortSignal
  } = {},
): Promise<SendSummary> {
  if (!capabilities.media || !capabilities.serverName) throw new Error('media is not available')
  const { timerSeconds, extras, ...upload } = options
  const uploaded = await uploadChatMediaV1({
    file,
    originDomain: capabilities.serverName,
    accessToken: await freshAccessToken(),
    ...upload,
  })
  return service.sendAttachment(conversation, uploaded.descriptor, uploaded.storageReferenceId, timerSeconds, extras)
}

/**
 * The plaintext of a received or sent attachment, as a File to send again
 * (forwarding): the original lives on its sender's server, so a forward is
 * a new upload, as in Signal.
 */
export async function attachmentFile(descriptor: ChatAttachmentDescriptorV1, signal?: AbortSignal): Promise<File> {
  const parts: Uint8Array[] = []
  for await (const { plain } of fetchChatMediaV1(descriptor, await freshAccessToken(), signal)) parts.push(plain)
  return new File(parts as BlobPart[], descriptor.filename, { type: descriptor.mimeType })
}
