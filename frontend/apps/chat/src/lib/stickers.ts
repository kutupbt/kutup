import { STICKER_IMAGE_MAX_BYTES, type ChatStickerV1 } from '@kutup/chat-core/types'
import { fitImage } from '@kutup/ui/lib/avatar'

/** A sticker image made from a picture: at most 512×512, WebP under 48 KiB. */
export async function stickerFromImage(file: Blob): Promise<Omit<ChatStickerV1, 'stickerId'>> {
  const fitted = await fitImage(file, { maxSide: 512, maxBytes: STICKER_IMAGE_MAX_BYTES })
  return { contentType: fitted.contentType, data: fitted.base64 }
}
