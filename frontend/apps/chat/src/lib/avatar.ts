import { toBase64 } from '@kutup/crypto/base64'

/** A profile picture: at most 512×512 and 512 KiB. */
export const PROFILE_AVATAR = { maxSide: 512, maxBytes: 512 * 1024 }
/** A group picture travels inside the group state: at most 256×256 and 48 KiB. */
export const GROUP_AVATAR = { maxSide: 256, maxBytes: 48 * 1024 }

/**
 * A picture as it is sent: the image's centre square, scaled down to fit,
 * re-encoded as WebP under the byte limit (smaller and lower quality until
 * it fits), all on this device (the original file, with its metadata,
 * never leaves it).
 */
export async function normalizeAvatar(
  file: File,
  limits: { maxSide: number; maxBytes: number } = PROFILE_AVATAR,
): Promise<{ base64: string; contentType: 'image/webp' }> {
  if (!['image/png', 'image/jpeg', 'image/webp'].includes(file.type)) throw new Error('unsupported avatar type')
  const image = await loadImage(file)
  const side = Math.min(image.naturalWidth, image.naturalHeight)
  if (side < 1) throw new Error('empty avatar')
  for (const scale of [1, 0.75, 0.5]) {
    const size = Math.max(1, Math.round(Math.min(limits.maxSide, side) * scale))
    const canvas = document.createElement('canvas')
    canvas.width = size
    canvas.height = size
    const context = canvas.getContext('2d')
    if (!context) throw new Error('avatar canvas is unavailable')
    context.drawImage(image, (image.naturalWidth - side) / 2, (image.naturalHeight - side) / 2, side, side, 0, 0, size, size)
    for (const quality of [0.86, 0.72, 0.56, 0.4]) {
      const blob = await new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, 'image/webp', quality))
      if (blob && blob.type === 'image/webp' && blob.size <= limits.maxBytes) {
        return { base64: toBase64(new Uint8Array(await blob.arrayBuffer())), contentType: 'image/webp' }
      }
    }
  }
  throw new Error('avatar could not be normalized')
}

/**
 * An image scaled down to fit `maxSide` (aspect kept), re-encoded as WebP
 * under `maxBytes`: a link preview's picture, small enough to travel inside
 * the message.
 */
export async function fitImage(
  file: Blob,
  limits: { maxSide: number; maxBytes: number },
): Promise<{ base64: string; contentType: 'image/webp' }> {
  const image = await loadImage(file)
  const { naturalWidth: width, naturalHeight: height } = image
  if (width < 1 || height < 1) throw new Error('empty image')
  for (const scale of [1, 0.75, 0.5, 0.35]) {
    const ratio = Math.min(1, limits.maxSide / Math.max(width, height)) * scale
    const canvas = document.createElement('canvas')
    canvas.width = Math.max(1, Math.round(width * ratio))
    canvas.height = Math.max(1, Math.round(height * ratio))
    const context = canvas.getContext('2d')
    if (!context) throw new Error('image canvas is unavailable')
    context.drawImage(image, 0, 0, canvas.width, canvas.height)
    for (const quality of [0.8, 0.65, 0.5]) {
      const blob = await new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, 'image/webp', quality))
      if (blob && blob.type === 'image/webp' && blob.size <= limits.maxBytes) {
        return { base64: toBase64(new Uint8Array(await blob.arrayBuffer())), contentType: 'image/webp' }
      }
    }
  }
  throw new Error('image could not be made small enough')
}

function loadImage(file: Blob): Promise<HTMLImageElement> {
  const url = URL.createObjectURL(file)
  return new Promise((resolve, reject) => {
    const image = new Image()
    image.onload = () => {
      URL.revokeObjectURL(url)
      resolve(image)
    }
    image.onerror = () => {
      URL.revokeObjectURL(url)
      reject(new Error('avatar image could not be read'))
    }
    image.src = url
  })
}
