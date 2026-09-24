import { toBase64 } from '@kutup/crypto/base64'

const MAX_AVATAR_BYTES = 512 * 1024

/**
 * A profile picture as it is sent: the image's centre square, at most
 * 512×512, re-encoded as WebP under 512 KiB, all on this device (the
 * original file, with its metadata, never leaves it).
 */
export async function normalizeAvatar(file: File): Promise<{ base64: string; contentType: string }> {
  if (!['image/png', 'image/jpeg', 'image/webp'].includes(file.type)) throw new Error('unsupported avatar type')
  const image = await loadImage(file)
  const side = Math.min(image.naturalWidth, image.naturalHeight)
  if (side < 1) throw new Error('empty avatar')
  const size = Math.min(512, side)
  const canvas = document.createElement('canvas')
  canvas.width = size
  canvas.height = size
  const context = canvas.getContext('2d')
  if (!context) throw new Error('avatar canvas is unavailable')
  context.drawImage(image, (image.naturalWidth - side) / 2, (image.naturalHeight - side) / 2, side, side, 0, 0, size, size)
  let blob: Blob | null = null
  for (const quality of [0.86, 0.72, 0.56]) {
    blob = await new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, 'image/webp', quality))
    if (blob && blob.size <= MAX_AVATAR_BYTES) break
  }
  if (!blob || blob.size > MAX_AVATAR_BYTES || blob.type !== 'image/webp') throw new Error('avatar could not be normalized')
  return { base64: toBase64(new Uint8Array(await blob.arrayBuffer())), contentType: blob.type }
}

function loadImage(file: File): Promise<HTMLImageElement> {
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
