import Image from '@tiptap/extension-image'

/** TipTap's image, keeping which inline part it shows (`data-cid`). */
export const InlineImage = Image.extend({
  addAttributes() {
    return {
      ...this.parent?.(),
      cid: {
        default: null,
        parseHTML: (element) => element.getAttribute('data-cid'),
        renderHTML: (attributes: { cid?: string | null }) => (attributes.cid ? { 'data-cid': attributes.cid } : {}),
      },
    }
  },
}).configure({ inline: true, allowBase64: false })

/** The editor's HTML as sent: each inline image points at its part (`cid:`), not at this browser's blob. */
export function withContentIds(html: string): string {
  if (!html.includes('data-cid')) return html
  const doc = new DOMParser().parseFromString(html, 'text/html')
  doc.querySelectorAll('img[data-cid]').forEach((img) => {
    img.setAttribute('src', `cid:${img.getAttribute('data-cid')}`)
    img.removeAttribute('data-cid')
  })
  return doc.body.innerHTML
}

/** A new Content-ID for an inline image. */
export const newContentId = () => `${crypto.randomUUID()}@kutup`

/**
 * Proton's "Remove metadata": a JPEG, PNG or WebP drawn again, without
 * EXIF (where, on which device, when). Other images go as they are.
 */
export async function withoutMetadata(file: File): Promise<Uint8Array> {
  const original = new Uint8Array(await file.arrayBuffer())
  if (!['image/jpeg', 'image/png', 'image/webp'].includes(file.type)) return original
  try {
    const bitmap = await createImageBitmap(file)
    const canvas = document.createElement('canvas')
    canvas.width = bitmap.width
    canvas.height = bitmap.height
    canvas.getContext('2d')!.drawImage(bitmap, 0, 0)
    bitmap.close()
    const blob = await new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, file.type, 0.92))
    return blob ? new Uint8Array(await blob.arrayBuffer()) : original
  } catch {
    return original
  }
}
