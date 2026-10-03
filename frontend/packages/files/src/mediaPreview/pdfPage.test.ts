import { describe, expect, it } from 'vitest'
import { contentBox } from './pdfPage'

function page(width: number, height: number, ink: [number, number][]) {
  const data = new Uint8ClampedArray(width * height * 4).fill(255)
  for (const [x, y] of ink) data.fill(0, (y * width + x) * 4, (y * width + x) * 4 + 3)
  return { width, height, data }
}

describe('contentBox', () => {
  it('finds the box around what is drawn', () => {
    expect(contentBox(page(10, 8, [[3, 2], [6, 5]]))).toEqual({ left: 3, top: 2, right: 6, bottom: 5 })
  })

  it('treats near-white as paper and a blank page as nothing', () => {
    expect(contentBox(page(4, 4, []))).toBeNull()
    const faint = page(4, 4, [])
    faint.data.fill(250)
    expect(contentBox(faint)).toBeNull()
  })
})
