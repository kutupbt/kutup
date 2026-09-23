// @vitest-environment node
import { strToU8, zipSync } from 'fflate'
import { describe, expect, it } from 'vitest'
import { inspectOoxmlContainerV1 } from './ooxml'

function officeFile(entries: Record<string, Uint8Array>): File {
  return new File([zipSync(entries).slice().buffer], 'fixture.zip', { type: 'application/zip' })
}

describe('bounded OOXML container inspection', () => {
  it.each([
    ['docx', 'word/document.xml'],
    ['pptx', 'ppt/presentation.xml'],
    ['xlsx', 'xl/workbook.xml'],
  ] as const)('recognizes a single %s document kind from the central directory', async (kind, marker) => {
    const file = officeFile({
      '[Content_Types].xml': strToU8('<Types/>'),
      [marker]: strToU8('<document/>'),
    })
    await expect(inspectOoxmlContainerV1(file)).resolves.toBe(kind)
  })

  it('rejects ambiguous, macro-enabled, active-X, and ordinary ZIP containers', async () => {
    await expect(inspectOoxmlContainerV1(officeFile({
      '[Content_Types].xml': strToU8('<Types/>'),
      'word/document.xml': strToU8('<document/>'),
      'xl/workbook.xml': strToU8('<workbook/>'),
    }))).resolves.toBeNull()
    await expect(inspectOoxmlContainerV1(officeFile({
      '[Content_Types].xml': strToU8('<Types/>'),
      'word/document.xml': strToU8('<document/>'),
      'word/vbaProject.bin': new Uint8Array([1]),
    }))).resolves.toBeNull()
    await expect(inspectOoxmlContainerV1(officeFile({
      '[Content_Types].xml': strToU8('<Types/>'),
      'ppt/presentation.xml': strToU8('<presentation/>'),
      'ppt/activeX/activeX1.bin': new Uint8Array([1]),
    }))).resolves.toBeNull()
    await expect(inspectOoxmlContainerV1(officeFile({
      'notes.txt': strToU8('hello'),
    }))).resolves.toBeNull()
  })

  it('rejects traversal names, excessive entries, and truncation', async () => {
    await expect(inspectOoxmlContainerV1(officeFile({
      '[Content_Types].xml': strToU8('<Types/>'),
      'ppt/presentation.xml': strToU8('<presentation/>'),
      '../outside.xml': strToU8('bad'),
    }))).resolves.toBeNull()
    const manyEntries: Record<string, Uint8Array> = {
      '[Content_Types].xml': strToU8('<Types/>'),
      'ppt/presentation.xml': strToU8('<presentation/>'),
      'ppt/slides/slide1.xml': strToU8('<slide/>'),
    }
    await expect(inspectOoxmlContainerV1(officeFile(manyEntries), {
      maxEntries: 2,
      maxCentralDirectoryBytes: 4096,
      maxEntryUncompressedBytes: 4096,
      maxTotalUncompressedBytes: 4096,
      maxCompressionRatio: 100,
    })).resolves.toBeNull()
    const valid = zipSync({
      '[Content_Types].xml': strToU8('<Types/>'),
      'ppt/presentation.xml': strToU8('<presentation/>'),
    })
    await expect(inspectOoxmlContainerV1(new Blob([
      valid.subarray(0, valid.length - 4).slice().buffer,
    ])))
      .resolves.toBeNull()
  })

  it('honors cancellation before reading', async () => {
    const controller = new AbortController()
    controller.abort()
    await expect(inspectOoxmlContainerV1(new Blob(), undefined, controller.signal))
      .rejects.toMatchObject({ name: 'AbortError' })
  })
})
