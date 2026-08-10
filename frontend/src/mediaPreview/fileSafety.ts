export type FileSafetyClassification =
  | 'previewable'
  | 'safe-download-only'
  | 'dangerous-active'
  | 'mismatch'

export interface FileSafetyInput {
  filename: string
  mimeType?: string
  /** A bounded prefix is sufficient for all V1 signature checks. */
  bytes: Uint8Array
  /** Set only after a bounded ZIP central-directory inspection. */
  verifiedContainerType?: 'docx' | 'pptx' | 'xlsx'
}

export interface FileSafetyResult {
  classification: FileSafetyClassification
  normalizedFilename: string
  extension: string
  claimedMimeType: string
  detectedMimeType?: string
  reason: string
}

// Signal Desktop's denylist is the compatibility floor. Content signatures
// below add protection for renamed executables and scripts.
const DANGEROUS_EXTENSIONS = new Set([
  'ade', 'adp', 'apk', 'bat', 'cab', 'chm', 'cmd', 'com', 'cpl', 'diagcab',
  'dll', 'dmg', 'exe', 'hta', 'inf', 'ins', 'isp', 'jar', 'js', 'jse', 'lib',
  'lnk', 'mde', 'mht', 'msc', 'msi', 'msp', 'mst', 'nsh', 'pif', 'ps1',
  'psc1', 'psm1', 'psrc', 'reg', 'scr', 'sct', 'settingcontent-ms', 'shb',
  'sys', 'vb', 'vbe', 'vbs', 'vxd', 'wsc', 'wsf', 'wsh',
])

const DANGEROUS_MIME_TYPES = new Set([
  'application/javascript',
  'application/vnd.android.package-archive',
  'application/vnd.microsoft.portable-executable',
  'application/x-bat',
  'application/x-dosexec',
  'application/x-executable',
  'application/x-msdownload',
  'application/x-msi',
  'application/x-sh',
  'text/html',
  'text/javascript',
])

const ACTIVE_WEB_EXTENSIONS = new Set(['html', 'htm', 'xhtml'])
const DOWNLOAD_ONLY_EXTENSIONS = new Set([
  '7z', 'bz2', 'docm', 'gz', 'heic', 'heif', 'iso', 'ods', 'odt', 'pptm',
  'rar', 'rtf', 'svg', 'tar', 'tgz', 'txt', 'xlsm', 'xml', 'xz', 'yaml',
  'yml', 'zip',
])

const PREVIEW_MIME_BY_EXTENSION: Readonly<Record<string, string>> = {
  aac: 'audio/aac',
  avif: 'image/avif',
  bmp: 'image/bmp',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  flac: 'audio/flac',
  gif: 'image/gif',
  jpeg: 'image/jpeg',
  jpg: 'image/jpeg',
  m4a: 'audio/mp4',
  mp3: 'audio/mpeg',
  mp4: 'video/mp4',
  oga: 'audio/ogg',
  ogg: 'audio/ogg',
  ogv: 'video/ogg',
  pdf: 'application/pdf',
  png: 'image/png',
  pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  wav: 'audio/wav',
  webm: 'video/webm',
  webp: 'image/webp',
  xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
}

const GENERIC_MIME_TYPES = new Set(['', 'application/octet-stream', 'binary/octet-stream'])
const BIDI_CONTROLS = /[\u202a-\u202e\u2066-\u2069]/u

export function normalizeFilenameForSafety(filename: string): string {
  return filename.normalize('NFC').replace(/[.\s]+$/u, '')
}

export function filenameExtension(filename: string): string {
  const normalized = normalizeFilenameForSafety(filename)
  const base = normalized.replace(/^.*[\\/]/u, '')
  const dot = base.lastIndexOf('.')
  return dot > 0 ? base.slice(dot + 1).toLowerCase() : ''
}

export function isDangerousFilename(filename: string): boolean {
  return DANGEROUS_EXTENSIONS.has(filenameExtension(filename))
}

export function classifyFileForKutup(input: FileSafetyInput): FileSafetyResult {
  const normalizedFilename = normalizeFilenameForSafety(input.filename)
  const extension = filenameExtension(normalizedFilename)
  const claimedMimeType = canonicalMime(input.mimeType)
  const detected = detectFileSignature(input.bytes)
  const base = { normalizedFilename, extension, claimedMimeType }

  if (!normalizedFilename || normalizedFilename.length > 1024 ||
      /[\0\r\n]/u.test(normalizedFilename) || BIDI_CONTROLS.test(normalizedFilename)) {
    return { ...base, classification: 'mismatch', reason: 'invalid-filename' }
  }
  if (DANGEROUS_EXTENSIONS.has(extension) || ACTIVE_WEB_EXTENSIONS.has(extension)) {
    return { ...base, classification: 'dangerous-active', reason: 'dangerous-extension' }
  }
  if (DANGEROUS_MIME_TYPES.has(claimedMimeType)) {
    return { ...base, classification: 'dangerous-active', reason: 'dangerous-mime' }
  }
  if (detected?.dangerous) {
    return {
      ...base,
      classification: 'dangerous-active',
      detectedMimeType: detected.mimeType,
      reason: 'dangerous-signature',
    }
  }

  const expectedMime = PREVIEW_MIME_BY_EXTENSION[extension]
  // EBML identifies a WebM container, but a bounded header check cannot tell
  // whether its tracks are audio-only. Preserve a trusted audio/webm claim so
  // browser-recorded voice notes reach the audio decoder instead of the video
  // preview path. The decoder remains the final validation boundary.
  const previewMime = extension === 'webm' && claimedMimeType === 'audio/webm'
    ? 'audio/webm'
    : expectedMime
  if (detected && detected.mimeType === 'text/html') {
    return {
      ...base,
      classification: 'dangerous-active',
      detectedMimeType: detected.mimeType,
      reason: 'active-web-signature',
    }
  }

  if (expectedMime) {
    if (!detected || !signaturesAgree(previewMime, detected.mimeType, extension)) {
      return {
        ...base,
        classification: 'mismatch',
        detectedMimeType: detected?.mimeType,
        reason: detected ? 'extension-signature-mismatch' : 'missing-known-signature',
      }
    }
    if (!GENERIC_MIME_TYPES.has(claimedMimeType) &&
        !mimeTypesAgree(previewMime, claimedMimeType, extension)) {
      return {
        ...base,
        classification: 'mismatch',
        detectedMimeType: detected.mimeType,
        reason: 'claimed-mime-mismatch',
      }
    }
    if (previewMime.startsWith('application/vnd.openxmlformats-officedocument.')) {
      if (input.verifiedContainerType === undefined) {
        return {
          ...base,
          classification: 'safe-download-only',
          detectedMimeType: detected.mimeType,
          reason: 'container-verification-required',
        }
      }
      if (input.verifiedContainerType !== extension) {
        return {
          ...base,
          classification: 'mismatch',
          detectedMimeType: detected.mimeType,
          reason: 'container-type-mismatch',
        }
      }
    }
    return {
      ...base,
      classification: 'previewable',
      detectedMimeType: previewMime,
      reason: 'allowlisted-signature',
    }
  }

  if (detected?.previewable) {
    // A known previewable payload disguised with an unrelated extension must
    // not be mounted as active media.
    if (extension) {
      return {
        ...base,
        classification: 'mismatch',
        detectedMimeType: detected.mimeType,
        reason: 'unrecognized-extension-for-previewable-content',
      }
    }
    if (!GENERIC_MIME_TYPES.has(claimedMimeType) &&
        !mimeTypesAgree(detected.mimeType, claimedMimeType, extension)) {
      return {
        ...base,
        classification: 'mismatch',
        detectedMimeType: detected.mimeType,
        reason: 'claimed-mime-mismatch',
      }
    }
    return {
      ...base,
      classification: 'previewable',
      detectedMimeType: detected.mimeType,
      reason: 'allowlisted-signature',
    }
  }

  return {
    ...base,
    classification: 'safe-download-only',
    detectedMimeType: detected?.mimeType,
    reason: DOWNLOAD_ONLY_EXTENSIONS.has(extension)
      ? 'download-only-type'
      : 'unsupported-type',
  }
}

interface DetectedSignature {
  mimeType: string
  previewable: boolean
  dangerous?: boolean
}

export function detectFileSignature(bytes: Uint8Array): DetectedSignature | undefined {
  if (bytes.length === 0) return undefined
  const prefixText = ascii(bytes.subarray(0, Math.min(bytes.length, 256)))
    .replace(/^\ufeff/u, '')
    .trimStart()
    .toLowerCase()
  if (prefixText.startsWith('#!')) {
    return { mimeType: 'application/x-sh', previewable: false, dangerous: true }
  }
  if (prefixText.startsWith('<!doctype html') || prefixText.startsWith('<html') ||
      prefixText.startsWith('<script') || prefixText.startsWith('<iframe')) {
    return { mimeType: 'text/html', previewable: false, dangerous: true }
  }
  if (matches(bytes, [0x4d, 0x5a])) {
    return { mimeType: 'application/vnd.microsoft.portable-executable', previewable: false, dangerous: true }
  }
  if (matches(bytes, [0x7f, 0x45, 0x4c, 0x46])) {
    return { mimeType: 'application/x-executable', previewable: false, dangerous: true }
  }
  if (isMachO(bytes)) {
    return { mimeType: 'application/x-mach-binary', previewable: false, dangerous: true }
  }
  if (matchesAscii(bytes, '%PDF-')) return detected('application/pdf')
  if (matches(bytes, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) {
    return detected('image/png')
  }
  if (matches(bytes, [0xff, 0xd8, 0xff])) return detected('image/jpeg')
  if (matchesAscii(bytes, 'GIF87a') || matchesAscii(bytes, 'GIF89a')) return detected('image/gif')
  if (matchesAscii(bytes, 'BM')) return detected('image/bmp')
  if (matchesAscii(bytes, 'RIFF') && matchesAscii(bytes, 'WEBP', 8)) return detected('image/webp')
  if (matchesAscii(bytes, 'RIFF') && matchesAscii(bytes, 'WAVE', 8)) return detected('audio/wav')
  if (matchesAscii(bytes, 'fLaC')) return detected('audio/flac')
  if (matchesAscii(bytes, 'OggS')) return detected('audio/ogg')
  if (matchesAscii(bytes, 'ID3') || isMpegAudioFrame(bytes)) return detected('audio/mpeg')
  if (isAacAdts(bytes)) return detected('audio/aac')
  if (matches(bytes, [0x1a, 0x45, 0xdf, 0xa3])) return detected('video/webm')
  if (matches(bytes, [0x50, 0x4b, 0x03, 0x04]) ||
      matches(bytes, [0x50, 0x4b, 0x05, 0x06]) ||
      matches(bytes, [0x50, 0x4b, 0x07, 0x08])) {
    return { mimeType: 'application/zip', previewable: false }
  }
  if (bytes.length >= 12 && matchesAscii(bytes, 'ftyp', 4)) {
    const brand = ascii(bytes.subarray(8, 12))
    if (brand === 'avif' || brand === 'avis') return detected('image/avif')
    if (brand === 'M4A ' || brand === 'M4B ') return detected('audio/mp4')
    return detected('video/mp4')
  }
  if (prefixText.startsWith('<svg') || prefixText.startsWith('<?xml')) {
    return { mimeType: 'image/svg+xml', previewable: false }
  }
  return undefined
}

function detected(mimeType: string): DetectedSignature {
  return { mimeType, previewable: true }
}

function signaturesAgree(expected: string, actual: string, extension: string): boolean {
  if (expected === actual) return true
  if (expected.startsWith('application/vnd.openxmlformats-officedocument.') && actual === 'application/zip') {
    return ['docx', 'pptx', 'xlsx'].includes(extension)
  }
  if (expected === 'video/ogg' && actual === 'audio/ogg') return true
  if (extension === 'webm' && expected === 'audio/webm' && actual === 'video/webm') return true
  return false
}

function mimeTypesAgree(expected: string, actual: string, extension: string): boolean {
  if (expected === actual) return true
  if (extension === 'jpg' || extension === 'jpeg') return actual === 'image/jpg'
  if (extension === 'mp3') return actual === 'audio/mp3'
  if (extension === 'ogg' || extension === 'oga' || extension === 'ogv') {
    return actual === 'application/ogg' || actual === 'audio/ogg' || actual === 'video/ogg'
  }
  return false
}

function canonicalMime(value?: string): string {
  return (value ?? '').split(';', 1)[0].trim().toLowerCase()
}

function matches(bytes: Uint8Array, signature: readonly number[], offset = 0): boolean {
  if (bytes.length < offset + signature.length) return false
  return signature.every((byte, index) => bytes[offset + index] === byte)
}

function matchesAscii(bytes: Uint8Array, value: string, offset = 0): boolean {
  if (bytes.length < offset + value.length) return false
  for (let index = 0; index < value.length; index += 1) {
    if (bytes[offset + index] !== value.charCodeAt(index)) return false
  }
  return true
}

function ascii(bytes: Uint8Array): string {
  let output = ''
  for (const byte of bytes) output += byte <= 0x7f ? String.fromCharCode(byte) : '\ufffd'
  return output
}

function isMpegAudioFrame(bytes: Uint8Array): boolean {
  return bytes.length >= 2 && bytes[0] === 0xff && (bytes[1] & 0xe0) === 0xe0
}

function isAacAdts(bytes: Uint8Array): boolean {
  return bytes.length >= 2 && bytes[0] === 0xff && (bytes[1] & 0xf6) === 0xf0
}

function isMachO(bytes: Uint8Array): boolean {
  const magics = [
    [0xfe, 0xed, 0xfa, 0xce], [0xce, 0xfa, 0xed, 0xfe],
    [0xfe, 0xed, 0xfa, 0xcf], [0xcf, 0xfa, 0xed, 0xfe],
    [0xca, 0xfe, 0xba, 0xbe], [0xbe, 0xba, 0xfe, 0xca],
  ]
  return magics.some(magic => matches(bytes, magic))
}
