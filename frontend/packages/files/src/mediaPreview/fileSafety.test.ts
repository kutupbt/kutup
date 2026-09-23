import { describe, expect, it } from 'vitest'
import {
  classifyFileForKutup,
  detectFileSignature,
  filenameExtension,
  isDangerousFilename,
  normalizeFilenameForSafety,
} from './fileSafety'

const ascii = (value: string) => new TextEncoder().encode(value)

describe('file safety classification', () => {
  it('requires an allowlisted extension, MIME, and signature to agree', () => {
    const result = classifyFileForKutup({
      filename: 'photo.PNG',
      mimeType: 'image/png; charset=binary',
      bytes: new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    })
    expect(result).toMatchObject({
      classification: 'previewable',
      extension: 'png',
      claimedMimeType: 'image/png',
      detectedMimeType: 'image/png',
    })
  })

  it('downgrades mismatched image content instead of mounting it', () => {
    const result = classifyFileForKutup({
      filename: 'photo.png',
      mimeType: 'image/png',
      bytes: ascii('GIF89a'),
    })
    expect(result).toMatchObject({
      classification: 'mismatch',
      detectedMimeType: 'image/gif',
      reason: 'extension-signature-mismatch',
    })
  })

  it.each([
    'run.exe',
    'run.EXE',
    'run.exe.',
    'run.exe .  .   ',
    'installer.MsI\t',
    'payload.js',
    'mobile.apk',
  ])('blocks dangerous names including Signal-compatible suffix tricks: %s', filename => {
    expect(isDangerousFilename(filename)).toBe(true)
    expect(classifyFileForKutup({ filename, bytes: ascii('unknown') }).classification)
      .toBe('dangerous-active')
  })

  it.each([
    new Uint8Array([0x4d, 0x5a, 0x90, 0x00]),
    new Uint8Array([0x7f, 0x45, 0x4c, 0x46]),
    new Uint8Array([0xfe, 0xed, 0xfa, 0xcf]),
    ascii('#!/bin/sh\necho owned'),
    ascii('<!doctype html><script>alert(1)</script>'),
  ])('blocks dangerous signatures even after a benign rename', bytes => {
    const result = classifyFileForKutup({ filename: 'quarterly-report.pdf', bytes })
    expect(result.classification).toBe('dangerous-active')
  })

  it('keeps SVG and archives download-only', () => {
    expect(classifyFileForKutup({
      filename: 'drawing.svg',
      mimeType: 'image/svg+xml',
      bytes: ascii('<svg xmlns="http://www.w3.org/2000/svg"></svg>'),
    }).classification).toBe('safe-download-only')
    expect(classifyFileForKutup({
      filename: 'bundle.zip',
      mimeType: 'application/zip',
      bytes: new Uint8Array([0x50, 0x4b, 0x03, 0x04]),
    }).classification).toBe('safe-download-only')
  })

  it('preserves audio/webm for browser-recorded voice notes', () => {
    expect(classifyFileForKutup({
      filename: 'voice-note.webm',
      mimeType: 'audio/webm; codecs=opus',
      bytes: new Uint8Array([0x1a, 0x45, 0xdf, 0xa3]),
    })).toMatchObject({
      classification: 'previewable',
      claimedMimeType: 'audio/webm',
      detectedMimeType: 'audio/webm',
    })
  })

  it('requires bounded container verification before allowing OOXML preview', () => {
    const zip = new Uint8Array([0x50, 0x4b, 0x03, 0x04])
    expect(classifyFileForKutup({
      filename: 'slides.pptx',
      mimeType: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
      bytes: zip,
    })).toMatchObject({
      classification: 'safe-download-only',
      reason: 'container-verification-required',
    })
    expect(classifyFileForKutup({
      filename: 'slides.pptx',
      mimeType: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
      bytes: zip,
      verifiedContainerType: 'pptx',
    }).classification).toBe('previewable')
    expect(classifyFileForKutup({
      filename: 'slides.pptx',
      mimeType: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
      bytes: zip,
      verifiedContainerType: 'docx',
    }).classification).toBe('mismatch')
    expect(classifyFileForKutup({
      filename: 'slides.pptx',
      mimeType: 'application/pdf',
      bytes: zip,
    }).classification).toBe('mismatch')
  })

  it('rejects misleading and control-character filenames', () => {
    expect(classifyFileForKutup({
      filename: `report\u202egnp.exe.txt`,
      mimeType: 'text/plain',
      bytes: ascii('hello'),
    }).reason).toBe('invalid-filename')
    expect(classifyFileForKutup({
      filename: 'bad\nname.png',
      bytes: new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    }).classification).toBe('mismatch')
  })

  it('normalizes only trailing dots/whitespace for extension matching', () => {
    expect(normalizeFilenameForSafety('photo.png .  . ')).toBe('photo.png')
    expect(filenameExtension('../archive.tar.gz')).toBe('gz')
  })

  it('detects representative raster, media, document, archive, and executable signatures', () => {
    expect(detectFileSignature(ascii('%PDF-1.7'))?.mimeType).toBe('application/pdf')
    expect(detectFileSignature(ascii('RIFF1234WEBP'))?.mimeType).toBe('image/webp')
    expect(detectFileSignature(ascii('RIFF1234WAVE'))?.mimeType).toBe('audio/wav')
    expect(detectFileSignature(ascii('OggS'))?.mimeType).toBe('audio/ogg')
    expect(detectFileSignature(new Uint8Array([0x50, 0x4b, 0x03, 0x04]))?.mimeType)
      .toBe('application/zip')
    expect(detectFileSignature(new Uint8Array([0x4d, 0x5a]))?.dangerous).toBe(true)
  })
})
