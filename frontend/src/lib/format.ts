export function formatBytes(bytes: number): string {
  const KB = 1024
  const MB = KB * 1024
  const GB = MB * 1024
  const TB = GB * 1024
  const PB = TB * 1024
  if (bytes < KB) return `${bytes} B`
  if (bytes < MB) return `${(bytes / KB).toFixed(1)} KB`
  if (bytes < GB) return `${(bytes / MB).toFixed(1)} MB`
  if (bytes < TB) return `${(bytes / GB).toFixed(2)} GB`
  if (bytes < PB) return `${(bytes / TB).toFixed(2)} TB`
  return `${(bytes / PB).toFixed(2)} PB`
}

export function formatSpeed(bps: number): string {
  if (bps <= 0) return ''
  if (bps < 1024) return `${bps} B/s`
  if (bps < 1024 * 1024) return `${(bps / 1024).toFixed(1)} KB/s`
  return `${(bps / 1024 / 1024).toFixed(1)} MB/s`
}

export async function copyText(text: string): Promise<void> {
  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(text)
  }
  const ta = document.createElement('textarea')
  ta.value = text
  ta.style.cssText = 'position:fixed;opacity:0'
  document.body.appendChild(ta)
  ta.focus()
  ta.select()
  document.execCommand('copy')
  document.body.removeChild(ta)
}
