/**
 * Folder colours. The stored values are the old palette's names (existing
 * folders keep their colour); the hex is how they render. These are data
 * colours a user picked, not theme tokens.
 */
export const FOLDER_COLORS = [
  { value: 'purple', hex: '#38bdf8', name: 'ice' },
  { value: 'blue', hex: '#0284c7', name: 'ocean' },
  { value: 'green', hex: '#0d9488', name: 'teal' },
  { value: 'amber', hex: '#f59e0b', name: 'amber' },
  { value: 'red', hex: '#ef4444', name: 'red' },
] as const

export function folderHex(color: string | null): string | null {
  return FOLDER_COLORS.find((c) => c.value === color)?.hex ?? null
}
