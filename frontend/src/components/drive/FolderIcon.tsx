const FOLDER_COLORS = [
  { label: 'Ice',   value: 'purple', hex: '#38bdf8' },
  { label: 'Ocean', value: 'blue',   hex: '#0284c7' },
  { label: 'Teal',  value: 'green',  hex: '#0d9488' },
  { label: 'Amber', value: 'amber',  hex: '#f59e0b' },
  { label: 'Red',   value: 'red',    hex: '#ef4444' },
]
export const DEFAULT_FOLDER_COLOR = '#0284c7'
export { FOLDER_COLORS }

export function folderHex(color?: string | null): string {
  return FOLDER_COLORS.find((c) => c.value === color)?.hex ?? DEFAULT_FOLDER_COLOR
}

export function FolderIcon({ color, size = 48 }: { color?: string | null; size?: number }) {
  const fill = folderHex(color)
  return (
    <svg width={size} height={Math.round(size * 0.834)} viewBox="0 0 48 40" fill="none">
      <path
        d="M5,6 L20,6 L24,11 L44,11 Q46,11 46,13 L46,36 Q46,38 44,38 L4,38 Q2,38 2,36 L2,9 Q2,6 5,6 Z"
        fill={fill}
      />
      <path
        d="M5,6 L20,6 L24,11 L2,11 L2,9 Q2,6 5,6 Z"
        fill="white"
        fillOpacity="0.18"
      />
    </svg>
  )
}
