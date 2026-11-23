import { describe, expect, it } from 'vitest'
import { BUILTIN_ICONS, builtinIcon, GROUP_DEFAULT_ICON } from './builtinIcons'

describe('built-in icons', () => {
  it('draws each of KeePass\'s 69, distinctly', () => {
    expect(BUILTIN_ICONS).toHaveLength(69)
    expect(new Set(BUILTIN_ICONS).size).toBe(69)
    expect(builtinIcon(GROUP_DEFAULT_ICON)).toBe(BUILTIN_ICONS[48])
    expect(builtinIcon(69)).toBeNull()
    expect(builtinIcon(null)).toBeNull()
  })
})
