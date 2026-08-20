# Tauri icons

Tauri's bundler needs platform-specific icon files at build time
(`32x32.png`, `128x128.png`, `128x128@2x.png`, `icon.icns`, `icon.ico`
plus mobile bits).

The checked-in desktop icon set is generated from `source.png` / `source.svg`.
Regenerate it after an approved brand-artwork change with:

```bash
pnpm tauri:icon src-tauri/icons/source.png
```

That rewrites everything `tauri.conf.json` references. If an experimental
Tauri mobile project has been initialized under `src-tauri/gen/`, it also
refreshes its Android and iOS icon catalogs. The dedicated native mobile apps
are separate work in progress and own their release asset catalogs.

The source artwork (`source.svg` / `source.png`) and all icons
rendered from it are kutup brand assets — see [`/TRADEMARK.md`](../../TRADEMARK.md)
for the brand-use policy. The AGPL covers the surrounding code, not
the artwork.
