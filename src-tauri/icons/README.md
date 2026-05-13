# Tauri icons

Tauri's bundler needs platform-specific icon files at build time
(`32x32.png`, `128x128.png`, `128x128@2x.png`, `icon.icns`, `icon.ico`
plus mobile bits).

To generate the full set from a single 1024×1024 source PNG of the
Kutup logo:

```bash
pnpm tauri:icon path/to/source.png
```

That writes everything `tauri.conf.json` references plus the
`gen/android/.../mipmap-*` and iOS `AppIcon.appiconset` assets.

For now the build will fail to bundle release artifacts until the
real icons land here; `pnpm tauri:dev` works without them.

The source artwork (`source.svg` / `source.png`) and all icons
rendered from it are kutup brand assets — see [`/TRADEMARK.md`](../../TRADEMARK.md)
for the brand-use policy. The AGPL covers the surrounding code, not
the artwork.
