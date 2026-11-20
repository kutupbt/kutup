import * as maplibregl from 'maplibre-gl'
import workerUrl from 'maplibre-gl/dist/maplibre-gl-worker.mjs?worker&url'

// MapLibre's workers come from a file on this origin that the build emits,
// so the apps' policy needs no blob: workers and no eval
// (docs/content-security-policy.md). Left to itself MapLibre would look for
// its worker beside its own module, which the bundle does not keep.
maplibregl.setWorkerUrl(workerUrl)

export { maplibregl }
