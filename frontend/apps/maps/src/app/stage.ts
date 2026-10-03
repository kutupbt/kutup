import { createContext, useContext, useEffect, useRef } from 'react'
import type { MapMarker, MapPoint } from '@kutup/map/MapView'

// The map stays in place while the side panel changes (your maps, one
// list): each panel says what the map shows through this stage.

export interface Scene {
  markers: MapMarker[]
  selectedId: string | null
  /** Frame the markers again whenever this changes. */
  fitKey: string | null
  /** Clicks on the map choose a point (adding a place). */
  picking: boolean
  label: string
}

export interface SceneHandlers {
  onMarkerClick?: (id: string) => void
  onPick?: (point: MapPoint) => void
}

export interface Stage {
  show: (scene: Scene, handlers: SceneHandlers) => void
  focus: (point: MapPoint, zoom: number) => void
}

export const StageContext = createContext<Stage | null>(null)

export function useStage(): Stage {
  const stage = useContext(StageContext)
  if (!stage) throw new Error('useStage outside the maps layout')
  return stage
}

/** Show `scene` on the map while this panel is open. Handlers may change every render. */
export function useMapScene(scene: Scene, handlers: SceneHandlers): void {
  const stage = useStage()
  const latest = useRef(handlers)
  latest.current = handlers
  useEffect(() => {
    stage.show(scene, {
      onMarkerClick: (id) => latest.current.onMarkerClick?.(id),
      onPick: (point) => latest.current.onPick?.(point),
    })
    // The scene's parts, not its identity: a panel builds a new object each render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [stage, scene.markers, scene.selectedId, scene.fitKey, scene.picking, scene.label])
}
