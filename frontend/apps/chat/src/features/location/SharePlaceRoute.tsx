import { useEffect, useState } from 'react'
import { Navigate } from 'react-router-dom'
import { openSharedPlace, parseSharedPlace } from '../../lib/sharedPlace'

/** `/share-place#…`: a place sent from Maps; the chats open with a dialog to choose where it goes. */
export function SharePlaceRoute() {
  // Read before <Navigate> (whose effect runs first) replaces the URL.
  const [place] = useState(() => parseSharedPlace(window.location.hash))
  useEffect(() => {
    if (place) openSharedPlace(place)
  }, [place])
  return <Navigate to="/" replace />
}
