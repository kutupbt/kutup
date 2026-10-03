// @vitest-environment jsdom
import { describe, expect, it } from 'vitest'
import { encodeListJson, type Place } from './list'
import { readPlaceFile, toGpx, toKml, UnreadablePlaceFile } from './exchange'

const fallback = (n: number) => `Place ${n}`
const place = (name: string, note: string, lat: number, lon: number): Place => ({
  id: name.toLowerCase().replace(/\W/g, '') || 'x',
  name,
  note,
  lat,
  lon,
  addedBy: 'a@example.org',
  addedAt: '2026-01-01T00:00:00Z',
})

describe('KML and GPX', () => {
  it('reads Google My Maps KML: points in, lines counted out', () => {
    const kml = `<?xml version="1.0"?>
      <kml xmlns="http://www.opengis.net/kml/2.2"><Document><name>Trip</name>
        <Folder><Placemark><name>Cafe</name><description><![CDATA[Good <b>coffee</b>]]></description>
          <Point><coordinates>28.97,41.02,0</coordinates></Point></Placemark></Folder>
        <Placemark><Point><coordinates> 29.0 , 41.1 </coordinates></Point></Placemark>
        <Placemark><name>Walk</name><LineString><coordinates>1,1 2,2</coordinates></LineString></Placemark>
      </Document></kml>`
    expect(readPlaceFile(kml, fallback)).toEqual({
      title: 'Trip',
      places: [
        { name: 'Cafe', note: 'Good coffee', lat: 41.02, lon: 28.97 },
        { name: 'Place 2', note: '', lat: 41.1, lon: 29.0 },
      ],
      skipped: 1,
    })
  })

  it('reads GPX waypoints and counts routes and tracks out', () => {
    const gpx = `<gpx version="1.1" xmlns="http://www.topografix.com/GPX/1/1">
      <metadata><name>Hike</name></metadata>
      <wpt lat="46.5" lon="7.9"><name>Summit</name><desc>View</desc></wpt>
      <wpt lat="95" lon="7.9"><name>Nowhere</name></wpt>
      <trk><name>Path</name></trk></gpx>`
    expect(readPlaceFile(gpx, fallback)).toEqual({
      title: 'Hike',
      places: [{ name: 'Summit', note: 'View', lat: 46.5, lon: 7.9 }],
      skipped: 2,
    })
  })

  it('round-trips its own KML and GPX, notes and awkward names included', () => {
    const places = [place('Tom & Jerry’s <bar>', 'Line one\nline "two"', 41.5, -2.25), place('Plain', '', -33.9, 151.2)]
    for (const text of [toKml('A & B', places), toGpx('A & B', places)]) {
      const back = readPlaceFile(text, fallback)
      expect(back.title).toBe('A & B')
      expect(back.places).toEqual(places.map(({ name, note, lat, lon }) => ({ name, note, lat, lon })))
      expect(back.skipped).toBe(0)
    }
  })

  it('reads a downloaded Kutup list and refuses anything else', () => {
    const json = new TextDecoder().decode(encodeListJson([place('Here', '', 1, 2)]))
    expect(readPlaceFile(json, fallback).places.map((p) => p.name)).toEqual(['Here'])
    expect(() => readPlaceFile('<html><body/></html>', fallback)).toThrow(UnreadablePlaceFile)
    expect(() => readPlaceFile('not xml at all <', fallback)).toThrow(UnreadablePlaceFile)
    expect(() => readPlaceFile('{"format":"other"}', fallback)).toThrow(UnreadablePlaceFile)
  })
})
