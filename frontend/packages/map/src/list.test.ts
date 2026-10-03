import { describe, expect, it } from 'vitest'
import * as Y from 'yjs'
import {
  addPlace,
  encodeListJson,
  fillDoc,
  listTitle,
  NotAPlaceList,
  parseListJson,
  placesOf,
  removePlace,
  replacePlaces,
  stateToListJson,
  updatePlace,
  type Place,
} from './list'

const place = (id: string, name: string, at: string): Place => ({
  id,
  name,
  note: '',
  lat: 41.0,
  lon: 29.0,
  addedBy: 'alice@example.org',
  addedAt: at,
})

describe('place lists', () => {
  it('round-trips through JSON in list order', () => {
    const places = [place('b', 'Second', '2026-01-02T00:00:00Z'), place('a', 'First', '2026-01-01T00:00:00Z')]
    expect(parseListJson(encodeListJson(places)).map((p) => p.id)).toEqual(['a', 'b'])
  })

  it('treats an empty upload as an empty list and rejects other files', () => {
    expect(parseListJson(new Uint8Array())).toEqual([])
    expect(parseListJson(new Uint8Array([0]))).toEqual([])
    expect(() => parseListJson(new TextEncoder().encode('{"format":"other"}'))).toThrow(NotAPlaceList)
    expect(() => parseListJson(new TextEncoder().encode('not json'))).toThrow(NotAPlaceList)
  })

  it('drops places with impossible coordinates or no name', () => {
    const bytes = new TextEncoder().encode(
      JSON.stringify({
        format: 'kutupmap',
        version: 1,
        places: [
          { id: 'ok', name: 'Here', lat: 10, lon: 20, addedAt: '2026-01-01T00:00:00Z' },
          { id: 'north', name: 'Too far', lat: 91, lon: 0 },
          { id: 'nameless', name: '  ', lat: 0, lon: 0 },
          { id: 'ok', name: 'Duplicate id', lat: 0, lon: 0 },
        ],
      }),
    )
    expect(parseListJson(bytes).map((p) => p.id)).toEqual(['ok'])
  })

  it('edits a live list and merges two editors', () => {
    const a = new Y.Doc()
    const b = new Y.Doc()
    a.on('update', (u: Uint8Array) => Y.applyUpdate(b, u))
    b.on('update', (u: Uint8Array) => Y.applyUpdate(a, u))
    addPlace(a, place('1', 'Cafe', '2026-01-01T00:00:00Z'))
    addPlace(b, place('2', 'Park', '2026-01-02T00:00:00Z'))
    updatePlace(b, '1', { name: 'Better cafe', lat: 40 })
    removePlace(a, '2')
    expect(placesOf(a)).toEqual(placesOf(b))
    expect(placesOf(a)).toEqual([{ ...place('1', 'Better cafe', '2026-01-01T00:00:00Z'), lat: 40 }])
  })

  it('restores an old state and exports a saved one', () => {
    const old = new Y.Doc()
    fillDoc(old, [place('x', 'Old', '2026-01-01T00:00:00Z')])
    const live = new Y.Doc()
    addPlace(live, place('y', 'New', '2026-02-01T00:00:00Z'))
    replacePlaces(live, old)
    expect(placesOf(live).map((p) => p.id)).toEqual(['x'])
    expect(parseListJson(stateToListJson(Y.encodeStateAsUpdateV2(live))).map((p) => p.name)).toEqual(['Old'])
  })

  it('titles a list by its file name', () => {
    expect(listTitle('Trip.kutupmap')).toBe('Trip')
    expect(listTitle('notes.md')).toBe('notes.md')
  })
})
