import { describe, expect, it } from 'vitest'
import { indexForTesting, searchCities } from './cities'

const all = indexForTesting([
  ['Istanbul', '', 'TR', 41.014, 28.95],
  ['İzmir', 'Izmir', 'TR', 38.412, 27.139],
  ['Şanlıurfa', 'Sanliurfa', 'TR', 37.167, 38.794],
  ['Frankfurt am Main', '', 'DE', 50.116, 8.684],
  ['Izmit', '', 'TR', 40.765, 29.941],
])

describe('searchCities', () => {
  it('ignores case, accents and the Turkish i', () => {
    expect(searchCities(all, 'izm').map((c) => c.name)).toEqual(['İzmir', 'Izmit'])
    expect(searchCities(all, 'şanl')[0].name).toBe('Şanlıurfa')
    expect(searchCities(all, 'sanli')[0].name).toBe('Şanlıurfa')
    expect(searchCities(all, 'İSTAN')[0].name).toBe('Istanbul')
  })

  it('finds a later word, after the names that start with the query', () => {
    expect(searchCities(all, 'main').map((c) => c.name)).toEqual(['Frankfurt am Main'])
  })

  it('needs two letters', () => {
    expect(searchCities(all, 'i')).toEqual([])
  })
})
