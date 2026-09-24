import { describe, expect, it } from 'vitest'

import { safeNext } from '@/lib/next'

describe('safeNext', () => {
  it('keeps paths inside the dashboard', () => {
    expect(safeNext('/invite/abc')).toBe('/invite/abc')
    expect(safeNext('/w/x/keys?tab=1')).toBe('/w/x/keys?tab=1')
  })

  it('never leads to another site', () => {
    for (const bad of [
      '//evil.example',
      '/\\evil.example',
      'https://evil.example',
      'evil',
      '',
      undefined,
      42,
    ]) {
      expect(safeNext(bad)).toBe('/')
    }
  })
})
