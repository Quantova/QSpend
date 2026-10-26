// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const F = require('../lib/format');

test('leading zeros of a digit group, separators around it and lookalike letters do not change the key', () => {
  const same = [
    ['INV-2026-0042', 'INV-2026-42', 'INV 2026 0042', 'INV/2026/0042'],
    ['2025-01', '2025-1'],
    ['AB-0110', 'AB0110', 'AB-110'],
    ['INV-042', 'INV-42', 'INV-0042', 'INV-OO42'],
    ['station-012', 'station_12', 'Station 12'],
    ['PO 0814', 'PO0814', 'PO-814'],
  ];
  for (const group of same) {
    const keys = new Set(group.map(F.labelKey));
    assert.strictEqual(keys.size, 1, group.join(' | ') + ' gave ' + [...keys].join(' | '));
  }
});

test('a digit-group boundary is kept so joining or splitting digits never collides two labels', () => {
  const distinct = [
    ['INV-2026-0042', 'INV20260042'],
    ['2025-1', '20251'],
    ['INV-1-23', 'INV-12-3'],
    ['INV-1-0', 'INV-10'],
    ['2025-11', '2025-1-1'],
    ['INV-1001', 'INV-1002'],
    ['AB-12', 'AB-21'],
  ];
  for (const [a, b] of distinct) assert.notStrictEqual(F.labelKey(a), F.labelKey(b), a + ' and ' + b + ' share a key');
});
