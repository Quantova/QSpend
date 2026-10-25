// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const F = require('../lib/format');

test('a label keeps one key however its separators, leading zeros and lookalike letters are written', () => {
  const same = [
    ['INV-2026-0042', 'INV20260042', 'INV 2026 0042'],
    ['INV-042', 'INV-42', 'INV-0042', 'INV-OO42'],
    ['INV-1001', 'INV/1OO1', 'ＩＮＶ１００１', 'inv 1001'],
    ['PO 0814', 'PO0814', 'PO-814'],
    ['P.O. 123', 'PO 123', 'PO-123'],
    ['station-012', 'station_12', 'Station 12'],
    ['AB-0111', 'AB-OiIi'],
  ];
  for (const group of same) {
    const keys = new Set(group.map(F.labelKey));
    assert.strictEqual(keys.size, 1, group.join(' | ') + ' gave ' + [...keys].join(' | '));
  }
});

test('a letter O is never dropped as a leading zero and distinct labels keep distinct keys', () => {
  const distinct = [
    ['PO-123', 'P-123'],
    ['PO123', 'P123'],
    ['P.O. 123', 'P-123'],
    ['VAT', 'VAT return'],
    ['INV-1002', 'INV-1001'],
    ['AB-12', 'AB-21'],
  ];
  for (const [a, b] of distinct) assert.notStrictEqual(F.labelKey(a), F.labelKey(b), a + ' and ' + b);
});
