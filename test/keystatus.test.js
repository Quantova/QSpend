// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const q = require('..');

const iso = (ms) => new Date(ms).toISOString();

test('a revoked key backdating an unanchored record never verifies valid', async () => {
  const stolen = q.generateKey();
  const now = Date.now();
  const app = q.appropriation({ key: stolen, budgetRef: 'B-2026', line: 'L1', period: '2026', currency: 'EUR', amount: '999999999', validUntil: iso(now + 86400e3), approvedAt: iso(now - 2 * 86400e3) });
  const r = await q.verify(app, {
    type: 'appropriation', ministryKeys: [q.describeKey(stolen)], requireAnchor: false, at: iso(now),
    keyStatus: async () => ({ revoked: true, revokedAt: Math.floor((now - 3600e3) / 1000) }),
  });
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.status, 'indeterminate');
});

test('a revoked key anywhere in the chain of authority makes the dependent record invalid', async () => {
  const ministry = q.generateKey();
  const budget = q.generateKey();
  const now = Date.now();
  const app = q.appropriation({ key: ministry, budgetRef: 'B', line: 'L', period: '2026', currency: 'EUR', amount: '900000000', validUntil: iso(now + 86400e3), approvedAt: iso(now - 3600e3) });
  const allot = q.allotment({ ledger: false, key: budget, appropriation: app, unit: 'works', amount: '900000000', first: true, allottedAt: iso(now - 1800e3) });
  const ministryId = q.keyId(ministry);
  let calls = 0;
  const keyStatus = async (id) => {
    calls += 1;
    return id === ministryId ? { revoked: true, revokedAt: Math.floor((now - 7200e3) / 1000) } : { revoked: false };
  };
  const common = { ministryKeys: [q.describeKey(ministry)], budgetKeys: [q.describeKey(budget)], requireAnchor: false, at: iso(now), allSupplied: true, keyStatus };
  const r = await q.verify(allot, Object.assign({ type: 'allotment', records: [app] }, common));
  assert.strictEqual(r.status, 'invalid');
  assert.ok(r.checks.some((c) => c.name === 'appropriation key status' && !c.ok));
  assert.strictEqual(calls, 2);
});
