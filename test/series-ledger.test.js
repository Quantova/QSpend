// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const test = require('node:test');
const assert = require('node:assert');
const { honest } = require('./honest');
const { iso } = require('./chain');

const dirs = [];
test.after(() => {
  for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
});

function folder() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'qspend-series-'));
  dirs.push(d);
  return d;
}

const refused = (e) => e.code === 'QSPEND_LEDGER';

test('with a ledger a second first allotment and an allotment after a stale previous are refused', async () => {
  const w = await honest();
  const { q, K, all } = w;
  const dir = folder();
  const allot = (amount, more) => q.allotment(Object.assign({ key: K.budget, appropriation: all.appropriation, unit: 'works', amount, allottedAt: iso(w.now - 60), ledger: dir }, more));
  const a1 = await allot('100000', { first: true });
  await assert.rejects(allot('600000', { first: true }), refused);
  const a2 = await allot('100000', { previous: a1 });
  assert.strictEqual(a2.statement.seq, 2);
  await assert.rejects(allot('100000', { previous: a1 }), refused);
  const racers = await Promise.allSettled(Array.from({ length: 6 }, () => allot('1000', { previous: a2 })));
  assert.strictEqual(racers.filter((r) => r.status === 'fulfilled').length, 1);
  assert.ok(racers.filter((r) => r.status === 'rejected').every((r) => refused(r.reason)));
  const latest = await q.ledgerLatest(dir, 'allotment', q.refOf(all.appropriation));
  assert.strictEqual(latest.statement.seq, 3);
  assert.deepStrictEqual(latest, racers.find((r) => r.status === 'fulfilled').value);
  const plain = q.allotment({ key: K.budget, appropriation: all.appropriation, unit: 'works', amount: '1000', first: true, allottedAt: iso(w.now - 60) });
  assert.strictEqual(typeof plain.then, 'undefined');
});

test('with a ledger two treasury officers cannot both pay the first payment of a commitment', async () => {
  const w = await honest();
  const { q, K, all } = w;
  const m = new Map();
  const store = {
    async read(name) {
      return m.has(name) ? m.get(name) : null;
    },
    async compareAndSwap(name, expected, next) {
      await new Promise((resolve) => setImmediate(resolve));
      if ((m.has(name) ? m.get(name) : null) !== expected) return false;
      m.set(name, next);
      return true;
    },
  };
  const officers = [K.treasury, q.generateKey()];
  const results = await Promise.allSettled(officers.map((key) => q.payment({ key, commitment: all.commitment, invoice: all.invoice, first: true, paidAt: iso(w.now - 60), ledger: store })));
  assert.strictEqual(results.filter((r) => r.status === 'fulfilled').length, 1);
  assert.ok(refused(results.find((r) => r.status === 'rejected').reason));
});
