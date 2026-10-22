// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const q = require('..');
const { network, stamper, iso } = require('./chain');

async function world() {
  const now = Math.floor(Date.now() / 1000);
  const net = network(now - 86400);
  const at = stamper(q, net);
  const K = {};
  for (const r of q.ROLES) K[r] = q.generateKey();
  const t0 = now - 80000;
  const app = await at(q.appropriation({ key: K.ministry, budgetRef: 'Act 2026', line: 'roads', period: '2026', currency: 'EUR', amount: '1000000', validUntil: iso(t0 + 1000), approvedAt: iso(t0) }), t0 + 5);
  const roles = Object.fromEntries(Object.entries(K).map(([r, k]) => [r + 'Keys', [q.keyId(k)]]));
  const check = (env, type, more) => {
    net.chain.block(now);
    return q.verify(env, Object.assign({ type, allSupplied: true, records: [app] }, roles, net.opts, more));
  };
  return { K, at, app, t0, check };
}

const period = (r) => r.checks.find((c) => c.name === 'appropriation period');

test('an appropriation states when it lapses and an allotment dated after that is refused at signing', async () => {
  const w = await world();
  assert.throws(() => q.appropriation({ key: w.K.ministry, budgetRef: 'A', line: 'L', period: '2026', currency: 'EUR', amount: '1', validUntil: iso(w.t0), approvedAt: iso(w.t0) }), /lapses only after/);
  assert.throws(() => q.allotment({ ledger: false, key: w.K.budget, appropriation: w.app, unit: 'works', amount: '1000', first: true, allottedAt: iso(w.t0 + 2000) }), /lapsed before this allotment/);
});

test('a record anchored after the appropriation lapsed is invalid, and one without a proven time is indeterminate', async () => {
  const w = await world();
  const inTime = await w.at(q.allotment({ ledger: false, key: w.K.budget, appropriation: w.app, unit: 'works', amount: '1000', first: true, allottedAt: iso(w.t0 + 100) }), w.t0 + 200);
  const ok = await w.check(inTime, 'allotment');
  assert.strictEqual(ok.status, 'valid', JSON.stringify(ok.checks.filter((c) => !c.ok)));
  assert.ok(period(ok).ok);
  const late = await w.at(q.allotment({ ledger: false, key: w.K.budget, appropriation: w.app, unit: 'works', amount: '1000', first: true, allottedAt: iso(w.t0 + 900) }), w.t0 + 1500);
  const bad = await w.check(late, 'allotment', { maxAnchorDelay: 3600 });
  assert.strictEqual(bad.status, 'invalid');
  assert.match(period(bad).detail, /anchored after the appropriation lapsed/);
  const bare = q.allotment({ ledger: false, key: w.K.budget, appropriation: w.app, unit: 'works', amount: '1000', first: true, allottedAt: iso(w.t0 + 300) });
  const open = await w.check(bare, 'allotment');
  assert.strictEqual(open.status, 'indeterminate');
  assert.ok(!period(open).ok && period(open).indeterminate);
  const lax = await w.check(bare, 'allotment', { requireAnchor: false });
  assert.strictEqual(lax.status, 'valid', JSON.stringify(lax.checks.filter((c) => !c.ok)));
});
