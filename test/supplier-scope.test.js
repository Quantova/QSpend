// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const q = require('..');
const F = require('../lib/format');
const { network, stamper, iso } = require('./chain');

async function government() {
  const now = Math.floor(Date.now() / 1000);
  const net = network(now - 86400);
  const at = stamper(q, net);
  const K = {};
  for (const r of q.ROLES) K[r] = q.generateKey();
  const secret = new Uint8Array(32).fill(6);
  const t0 = now - 80000;
  let n = 0;
  const next = () => {
    n += 10;
    return t0 + n;
  };
  const line = async (name) => {
    let t = next();
    const app = await at(q.appropriation({ key: K.ministry, budgetRef: 'Act ' + name, line: name, period: '2026', currency: 'EUR', amount: '1000000', validUntil: iso(now + 86400), approvedAt: iso(t) }), t + 1);
    t = next();
    const allot = await at(q.allotment({ key: K.budget, appropriation: app, unit: name, amount: '1000000', first: true, allottedAt: iso(t) }), t + 1);
    return { app, allot };
  };
  const chainOf = async (l, supplier, number) => {
    let t = next();
    const com = await at(q.commitment({ key: K.officer, allotment: l.allot, supplier, partySecret: secret, document: Buffer.from('po ' + t), amount: '50000', first: true, committedAt: iso(t) }), t + 1);
    t = next();
    const rec = await at(q.receipt({ key: K.receiver, commitment: com, document: Buffer.from('grn ' + t), receivedAt: iso(t) }), t + 1);
    t = next();
    const inv = await at(q.invoice({ key: K.intake, commitment: com, receipt: rec, invoiceNumber: number, document: Buffer.from('scan ' + t), amount: '20000', receivedAt: iso(t) }), t + 1);
    t = next();
    const pay = await at(q.payment({ key: K.treasury, commitment: com, invoice: inv, first: true, paidAt: iso(t) }), t + 1);
    return [com, rec, inv, pay];
  };
  const roles = Object.fromEntries(Object.entries(K).map(([r, k]) => [r + 'Keys', [q.keyId(k)]]));
  const check = (p, records) => {
    net.chain.block(now);
    return q.verify(p, Object.assign({ type: 'payment', allSupplied: true, records }, roles, net.opts));
  };
  return { K, secret, line, chainOf, check };
}

test('a supplier keeps one commitment across every appropriation of the government', async () => {
  const g = await government();
  const roads = await g.line('roads');
  const schools = await g.line('schools');
  const [c1] = await g.chainOf(roads, 'ACME BV', 'INV-1001');
  const [c2] = await g.chainOf(schools, 'acme b.v.', 'INV-1002');
  assert.strictEqual(c1.statement.supplierRef, c2.statement.supplierRef);
  assert.strictEqual(c1.statement.partyScheme, F.PARTY_SCHEME);
  assert.strictEqual(c1.statement.supplierRef, q.commitParty('ACME BV', { secret: g.secret, scope: 'supplier' }).ref);
  assert.notStrictEqual(c1.statement.supplierRef, q.commitParty('ACME BV', { secret: g.secret, scope: q.refOf(roads.app) }).ref);
  assert.throws(() => q.commitment({ key: g.K.officer, allotment: roads.allot, supplierRef: q.commitParty('ACME BV').ref, document: Buffer.from('po'), amount: '1', first: true }), /partySecret/);
  const st = Object.assign({}, c1.statement, { partyScheme: 'random-salt/1' });
  assert.match(F.statementProblem('commitment', st), /secret of the authority/);
});

test('one invoice of a supplier paid again under another appropriation is invalid', async () => {
  const g = await government();
  const roads = await g.line('roads');
  const schools = await g.line('schools');
  const first = await g.chainOf(roads, 'ACME BV', 'INV-1001');
  const second = await g.chainOf(schools, 'ACME B.V.', 'INV 1001');
  const records = [roads.app, roads.allot, schools.app, schools.allot].concat(first, second.slice(0, 3));
  const r = await g.check(second[3], records);
  assert.strictEqual(r.status, 'invalid');
  assert.ok(r.checks.some((c) => c.name === 'invoice paid once' && !c.ok && !c.indeterminate));
  const other = await g.chainOf(schools, 'Other Ltd', 'INV-1001');
  const open = await g.check(other[3], [roads.app, roads.allot, schools.app, schools.allot].concat(first, other.slice(0, 3)));
  assert.strictEqual(open.status, 'indeterminate');
  assert.ok(open.checks.some((c) => c.name === 'invoice paid once' && !c.ok && c.indeterminate));
});
