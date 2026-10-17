// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const q = require('..');
const { network, stamper, iso, failing } = require('./chain');

async function ledger() {
  const now = Math.floor(Date.now() / 1000);
  const net = network(now - 86400);
  const at = stamper(q, net);
  const K = {};
  for (const r of ['ministry', 'budget', 'officer', 'receiver', 'intake', 'treasury']) K[r] = q.generateKey();
  const t0 = now - 80000;
  const app = await at(q.appropriation({ key: K.ministry, budgetRef: 'B1', line: 'roads', period: '2026', currency: 'EUR', amount: '1000000', approvedAt: iso(t0) }), t0 + 5);
  const allot = await at(q.allotment({ key: K.budget, appropriation: app, unit: 'works', amount: '1000000', first: true, allottedAt: iso(t0 + 10) }), t0 + 15);
  const secret = new Uint8Array(32).fill(4);
  const supplier = (name) => q.commitParty(name, { secret, scope: q.refOf(app) }).ref;
  let n = 0;
  const next = () => {
    n += 10;
    return t0 + 20 + n;
  };
  const commitment = async (name, previous) => {
    const t = next();
    return at(q.commitment(Object.assign({ key: K.officer, allotment: allot, supplierRef: supplier(name), document: Buffer.from('po ' + t), amount: '50000', committedAt: iso(t) }, previous ? { previous } : { first: true })), t + 1);
  };
  const receipt = async (c) => {
    const t = next();
    return at(q.receipt({ key: K.receiver, commitment: c, document: Buffer.from('grn ' + t), receivedAt: iso(t) }), t + 1);
  };
  const invoice = async (c, rec, number, doc) => {
    const t = next();
    return at(q.invoice({ key: K.intake, commitment: c, receipt: rec, invoiceNumber: number, document: Buffer.from(doc || 'scan ' + t), amount: '20000', receivedAt: iso(t) }), t + 1);
  };
  const payment = async (c, inv, previous) => {
    const t = next();
    return at(q.payment(Object.assign({ key: K.treasury, commitment: c, invoice: inv, paidAt: iso(t) }, previous ? { previous } : { first: true })), t + 1);
  };
  const roles = { ministryKeys: [q.keyId(K.ministry)], budgetKeys: [q.keyId(K.budget)], officerKeys: [q.keyId(K.officer)], receiverKeys: [q.keyId(K.receiver)], intakeKeys: [q.keyId(K.intake)], treasuryKeys: [q.keyId(K.treasury)] };
  const check = (p, records) => {
    net.chain.block(now);
    return q.verify(p, Object.assign({ type: 'payment', allSupplied: true, records: [app, allot].concat(records) }, roles, net.opts));
  };
  return { commitment, receipt, invoice, payment, check };
}

test('an invoice number written with lookalike letters or other separators cannot be paid twice under one commitment', async () => {
  const l = await ledger();
  const c = await l.commitment('ACME BV');
  const rec = await l.receipt(c);
  const i1 = await l.invoice(c, rec, 'INV-1001');
  const p1 = await l.payment(c, i1);
  for (const variant of ['ІNV‑1001', 'inv 1001', 'INV/1OO1', 'ＩＮＶ１００１']) {
    const i2 = await l.invoice(c, rec, variant);
    const p2 = await l.payment(c, i2, p1);
    const r = await l.check(p2, [c, rec, i1, i2, p1]);
    assert.strictEqual(r.status, 'invalid', variant + '\n' + failing(r).join('\n'));
    assert.ok(r.checks.some((x) => x.name === 'invoice paid once' && !x.ok));
  }
});

test('one invoice of a supplier cannot be paid again under another commitment', async () => {
  const l = await ledger();
  const cA = await l.commitment('ACME BV');
  const cB = await l.commitment('acme b.v.', cA);
  const recA = await l.receipt(cA);
  const recB = await l.receipt(cB);
  const i1 = await l.invoice(cA, recA, 'INV-1001');
  const i2 = await l.invoice(cB, recB, 'inv1001');
  const p1 = await l.payment(cA, i1);
  const p2 = await l.payment(cB, i2);
  const r = await l.check(p2, [cA, cB, recA, recB, i1, i2, p1]);
  assert.strictEqual(r.status, 'invalid', failing(r).join('\n'));
  assert.ok(r.checks.some((x) => x.name === 'invoice paid once' && /another commitment/.test(x.detail)));
});

test('the same invoice document cannot be paid under two commitments of different suppliers', async () => {
  const l = await ledger();
  const cA = await l.commitment('ACME BV');
  const cB = await l.commitment('Other Ltd', cA);
  const recA = await l.receipt(cA);
  const recB = await l.receipt(cB);
  const i1 = await l.invoice(cA, recA, 'INV-1001', 'the same scan');
  const i2 = await l.invoice(cB, recB, 'X-77', 'the same scan');
  const p1 = await l.payment(cA, i1);
  const p2 = await l.payment(cB, i2);
  const r = await l.check(p2, [cA, cB, recA, recB, i1, i2, p1]);
  assert.strictEqual(r.status, 'invalid', failing(r).join('\n'));
});

test('equal invoice numbers of different suppliers are paid normally', async () => {
  const l = await ledger();
  const cA = await l.commitment('ACME BV');
  const cB = await l.commitment('Other Ltd', cA);
  const recA = await l.receipt(cA);
  const recB = await l.receipt(cB);
  const i1 = await l.invoice(cA, recA, '1001');
  const i2 = await l.invoice(cB, recB, '1001');
  const p1 = await l.payment(cA, i1);
  const p2 = await l.payment(cB, i2);
  const r = await l.check(p2, [cA, cB, recA, recB, i1, i2, p1]);
  assert.strictEqual(r.status, 'valid', failing(r).join('\n'));
});
