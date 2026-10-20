'use strict';

const crypto = require('crypto');
const test = require('node:test');
const assert = require('node:assert');
const q = require('..');
const F = require('../lib/format');
const native = require('../lib/native');
const { network, stamper, iso, failing } = require('./chain');
const { mulberry32, iterations } = require('./fuzz');
const { variantOf } = require('./variants');

const CODE = F.NAME.toUpperCase() + '_';

function rawSign(type, st, key) {
  const problem = F.statementProblem(type, st);
  if (problem) throw new Error(problem);
  const sig = native.sign(key, F.payload(type, st), crypto.randomBytes(32));
  return { format: F.FORMAT, type, algorithm: F.ALGORITHM, signer: { id: q.keyId(key), publicKey: Buffer.from(q.publicKey(key)).toString('base64') }, statement: st, signature: Buffer.from(sig).toString('base64') };
}

async function books(rng) {
  const int = (n) => Math.floor(rng() * n);
  const now = Math.floor(Date.now() / 1000);
  const net = network(now - 86400);
  const at = stamper(q, net);
  const K = {};
  for (const r of q.ROLES) K[r] = q.generateKey();
  const roles = Object.fromEntries(Object.entries(K).map(([r, k]) => [r + 'Keys', [q.keyId(k)]]));
  let t = now - 80000;
  const next = () => (t += 20);
  const app = await at(q.appropriation({ key: K.ministry, budgetRef: 'B', line: 'L', period: '2026', currency: 'EUR', amount: '100000000', validUntil: iso(now + 86400), approvedAt: iso(next()) }), t + 1);
  const allot = await at(q.allotment({ key: K.budget, appropriation: app, unit: 'u', amount: '100000000', first: true, allottedAt: iso(next()) }), t + 1);
  const secret = Uint8Array.from({ length: 32 }, (_, i) => (1 + int(200) + i) & 255);
  const cap = 1000 + int(90000);
  const com = await at(q.commitment({ key: K.officer, allotment: allot, supplier: 'ACME BV', partySecret: secret, document: Buffer.from('po ' + cap), amount: String(cap), first: true, committedAt: iso(next()) }), t + 1);
  const com2 = await at(q.commitment({ key: K.officer, allotment: allot, supplier: 'acme b.v.', partySecret: secret, document: Buffer.from('po2 ' + cap), amount: String(cap), previous: com, committedAt: iso(next()) }), t + 1);
  const rec = await at(q.receipt({ key: K.receiver, commitment: com, document: Buffer.from('grn'), receivedAt: iso(next()) }), t + 1);
  const rec2 = await at(q.receipt({ key: K.receiver, commitment: com2, document: Buffer.from('grn2'), receivedAt: iso(next()) }), t + 1);
  const invoice = (c, r, number, amount, doc) => at(q.invoice({ key: K.intake, commitment: c, receipt: r, invoiceNumber: number, document: Buffer.from(doc || 'scan ' + number + ' ' + t), amount: String(amount), receivedAt: iso(next()) }), t + 1);
  const pay = (c, inv, previous) => at(q.payment(Object.assign({ key: K.treasury, commitment: c, invoice: inv, paidAt: iso(next()) }, previous ? { previous } : { first: true })), t + 1);
  const forge = (fields, previous) => {
    const last = previous ? F.parse(previous).statement : null;
    const st = {
      paymentId: crypto.randomBytes(16).toString('hex'), treasuryKeyId: q.keyId(K.treasury), commitmentRef: fields.commitmentRef, invoiceRef: fields.invoiceRef, currency: 'EUR', amount: fields.amount,
      seq: last ? last.seq + 1 : 1, prevPaymentRef: last ? q.refOf(previous) : '', paidTotal: last ? String(BigInt(last.paidTotal) + BigInt(fields.amount)) : fields.amount, paidAt: iso(next()), note: '',
    };
    return at(rawSign('payment', st, K.treasury), t + 1);
  };
  const base = [app, allot, com, com2, rec, rec2];
  const check = (p, records) => {
    net.chain.block(now);
    return q.verify(p, Object.assign({ type: 'payment', at: iso(now), allSupplied: true, records: base.concat(records) }, roles, net.opts));
  };
  return { int, cap, com, com2, rec, rec2, invoice, pay, forge, check, next };
}

const ROUNDS = iterations(20);

test('payments under a commitment never total more than the commitment, whether made through the library or signed directly', async (t) => {
  const rng = mulberry32(0x5bead);
  let refusedByLibrary = 0;
  let refusedByVerify = 0;
  for (let round = 0; round < ROUNDS; round += 1) {
    const b = await books(rng);
    const n = 1 + b.int(4);
    let prev = null;
    let paid = 0n;
    const records = [];
    for (let i = 0; i < n; i += 1) {
      const amount = 1 + b.int(Math.floor(b.cap / n));
      const inv = await b.invoice(b.com, b.rec, 'INV-' + round + '-' + i, amount);
      prev = await b.pay(b.com, inv, prev);
      paid += BigInt(amount);
      records.push(inv, prev);
    }
    const honest = await b.check(prev, records);
    assert.strictEqual(honest.status, 'valid', failing(honest).join('\n'));
    const left = BigInt(b.cap) - paid;
    const over = left + 1n + BigInt(b.int(1000));
    const capAmount = over > BigInt(b.cap) ? BigInt(b.cap) : over;
    const bigInv = await b.invoice(b.com, b.rec, 'INV-over-' + round, capAmount);
    await assert.rejects(async () => b.pay(b.com, bigInv, prev), (e) => typeof e.code === 'string' && e.code.startsWith(CODE));
    refusedByLibrary += 1;
    const forged = await b.forge({ commitmentRef: q.refOf(b.com), invoiceRef: q.refOf(bigInv), amount: String(capAmount) }, prev);
    const r = await b.check(forged, records.concat([bigInv]));
    assert.notStrictEqual(r.status, 'valid', 'a payment taking the total to ' + (paid + capAmount) + ' above ' + b.cap + ' verified valid');
    assert.ok(r.checks.some((c) => c.name === 'running total' && !c.ok), failing(r).join('\n'));
    refusedByVerify += 1;
  }
  t.diagnostic(JSON.stringify({ rounds: ROUNDS, refusedByLibrary, refusedByVerify }));
});

test('an invoice is paid at most once, also when its number is written in another canonical form or paid under another commitment of the same supplier', async (t) => {
  const rng = mulberry32(0x1a40c);
  const counts = { repeat: 0, variant: 0, otherCommitment: 0, sameDocument: 0 };
  for (let round = 0; round < ROUNDS; round += 1) {
    const b = await books(rng);
    const number = ['INV-', 'AB-', '2026/', 'PO '][b.int(4)] + String(1000 + b.int(9000)).replace(/[2-9]/g, (d) => (rng() < 0.4 ? ['0', '1'][b.int(2)] : d));
    const amount = 1 + b.int(Math.floor(b.cap / 4));
    const inv = await b.invoice(b.com, b.rec, number, amount);
    const p1 = await b.pay(b.com, inv);
    const records = [inv, p1];
    const again = await b.forge({ commitmentRef: q.refOf(b.com), invoiceRef: q.refOf(inv), amount: String(amount) }, p1);
    const ra = await b.check(again, records);
    assert.strictEqual(ra.status, 'invalid', 'the same invoice record paid twice verified ' + ra.status);
    counts.repeat += 1;
    for (let k = 0; k < 3; k += 1) {
      const v = variantOf(rng, number);
      assert.ok(F.sameIdentifier(v, number), JSON.stringify(v) + ' should share the canonical form of ' + number);
      const vinv = await b.invoice(b.com, b.rec, v, 1);
      const p2 = await b.pay(b.com, vinv, p1);
      const r2 = await b.check(p2, records.concat([vinv]));
      assert.strictEqual(r2.status, 'invalid', 'the invoice number ' + JSON.stringify(v) + ' was paid again after ' + number);
      assert.ok(r2.checks.some((c) => c.name === 'invoice paid once' && !c.ok), failing(r2).join('\n'));
      counts.variant += 1;
      const vinv2 = await b.invoice(b.com2, b.rec2, variantOf(rng, number), 1);
      const p3 = await b.pay(b.com2, vinv2);
      const r3 = await b.check(p3, records.concat([vinv2]));
      assert.strictEqual(r3.status, 'invalid', 'the invoice number was paid again under another commitment of the same supplier');
      assert.ok(r3.checks.some((c) => c.name === 'invoice paid once' && !c.ok), failing(r3).join('\n'));
      counts.otherCommitment += 1;
    }
    const sameDoc = await b.invoice(b.com2, b.rec2, 'X-' + b.int(1e6), 1, 'scan ' + number + ' ' + 'same');
    const firstDoc = await b.invoice(b.com, b.rec, 'Y-' + b.int(1e6), 1, 'scan ' + number + ' ' + 'same');
    const pd1 = await b.pay(b.com, firstDoc, p1);
    const pd2 = await b.pay(b.com2, sameDoc);
    const rd = await b.check(pd2, records.concat([firstDoc, sameDoc, pd1]));
    assert.strictEqual(rd.status, 'invalid', 'the same invoice document was paid under two commitments');
    counts.sameDocument += 1;
  }
  t.diagnostic(JSON.stringify(Object.assign({ rounds: ROUNDS }, counts)));
});

test('an honest series of distinct invoices within the commitment stays valid', async () => {
  const rng = mulberry32(0x77);
  const b = await books(rng);
  let prev = null;
  const records = [];
  for (let i = 0; i < 4; i += 1) {
    const inv = await b.invoice(b.com, b.rec, 'INV-' + (2000 + i * 17), 1 + b.int(Math.floor(b.cap / 4)));
    prev = await b.pay(b.com, inv, prev);
    records.push(inv, prev);
  }
  const r = await b.check(prev, records);
  assert.strictEqual(r.status, 'valid', failing(r).join('\n'));
});
