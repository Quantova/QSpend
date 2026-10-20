// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const test = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('child_process');
const q = require('..');
const { honest } = require('./honest');
const { iso } = require('./chain');

const BIN = path.join(__dirname, '..', 'bin', 'qspend.js');

test('a commitment may cite the procurement award, and verify checks it when the award reference is given', async () => {
  const w = await honest();
  const { q, K, all, roles, net } = w;
  const award = 'aa'.repeat(32);
  const cited = await w.at(q.commitment({ key: K.officer, allotment: all.allotment, supplier: 'ACME BV', partySecret: Uint8Array.from({ length: 32 }, (_, i) => (4 + i) & 255), document: Buffer.from('po2'), awardRef: award, amount: '1000', previous: all.commitment, committedAt: iso(w.now - 120) }), w.now - 110);
  assert.strictEqual(cited.statement.awardRef, award);
  const check = (env, more) => {
    net.chain.block(w.now);
    return q.verify(env, Object.assign({ type: 'commitment', allSupplied: true, records: [all.appropriation, all.allotment, all.commitment] }, roles, net.opts, more));
  };
  const ok = await check(cited, { awardRef: award });
  assert.strictEqual(ok.status, 'valid', JSON.stringify(ok.checks.filter((c) => !c.ok)));
  const other = await check(cited, { awardRef: 'bb'.repeat(32) });
  assert.strictEqual(other.status, 'invalid');
  const none = await check(all.commitment, { awardRef: award });
  assert.strictEqual(none.status, 'invalid');
  assert.strictEqual(all.commitment.statement.awardRef, '');
  await assert.rejects(check(cited, { awardRef: 'not hex' }), (e) => e.code === 'QSPEND_INVALID_INPUT');
});

test('the award reference is checked on the commitment named by a receipt, an invoice or a payment', async () => {
  const w = await honest();
  const { K, all, roles, net } = w;
  const award = 'aa'.repeat(32);
  const cited = await w.at(q.commitment({ key: K.officer, allotment: all.allotment, supplier: 'ACME BV', partySecret: Uint8Array.from({ length: 32 }, (_, i) => (4 + i) & 255), document: Buffer.from('po2'), awardRef: award, amount: '1000', previous: all.commitment, committedAt: iso(w.now - 300) }), w.now - 290);
  const receipt = await w.at(q.receipt({ key: K.receiver, commitment: cited, document: Buffer.from('grn2'), receivedAt: iso(w.now - 280) }), w.now - 270);
  const invoice = await w.at(q.invoice({ key: K.intake, commitment: cited, receipt, invoiceNumber: 'INV-2002', document: Buffer.from('inv2'), amount: '1000', receivedAt: iso(w.now - 260) }), w.now - 250);
  const payment = await w.at(q.payment({ key: K.treasury, commitment: cited, invoice, first: true, paidAt: iso(w.now - 240) }), w.now - 230);
  const pool = Object.values(all).concat([cited, receipt, invoice]);
  const check = (type, env, more) => {
    net.chain.block(w.now);
    return q.verify(env, Object.assign({ type, allSupplied: true, records: pool }, roles, net.opts, more));
  };
  const awardCheck = (r) => r.checks.filter((c) => /award$/.test(c.name));
  for (const [type, env] of [['receipt', receipt], ['invoice', invoice], ['payment', payment]]) {
    const ok = await check(type, env, { awardRef: award });
    assert.strictEqual(ok.status, 'valid', type + ' ' + JSON.stringify(ok.checks.filter((c) => !c.ok)));
    assert.strictEqual(awardCheck(ok).length, 1, type);
    const other = await check(type, env, { awardRef: 'bb'.repeat(32) });
    assert.strictEqual(other.status, 'invalid', type);
    assert.deepStrictEqual(awardCheck(other).map((c) => c.ok), [false], type);
    const without = await check(type, env);
    assert.strictEqual(without.status, 'valid', type);
    assert.strictEqual(awardCheck(without).length, 0, type);
  }
  const uncited = await check('payment', all.payment, { awardRef: award });
  assert.strictEqual(uncited.status, 'invalid');
  assert.match(awardCheck(uncited)[0].detail, /cites no procurement award/);
});

test('an award reference is refused for an appropriation or an allotment by the library and the command line', async (t) => {
  const w = await honest();
  const { all, roles, net } = w;
  for (const type of ['appropriation', 'allotment']) {
    await assert.rejects(q.verify(all[type], Object.assign({ type, allSupplied: true, records: Object.values(all), awardRef: 'aa'.repeat(32) }, roles, net.opts)), (e) => e.code === 'QSPEND_INVALID_INPUT' && /does not apply/.test(e.message));
  }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qspend-award-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'appropriation.json');
  fs.writeFileSync(file, JSON.stringify(all.appropriation));
  for (const type of ['appropriation', 'allotment']) {
    const r = spawnSync(process.execPath, [BIN, 'verify', file, '--type', type, '--award-ref', 'aa'.repeat(32), '--allow-unanchored', '--at', iso(w.now)], { encoding: 'utf8', cwd: dir });
    assert.strictEqual(r.status, 64, r.stderr);
    assert.match(r.stderr, /--award-ref does not apply when verifying an? (appropriation|allotment)/);
  }
});
