// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { honest } = require('./honest');
const { iso } = require('./chain');

test('a commitment may cite the procurement award, and verify checks it when the award reference is given', async () => {
  const w = await honest();
  const { q, K, all, roles, net } = w;
  const award = 'aa'.repeat(32);
  const cited = await w.at(q.commitment({ key: K.officer, allotment: all.allotment, supplier: 'ACME BV', partySecret: new Uint8Array(32).fill(4), document: Buffer.from('po2'), awardRef: award, amount: '1000', previous: all.commitment, committedAt: iso(w.now - 120) }), w.now - 110);
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
