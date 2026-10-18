// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const crypto = require('crypto');
const test = require('node:test');
const assert = require('node:assert');
const qstamp = require('@quantovainc/qstamp');
const q = require('..');
const F = require('../lib/format');
const { network, stamper, iso, bech32m } = require('./chain');

const RECORDS_MAX = F.SPEC.recordsMax || 2000;

function rootType() {
  return Object.entries(F.SPEC.types).find(([, t]) => Object.keys(t.links || {}).length === 0 && !t.chain && !t.secretParty && !t.deriveFields);
}

async function anchoredRoot() {
  const now = Math.floor(Date.now() / 1000);
  const net = network(now - 600);
  const [type, t] = rootType();
  const key = q.generateKey();
  const opts = { key, [t.time]: iso(now - 500) };
  let n = 1;
  for (const [name, def] of Object.entries(t.fields || {})) {
    const kind = def[0];
    if (kind === 'text') opts[name] = 'T' + name;
    else if (kind === 'digest') opts[name] = 'ab'.repeat(32);
    else if (kind === 'currency') opts[name] = 'EUR';
    else if (kind === 'amount' || kind === 'posamount') opts[name] = '100';
    else if (kind === 'size') opts[name] = 10;
    else if (kind === 'time') opts[name] = iso(now + 3600 * n++);
    else if (kind === 'key') opts[name] = q.keyId(q.generateKey());
    else if (kind === 'party') opts[name] = q.commitParty('P' + name).ref;
  }
  const env = await stamper(q, net)(q[type](opts), now - 490);
  net.chain.block(now);
  const base = Object.assign({ type, [t.role + 'Keys']: [q.keyId(key)], at: iso(now) }, net.opts);
  const bare = Object.assign({}, env);
  delete bare.anchor;
  return { net, env, bare, base, now };
}

function receiptFor(env, time, height) {
  const digest = q.anchorDigest(env);
  const salt = crypto.randomBytes(32);
  const leaf = qstamp.leafHash('sha3-256', Buffer.from(digest, 'hex'), salt);
  const tn = qstamp.NETWORKS.testnet;
  return {
    format: qstamp.RECEIPT_FORMAT,
    chain: { id: tn.chainId, genesis: tn.genesis },
    contract: tn.contract,
    kind: String(q.KIND),
    record: { alg: 'sha3-256', digest, salt: salt.toString('hex') },
    proof: { index: 0, size: 1, path: [] },
    root: leaf.toString('hex'),
    anchor: { tx: bech32m('QTX', crypto.randomBytes(32)), height, block: bech32m('QBK', crypto.randomBytes(32)), time, sender: bech32m('Q', crypto.randomBytes(32)) },
  };
}

function copies(bare, receipts) {
  return receipts.map((r) => Object.assign({}, bare, { anchor: r }));
}

function slowClients(clients, wrap) {
  return clients.map((c) => Object.assign({}, c, { transaction: (id) => wrap(id, () => c.transaction(id)) }));
}

function unanswered(txs) {
  const real = qstamp.verify;
  qstamp.verify = async (receipt, options) => {
    if (!txs.has(receipt.anchor.tx)) return real(receipt, options);
    return { valid: false, status: 'indeterminate', endpoints: [], checks: [{ name: 'transport', ok: false, detail: 'the endpoints did not answer', transport: true }] };
  };
  return () => {
    qstamp.verify = real;
  };
}

test('anchors that claim an earlier time at a height the chain reached only later never hide the proven anchor', async () => {
  const { env, bare, base, net } = await anchoredRoot();
  const proven = await q.verify(env, base);
  assert.strictEqual(proven.status, 'valid', JSON.stringify(proven.checks.filter((c) => !c.ok)));
  const t = env.anchor.anchor.time;
  for (const n of [1, 8, 20]) {
    const forged = Array.from({ length: n }, (_, i) => receiptFor(bare, t - 5 - i, net.chain.height + 1000 + i));
    const restore = unanswered(new Set(forged.map((f) => f.anchor.tx)));
    try {
      const r = await q.verify(env, Object.assign({}, base, { records: copies(bare, forged) }));
      assert.strictEqual(r.status, 'valid', n + ' ' + JSON.stringify(r.checks.filter((c) => !c.ok)));
      assert.strictEqual(r.anchoredAt, proven.anchoredAt);
      assert.ok(r.notices.some((x) => /ignored/.test(x)), JSON.stringify(r.notices));
    } finally {
      restore();
    }
    const live = await q.verify(env, Object.assign({}, base, { records: copies(bare, forged) }));
    assert.strictEqual(live.status, 'valid', n + ' ' + JSON.stringify(live.checks.filter((c) => !c.ok)));
    assert.strictEqual(live.anchoredAt, proven.anchoredAt);
  }
});

test('an unanswered anchor below the proven height keeps the result open but never drops the proven anchor', async () => {
  const { env, bare, base } = await anchoredRoot();
  const t = env.anchor.anchor.time;
  const unsure = receiptFor(bare, t - 60, env.anchor.anchor.height - 5);
  const same = receiptFor(bare, t, env.anchor.anchor.height - 5);
  const restore = unanswered(new Set([unsure.anchor.tx, same.anchor.tx]));
  try {
    const r = await q.verify(env, Object.assign({}, base, { records: copies(bare, [unsure]) }));
    assert.strictEqual(r.status, 'indeterminate');
    assert.ok(r.checks.some((c) => c.name === 'anchor earlier copies' && !c.ok && c.indeterminate));
    assert.strictEqual(r.anchoredAt, iso(t));
    const tied = await q.verify(env, Object.assign({}, base, { records: copies(bare, [same]) }));
    assert.strictEqual(tied.status, 'valid', JSON.stringify(tied.checks.filter((c) => !c.ok)));
    assert.strictEqual(tied.anchoredAt, iso(t));
  } finally {
    restore();
  }
});

test('a flood of forged anchors is read within the time limit and leaves the proven verdict', async () => {
  const { env, bare, base, net } = await anchoredRoot();
  const t = env.anchor.anchor.time;
  const n = Math.min(2000, RECORDS_MAX) - 1;
  const forged = Array.from({ length: n }, (_, i) => receiptFor(bare, t - 1 - (i % 500), i % 2 ? net.chain.height + 100 + i : 1000 + i));
  const started = Date.now();
  const r = await q.verify(env, Object.assign({}, base, { records: copies(bare, forged) }));
  const took = Date.now() - started;
  assert.strictEqual(r.status, 'valid', JSON.stringify(r.checks.filter((c) => !c.ok).slice(0, 3)));
  assert.strictEqual(r.anchoredAt, iso(t));
  assert.ok(!r.checks.some((c) => c.name === 'time limit'));
  assert.ok(took < 60000, 'took ' + took + ' ms');
});

test('anchor lookups run at most four at a time', async () => {
  const { env, bare, base } = await anchoredRoot();
  const t = env.anchor.anchor.time;
  const forged = Array.from({ length: 16 }, (_, i) => receiptFor(bare, t - 100 - i, 1000 + i));
  const pending = new Map();
  let most = 0;
  const clients = slowClients(base.clients, async (id, read) => {
    pending.set(id, (pending.get(id) || 0) + 1);
    most = Math.max(most, pending.size);
    try {
      await new Promise((resolve) => setTimeout(resolve, 20));
      return await read();
    } finally {
      const left = pending.get(id) - 1;
      if (left) pending.set(id, left);
      else pending.delete(id);
    }
  });
  const r = await q.verify(env, Object.assign({}, base, { clients, records: copies(bare, forged) }));
  assert.strictEqual(r.status, 'valid', JSON.stringify(r.checks.filter((c) => !c.ok)));
  assert.ok(most >= 2 && most <= 4, 'at most ' + most + ' transactions were read at once');
});

test('a verification that reaches its time limit is indeterminate and says so', async () => {
  const { env, bare, base } = await anchoredRoot();
  const forged = Array.from({ length: 6 }, (_, i) => receiptFor(bare, env.anchor.anchor.time - 10 - i, 1000 + i));
  const clients = slowClients(base.clients, () => new Promise(() => {}));
  const started = Date.now();
  const r = await q.verify(env, Object.assign({}, base, { clients, deadlineMs: 300, records: copies(bare, forged) }));
  assert.ok(Date.now() - started < 5000);
  assert.strictEqual(r.status, 'indeterminate');
  assert.strictEqual(r.anchoredAt, null);
  const limit = r.checks.find((c) => c.name === 'time limit');
  assert.ok(limit && !limit.ok && limit.indeterminate && /deadlineMs/.test(limit.detail));
});

test('the time limits and the bound on anchor lookups are checked', async () => {
  const at = new Date().toISOString();
  for (const v of [0, -1, 1.5, '10', 3600001, null]) await assert.rejects(q.verify({}, { type: q.TYPES[0], deadlineMs: v, at }), /deadlineMs/);
  for (const v of [0, 1.5, '10', 3600001]) await assert.rejects(q.verify({}, { type: q.TYPES[0], keyStatus: async () => ({ revoked: false }), keyStatusTimeoutMs: v, at }), /keyStatusTimeoutMs/);
  await assert.rejects(q.verify({}, { type: q.TYPES[0], keyStatusTimeoutMs: 1000, at }), /keyStatusTimeoutMs goes with keyStatus/);
  await assert.rejects(q.verify({}, { type: q.TYPES[0], maxAnchorLookups: 8 * RECORDS_MAX + 1, at }), /maxAnchorLookups/);
  const { env, base } = await anchoredRoot();
  const r = await q.verify(env, Object.assign({}, base, { maxAnchorLookups: 8 * RECORDS_MAX, deadlineMs: 3600000 }));
  assert.strictEqual(r.status, 'valid');
});

test('the key registry answer must have the documented shape', async () => {
  const { env, base, now } = await anchoredRoot();
  const revokedAt = now - 3600;
  const malformed = [
    undefined, null, 'revoked', 1, [], { status: 'revoked', revokedAt }, { revoked: 'true', revokedAt }, { revoked: 1, revokedAt },
    { revoked: true }, { revoked: true, revokedAt: revokedAt * 1000 }, { revoked: true, revokedAt: iso(revokedAt) }, { revoked: true, revokedAt: revokedAt + 0.5 },
    { revoked: true, revokedAt: 1000 }, { revoked: true, revokedAt: 1e11 + 1 }, { revoked: true, revokedAt: Number.NaN },
    Object.defineProperty({}, 'revoked', { get() { throw new Error('getter'); } }),
    new Proxy({}, { get() { throw new Error('trap'); } }),
  ];
  for (const [i, answer] of malformed.entries()) {
    const r = await q.verify(env, Object.assign({}, base, { keyStatus: async () => answer }));
    const c = r.checks.find((x) => x.name === 'key status');
    assert.strictEqual(r.status, 'indeterminate', 'answer ' + i);
    assert.ok(c && !c.ok && c.indeterminate, 'answer ' + i);
  }
  const clean = await q.verify(env, Object.assign({}, base, { keyStatus: async () => ({ revoked: false }) }));
  assert.strictEqual(clean.status, 'valid');
  const before = await q.verify(env, Object.assign({}, base, { keyStatus: async () => ({ revoked: true, revokedAt }) }));
  assert.strictEqual(before.status, 'invalid');
  assert.ok(before.checks.some((c) => c.name === 'key status' && !c.ok && !c.indeterminate));
  const after = await q.verify(env, Object.assign({}, base, { keyStatus: () => ({ revoked: true, revokedAt: now - 60 }) }));
  assert.strictEqual(after.status, 'valid');
});

test('a key registry that does not answer in time gives an indeterminate result', async () => {
  const { env, base } = await anchoredRoot();
  const started = Date.now();
  const r = await q.verify(env, Object.assign({}, base, { keyStatus: () => new Promise(() => {}), keyStatusTimeoutMs: 200 }));
  assert.ok(Date.now() - started < 5000);
  assert.strictEqual(r.status, 'indeterminate');
  const c = r.checks.find((x) => x.name === 'key status');
  assert.ok(c && !c.ok && c.transport && c.indeterminate);
  const thrown = await q.verify(env, Object.assign({}, base, { keyStatus: () => { throw Symbol('down'); } }));
  assert.strictEqual(thrown.status, 'indeterminate');
});
