// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const path = require('path');
const { createRequire } = require('module');
const test = require('node:test');
const assert = require('node:assert');
const q = require('..');
const F = require('../lib/format');
const { network, stamper, proofs, iso, SEED } = require('./chain');

const qstampBase = path.dirname(require.resolve('@quantovainc/qstamp'));
const { core } = createRequire(path.join(qstampBase, 'package.json'))('@quantovainc/qcore');

const SAME = [
  ['NL-123456789', 'nl123456789', 'NL‑123456789', 'NL 123 456 789', 'ＮＬ１２３４５６７８９', 'NL.123.456.789', 'nl-I23456789', 'ΝL-123456789'],
  ['alice', 'Alice', 'ALICE', 'аlice', 'ALΙCE'],
  ['straße', 'STRASSE', 'Strasse'],
  ['INV-1001', 'ІNV‑1001', 'inv 1001', 'INV/1OO1'],
];

test('identifiers that differ only in case, separators, width or lookalike letters share one canonical form', () => {
  for (const group of SAME) {
    const forms = new Set(group.map((x) => F.canonicalIdentifier(x)));
    assert.strictEqual(forms.size, 1, group.join(' | ') + ' gave ' + [...forms].join(' | '));
  }
  assert.notStrictEqual(F.canonicalIdentifier('NL-123456789'), F.canonicalIdentifier('NL-123456788'));
  assert.notStrictEqual(F.canonicalIdentifier('alice'), F.canonicalIdentifier('bob'));
});

test('the canonical form is stable when applied again', () => {
  for (const group of SAME) {
    for (const x of group) {
      const c = F.canonicalIdentifier(x);
      assert.strictEqual(F.canonicalIdentifier(c), c);
    }
  }
});

test('identifiers without letters or digits, or with invisible or unassigned characters, are refused', () => {
  for (const bad of ['---', ' ', 'a\u200db', 'a\u202eb', 'x\u{50000}', '', 42]) assert.throws(() => F.canonicalIdentifier(bad));
});

test('party commitments use the canonical identifier', () => {
  const salt = Uint8Array.from({ length: 32 }, (_, i) => (5 + i) & 255);
  const secret = Uint8Array.from({ length: 32 }, (_, i) => (6 + i) & 255);
  const scope = 'ab'.repeat(32);
  const refs = new Set(SAME[0].map((x) => q.commitParty(x, { salt }).ref));
  assert.strictEqual(refs.size, 1);
  const derived = new Set(SAME[0].map((x) => q.commitParty(x, { secret, scope }).ref));
  assert.strictEqual(derived.size, 1);
  assert.notStrictEqual(q.commitParty('NL-1').ref, q.commitParty('NL-1').ref);
  assert.notStrictEqual(F.partyRef(salt, 'NL-1'), F.legacyPartyRef(salt, 'NL-1'));
});

test('verification fails closed when the chain time cannot be read', async () => {
  const broken = { base: 'https://down.example', nodeInfo: async () => { throw new Error('refused by the endpoint'); }, block: async () => null, events: async () => ({ events: [] }), transaction: async () => null };
  const other = Object.assign({}, broken, { base: 'https://down2.example' });
  await assert.rejects(q.verify({}, { type: q.TYPES[0], clients: [broken, other] }), (e) => e.code === F.NAME.toUpperCase() + '_NO_CHAIN_TIME');
  const r = await q.verify({}, { type: q.TYPES[0], clients: [broken, other], at: new Date().toISOString() });
  assert.strictEqual(r.status, 'invalid');
});

test('the bound on anchor lookups is checked', async () => {
  for (const v of [0, 1.5, -1, '10', 1e12]) await assert.rejects(q.verify({}, { type: q.TYPES[0], maxAnchorLookups: v, at: new Date().toISOString() }));
});

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
  const base = Object.assign({ type, [t.role + 'Keys']: [q.keyId(key)] }, net.opts);
  return { net, env, base };
}

test('an anchor confirmed only by endpoints chosen by the caller is unproven and never makes a record valid', async () => {
  const { env, base, net } = await anchoredRoot();
  try {
    const proven = await q.verify(env, base);
    assert.strictEqual(proven.status, 'valid', JSON.stringify(proven.checks.filter((c) => !c.ok)));
    assert.ok(proven.anchoredAt);
    proofs(false);
    const r = await q.verify(env, base);
    assert.strictEqual(r.status, 'indeterminate');
    assert.strictEqual(r.valid, false);
    assert.strictEqual(r.anchoredAt, null);
    const proof = r.checks.find((c) => c.name === 'anchor proof');
    assert.ok(proof && !proof.ok && proof.indeterminate && !proof.transport);
    const lax = await q.verify(env, Object.assign({ requireAnchor: false }, base));
    assert.notStrictEqual(lax.status, 'valid');
    const flags = ['trustSingleEndpoint', 'trustCustomEndpoints', 'allowLoopback', 'trustCustomContract'];
    for (let mask = 0; mask < 1 << flags.length; mask += 1) {
      const o = Object.assign({}, base, { clients: net.clients, at: new Date().toISOString() });
      delete o.trustCustomEndpoints;
      flags.forEach((f, i) => { if (mask & (1 << i)) o[f] = true; });
      if (o.trustCustomContract) o.contract = env.anchor.contract;
      const x = await q.verify(env, o);
      assert.notStrictEqual(x.status, 'valid', JSON.stringify(o));
      assert.strictEqual(x.anchoredAt, null);
    }
  } finally {
    proofs(true);
  }
});

test('endpoints chosen by the caller are consulted only with trustCustomEndpoints', async () => {
  const { env, base } = await anchoredRoot();
  const o = Object.assign({}, base);
  delete o.trustCustomEndpoints;
  await assert.rejects(q.verify(env, o), (e) => e.code === F.NAME.toUpperCase() + '_NO_CHAIN_TIME');
  const r = await q.verify(env, Object.assign({ at: new Date().toISOString() }, o));
  assert.strictEqual(r.status, 'indeterminate');
  assert.ok(r.checks.some((c) => c.name === 'anchor endpoints' && !c.ok && /trustCustomEndpoints/.test(c.detail)));
});

test('a loopback endpoint is refused unless allowLoopback is set', async () => {
  const { env, base } = await anchoredRoot();
  const o = Object.assign({}, base, { at: new Date().toISOString(), clients: undefined, rpc: ['http://127.0.0.1:9'] });
  delete o.clients;
  const r = await q.verify(env, o);
  assert.strictEqual(r.status, 'indeterminate');
  assert.ok(r.checks.some((c) => c.name === 'anchor endpoints' && /loopback/.test(c.detail)));
});

test('the account expected to sign the anchor is checked', async () => {
  const { env, base } = await anchoredRoot();
  const other = core.address(new Uint8Array(32).fill(9), 0);
  const wrong = await q.verify(env, Object.assign({ expectedSender: other }, base));
  assert.strictEqual(wrong.status, 'invalid');
  assert.ok(wrong.checks.some((c) => c.name === 'anchor sender' && !c.ok));
  const right = await q.verify(env, Object.assign({ expectedSender: [other, core.address(SEED, 0)] }, base));
  assert.strictEqual(right.status, 'valid');
});

test('a sovereign network is refused by a package without the sovereign path', async () => {
  const sovereign = { chainId: 'q-sovereign-1', genesis: 'ab'.repeat(32), contract: 'Q1D6TZFRL203P3DFAFVUPZUHGUCM4EWGH6063XNS42VA5235RNQWXS7FXEWX', rpcs: [{ url: 'https://a.example', operator: 'A' }] };
  let present = true;
  try {
    require.resolve('../lib/sovereign');
  } catch (e) {
    present = false;
  }
  if (present) return;
  await assert.rejects(q.verify({}, { type: q.TYPES[0], sovereign, at: new Date().toISOString() }), /sovereign networks are not part of this package/);
});
