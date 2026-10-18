// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const test = require('node:test');
const assert = require('node:assert');
const q = require('..');
const F = require('../lib/format');
const native = require('../lib/native');
const { honest } = require('./honest');

const iso = (s) => new Date(s * 1000).toISOString();
const dirs = [];
const LEDGER = F.NAME.toUpperCase() + '_LEDGER';

test.after(() => {
  for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
});

function folder() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), F.NAME + '-series-'));
  dirs.push(d);
  return d;
}

function rootType() {
  return Object.entries(F.SPEC.types).find(([, t]) => Object.keys(t.links || {}).length === 0 && !t.chain && !t.secretParty && !t.deriveFields);
}

function rootRecord(note) {
  const now = Math.floor(Date.now() / 1000);
  const [type, t] = rootType();
  const opts = { key: q.generateKey(), [t.time]: iso(now - 500), note };
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
  return { type, opts, env: q[type](opts) };
}

let world = null;
async function seriesBase() {
  if (!world) world = await honest();
  const type = Object.keys(world.all).find((k) => F.TYPES.includes(k) && F.SPEC.types[k].chain);
  const t = F.SPEC.types[type];
  const base = F.parse(world.all[type]);
  return { type, t, base, scope: base.statement[t.chain.scope] };
}

function forge(base, seq, change) {
  const t = F.SPEC.types[base.type];
  const key = q.generateKey();
  const st = Object.assign({}, base.statement);
  st[t.id] = crypto.randomBytes(16).toString('hex');
  st[t.signer] = q.keyId(key);
  if (t.chain) {
    st.seq = seq;
    st[t.chain.prev] = seq === 1 ? '' : crypto.randomBytes(32).toString('hex');
    if (t.chain.total) st[t.chain.total] = (BigInt(st[t.chain.amount]) * BigInt(seq)).toString();
  }
  if (change) change(st, t);
  const signature = native.sign(key, F.payload(base.type, st), new Uint8Array(crypto.randomBytes(32)));
  return { format: F.FORMAT, type: base.type, algorithm: F.ALGORITHM, signer: { id: q.keyId(key), publicKey: Buffer.from(q.publicKey(key)).toString('base64') }, statement: st, signature: Buffer.from(signature).toString('base64') };
}

function state(name, seq, env) {
  return JSON.stringify({ format: F.NAME + '-series/1', series: name, seq, ref: q.refOf(env), envelope: env }) + '\n';
}

test('the folder ledger stores each position of a series once and moves only from the latest record', async () => {
  const { type, base, scope } = await seriesBase();
  const NAME = F.NAME + '.' + type + '.' + scope;
  const store = q.folderLedger(folder());
  const [a, b] = [1, 1].map((n) => forge(base, n));
  const [c, d] = [2, 2].map((n) => forge(base, n));
  assert.strictEqual(await store.read(NAME), null);
  assert.strictEqual(await store.compareAndSwap(NAME, null, state(NAME, 1, a)), true);
  assert.strictEqual(await store.compareAndSwap(NAME, null, state(NAME, 1, b)), false);
  assert.strictEqual(await store.read(NAME), state(NAME, 1, a));
  assert.strictEqual(await store.compareAndSwap(NAME, state(NAME, 1, b), state(NAME, 2, c)), false);
  await assert.rejects(store.compareAndSwap(NAME, state(NAME, 1, a), state(NAME, 3, forge(base, 2))), (e) => e.code === LEDGER);
  assert.strictEqual(await store.compareAndSwap(NAME, state(NAME, 1, a), state(NAME, 3, forge(base, 3))), false);
  assert.strictEqual(await store.compareAndSwap(NAME, state(NAME, 1, a), state(NAME, 2, d)), true);
  const racers = Array.from({ length: 8 }, () => forge(base, 3));
  const won = await Promise.all(racers.map((env) => store.compareAndSwap(NAME, state(NAME, 2, d), state(NAME, 3, env))));
  assert.strictEqual(won.filter(Boolean).length, 1);
  assert.strictEqual(await store.compareAndSwap(NAME, state(NAME, 2, d), state(NAME, 3, forge(base, 3))), false);
  await assert.rejects(store.read('../' + NAME), (e) => e.code === F.NAME.toUpperCase() + '_INVALID_INPUT');
});

test('a record outside any series takes no ledger, and a damaged ledger entry stops signing', async () => {
  const { type, opts } = rootRecord('plain');
  assert.throws(() => q[type](Object.assign({}, opts, { ledger: folder() })), (e) => e.code === F.NAME.toUpperCase() + '_INVALID_INPUT' && /no ledger/.test(e.message));
  const series = Object.entries(F.SPEC.types).find(([, t]) => t.chain || t.once);
  if (!series) return;
  await assert.rejects(q.ledgerLatest(folder(), series[0], 'zz'), (e) => e.code === F.NAME.toUpperCase() + '_INVALID_INPUT');
  const dir = folder();
  const name = F.NAME + '.' + series[0] + '.' + 'ef'.repeat(32);
  fs.writeFileSync(path.join(dir, name + '.1.json'), '{"format":"broken"}\n');
  await assert.rejects(q.ledgerLatest(dir, series[0], 'ef'.repeat(32)), (e) => e.code === LEDGER);
  assert.strictEqual(await q.ledgerLatest(folder(), series[0], 'ef'.repeat(32)), null);
});

test('a ledger entry whose position, type or series differs from the envelope inside it is refused', async () => {
  const { type, t, base, scope } = await seriesBase();
  const NAME = F.NAME + '.' + type + '.' + scope;
  const fixed = (text) => ({ read: async () => text, compareAndSwap: async () => false });
  const good = forge(base, 2);
  assert.deepStrictEqual(await q.ledgerLatest(fixed(state(NAME, 2, good)), type, scope), good);
  await assert.rejects(q.ledgerLatest(fixed(state(NAME, 5, good)), type, scope), (e) => e.code === LEDGER);
  await assert.rejects(q.ledgerLatest(fixed(state(NAME, 1, good)), type, scope), (e) => e.code === LEDGER);
  const elsewhere = forge(base, 2, (st) => {
    st[t.chain.scope] = 'ab'.repeat(32);
  });
  await assert.rejects(q.ledgerLatest(fixed(state(NAME, 2, elsewhere)), type, scope), (e) => e.code === LEDGER);
  const plain = rootRecord('other type').env;
  await assert.rejects(q.ledgerLatest(fixed(state(NAME, 1, plain)), type, scope), (e) => e.code === LEDGER);
  const other = Object.entries(F.SPEC.types).find(([k, x]) => k !== type && (x.chain || x.once));
  if (other) await assert.rejects(q.ledgerLatest(fixed(state(F.NAME + '.' + other[0] + '.' + scope, 2, good)), other[0], scope), (e) => e.code === LEDGER);
});

test('the folder ledger never follows a symbolic link and refuses an entry filed under another position', async (t) => {
  const { type, base, scope } = await seriesBase();
  const NAME = F.NAME + '.' + type + '.' + scope;
  const dir = folder();
  const outside = folder();
  const one = forge(base, 1);
  fs.writeFileSync(path.join(outside, 'entry.json'), state(NAME, 1, one));
  if (process.platform !== 'win32') {
    fs.symlinkSync(path.join(outside, 'entry.json'), path.join(dir, NAME + '.1.json'));
    await assert.rejects(q.ledgerLatest(dir, type, scope), (e) => e.code === LEDGER && /not a small regular file/.test(e.message));
    fs.rmSync(path.join(dir, NAME + '.1.json'));
  }
  fs.mkdirSync(path.join(dir, NAME + '.1.json'));
  await assert.rejects(q.ledgerLatest(dir, type, scope), (e) => e.code === LEDGER);
  fs.rmSync(path.join(dir, NAME + '.1.json'), { recursive: true });
  fs.writeFileSync(path.join(dir, NAME + '.1.json'), state(NAME, 1, one));
  fs.writeFileSync(path.join(dir, NAME + '.2.json'), state(NAME, 1, one));
  await assert.rejects(q.ledgerLatest(dir, type, scope), (e) => e.code === LEDGER && /does not hold position 2/.test(e.message));
  t.diagnostic('symbolic links checked ' + (process.platform !== 'win32'));
});

test('the folder ledger reads the latest record of a series by its name without listing the folder', async () => {
  const { type, base, scope } = await seriesBase();
  const NAME = F.NAME + '.' + type + '.' + scope;
  const dir = folder();
  for (let i = 0; i < 300; i += 1) fs.writeFileSync(path.join(dir, F.NAME + '.' + type + '.' + crypto.randomBytes(32).toString('hex') + '.1.json'), '');
  const store = q.folderLedger(dir);
  const list = fs.readdirSync;
  const unlisted = async (fn) => {
    fs.readdirSync = () => {
      throw new Error('the folder was listed');
    };
    try {
      return await fn();
    } finally {
      fs.readdirSync = list;
    }
  };
  let prev = null;
  for (let seq = 1; seq <= 19; seq += 1) {
    const env = forge(base, seq);
    assert.strictEqual(await store.compareAndSwap(NAME, prev, state(NAME, seq, env)), true);
    prev = state(NAME, seq, env);
    assert.strictEqual(await unlisted(() => store.read(NAME)), prev);
    assert.deepStrictEqual(await unlisted(() => q.ledgerLatest(dir, type, scope)), env);
  }
});

test('a series missing a record below its latest one is refused as damaged, so no position is signed twice', async () => {
  const { type, base, scope } = await seriesBase();
  const NAME = F.NAME + '.' + type + '.' + scope;
  for (const lost of [1, 2, 4]) {
    const dir = folder();
    const store = q.folderLedger(dir);
    const chain = [null];
    for (let n = 1; n <= 5; n++) {
      chain[n] = forge(base, n);
      assert.strictEqual(await store.compareAndSwap(NAME, n === 1 ? null : state(NAME, n - 1, chain[n - 1]), state(NAME, n, chain[n])), true);
    }
    fs.rmSync(path.join(dir, NAME + '.' + lost + '.json'));
    const seen = await store.read(NAME);
    const at = seen === null ? 0 : JSON.parse(seen).seq;
    if (at === 5) continue;
    const before = fs.readdirSync(dir).length;
    await assert.rejects(store.compareAndSwap(NAME, seen, state(NAME, at + 1, forge(base, at + 1))), (e) => e.code === LEDGER && /missing a record/.test(e.message));
    assert.strictEqual(fs.readdirSync(dir).length, before);
  }
  const dir = folder();
  const store = q.folderLedger(dir);
  const chain = [null];
  for (let n = 1; n <= 5; n++) {
    chain[n] = forge(base, n);
    await store.compareAndSwap(NAME, n === 1 ? null : state(NAME, n - 1, chain[n - 1]), state(NAME, n, chain[n]));
  }
  fs.rmSync(path.join(dir, NAME + '.3.json'));
  assert.strictEqual(await store.read(NAME), state(NAME, 5, chain[5]));
  assert.strictEqual(await store.compareAndSwap(NAME, state(NAME, 5, chain[5]), state(NAME, 6, forge(base, 6))), true);
});
