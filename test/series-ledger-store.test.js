// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const test = require('node:test');
const assert = require('node:assert');
const q = require('..');
const F = require('../lib/format');

const iso = (s) => new Date(s * 1000).toISOString();
const dirs = [];

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

function state(name, seq, env) {
  return JSON.stringify({ format: F.NAME + '-series/1', series: name, seq, ref: q.refOf(env), envelope: env }) + '\n';
}

const NAME = F.NAME + '.' + rootType()[0] + '.' + 'cd'.repeat(32);

test('the folder ledger stores each position of a series once and moves only from the latest record', async () => {
  const store = q.folderLedger(folder());
  const [a, b, c] = ['one', 'two', 'three'].map((n) => rootRecord(n).env);
  assert.strictEqual(await store.read(NAME), null);
  assert.strictEqual(await store.compareAndSwap(NAME, null, state(NAME, 1, a)), true);
  assert.strictEqual(await store.compareAndSwap(NAME, null, state(NAME, 1, b)), false);
  assert.strictEqual(await store.read(NAME), state(NAME, 1, a));
  assert.strictEqual(await store.compareAndSwap(NAME, state(NAME, 1, b), state(NAME, 2, c)), false);
  assert.strictEqual(await store.compareAndSwap(NAME, state(NAME, 1, a), state(NAME, 3, c)), false);
  assert.strictEqual(await store.compareAndSwap(NAME, state(NAME, 1, a), state(NAME, 2, b)), true);
  const racers = Array.from({ length: 8 }, (_, i) => rootRecord('racer ' + i).env);
  const won = await Promise.all(racers.map((env) => store.compareAndSwap(NAME, state(NAME, 2, b), state(NAME, 3, env))));
  assert.strictEqual(won.filter(Boolean).length, 1);
  assert.strictEqual(await store.compareAndSwap(NAME, state(NAME, 2, b), state(NAME, 3, c)), false);
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
  await assert.rejects(q.ledgerLatest(dir, series[0], 'ef'.repeat(32)), (e) => e.code === F.NAME.toUpperCase() + '_LEDGER');
  assert.strictEqual(await q.ledgerLatest(folder(), series[0], 'ef'.repeat(32)), null);
});
