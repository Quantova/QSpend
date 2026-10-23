// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const F = require('../lib/format');
const native = require('../lib/native');
const { honest } = require('./honest');
const { forged } = require('./chain');

function signedBy(env, key, q) {
  const statement = Object.assign({}, env.statement, { [F.SIGNER[env.type]]: q.keyId(key) });
  const signature = native.sign(key, F.payload(env.type, statement), new Uint8Array(crypto.randomBytes(32)));
  const out = Object.assign({}, env, { statement, signer: { id: q.keyId(key), publicKey: Buffer.from(q.publicKey(key)).toString('base64') }, signature: Buffer.from(signature).toString('base64') });
  delete out.anchor;
  return out;
}

let world;
async function setup() {
  if (!world) world = await honest();
  return world;
}

function optionsFor(w, type, records) {
  return Object.assign({ type, at: new Date(w.now * 1000).toISOString(), allSupplied: true, records }, w.roles, w.net.opts);
}

test('records signed by an untrusted key, junk and badly signed records never turn a valid series record invalid', async () => {
  const w = await setup();
  const outsider = w.q.generateKey();
  for (const type of Object.keys(w.all).filter((t) => F.SPEC.types[t].chain)) {
    const target = w.all[type];
    const others = Object.values(w.all).filter((e) => e !== target).concat(w.extra || []);
    const fork = signedBy(target, outsider, w.q);
    const noise = [fork, { junk: true }, Object.assign({}, fork, { signature: target.signature })];
    const r = await w.q.verify(target, optionsFor(w, type, others.concat(noise)));
    assert.strictEqual(r.status, 'valid', type + ' ' + JSON.stringify(r.checks.filter((c) => !c.ok)));
  }
});

test('a copy carrying a forged anchor listed before the genuine record never displaces it', async () => {
  const w = await setup();
  for (const type of Object.keys(w.all).filter((t) => F.SPEC.types[t].chain)) {
    const target = w.all[type];
    const others = Object.values(w.all).filter((e) => e !== target).concat(w.extra || []);
    const first = others.filter((e) => e && e.anchor).map((e, n) => Object.assign({}, e, { anchor: forged(e.anchor, 3600, n) }));
    const r = await w.q.verify(target, optionsFor(w, type, first.concat(others)));
    const open = r.checks.filter((c) => !c.ok);
    assert.ok(r.status === 'valid' || (r.status === 'indeterminate' && open.every((c) => / earlier copies$/.test(c.name))), type + ' ' + JSON.stringify(open));
  }
});
