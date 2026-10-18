'use strict';

const test = require('node:test');
const assert = require('node:assert');
const F = require('../lib/format');
const { campaign } = require('./fuzz');
const { honest } = require('./honest');

const CODE = F.NAME.toUpperCase() + '_';

function stringsOf(v, out) {
  if (typeof v === 'string' && v.length < 200) out.push(v);
  else if (v && typeof v === 'object') for (const k of Object.keys(v)) stringsOf(v[k], out);
  return out;
}

let world;
async function setup() {
  if (!world) world = await honest();
  return world;
}

function optionsFor(w, type, target) {
  const records = Object.values(w.all).filter((e) => e !== target).concat(w.extra || []);
  return Object.assign({ type, at: new Date(w.now * 1000).toISOString(), allSupplied: true, records }, w.roles, w.net.opts);
}

F.TYPES.forEach((type, n) => {
  test('a changed Qstamp receipt never lets ' + F.article(type) + ' verify valid', async (t) => {
    const w = await setup();
    const base = w.all[type];
    const opts = optionsFor(w, type, base);
    const receipt = base.anchor;
    const honestResult = await w.q.verify(base, opts);
    assert.strictEqual(honestResult.status, 'valid', JSON.stringify(honestResult.checks.filter((c) => !c.ok)));
    const pool = stringsOf(Object.values(w.all).map((e) => e.anchor), []);
    const stats = await campaign({
      name: type + ' receipt',
      seed: 0xa9c4 + n,
      base: receipt,
      pool,
      code: CODE,
      check: (r) => w.q.verify(Object.assign({}, base, { anchor: r }), opts),
      valid: (r) => r.status === 'valid' || r.valid === true,
    });
    t.diagnostic(JSON.stringify(stats));
  });
});
