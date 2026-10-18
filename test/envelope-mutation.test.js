'use strict';

const test = require('node:test');
const assert = require('node:assert');
const F = require('../lib/format');
const { campaign, mutator, canon } = require('./fuzz');
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
  test('a changed ' + type + ' envelope never verifies valid, every refusal carries the ' + CODE + ' code and each check ends within the time bound', async (t) => {
    const w = await setup();
    const base = w.all[type];
    const opts = optionsFor(w, type, base);
    const honestResult = await w.q.verify(base, opts);
    assert.strictEqual(honestResult.status, 'valid', JSON.stringify(honestResult.checks.filter((c) => !c.ok)));
    const pool = stringsOf(w.all, []);
    const stats = await campaign({
      name: type,
      seed: 0x51e7 + n,
      base,
      pool,
      code: CODE,
      check: (m) => w.q.verify(m, opts),
      valid: (r) => r.status === 'valid' || r.valid === true,
    });
    t.diagnostic(JSON.stringify(stats));
  });
});

test('the mutation stream is the same for the same seed', () => {
  const a = mutator(7);
  const b = mutator(7);
  const base = { format: 'x/1', statement: { a: '00ff', b: 1 }, signature: 'QUJDREVGR0hJSktMTU5PUA==' };
  for (let i = 0; i < 200; i += 1) assert.strictEqual(canon(a.mutate(base, i).value), canon(b.mutate(base, i).value));
});
