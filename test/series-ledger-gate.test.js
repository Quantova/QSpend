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
const F = require('../lib/format');
const { honest } = require('./honest');

const ROOT = path.join(__dirname, '..');
const BIN = path.join(ROOT, 'bin', fs.readdirSync(path.join(ROOT, 'bin')).find((f) => f.endsWith('.js')));
const LEDGER = F.NAME.toUpperCase() + '_LEDGER';
const kebab = (s) => s.replace(/[A-Z]/g, (c) => '-' + c.toLowerCase());
const dirs = [];

test.after(() => {
  for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
});

function folder() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), F.NAME + '-gate-'));
  dirs.push(d);
  return d;
}

const run = (args, cwd) => spawnSync(process.execPath, [BIN].concat(args), { encoding: 'utf8', cwd });

let world = null;
async function fixture() {
  if (!world) world = await honest();
  const pool = Object.values(world.all).concat((world.extra || []).flat());
  const type = Object.keys(world.all).find((k) => F.TYPES.includes(k) && F.SPEC.types[k].chain && !F.SPEC.types[k].secretParty && world.all[k].statement.seq === 1);
  const t = F.SPEC.types[type];
  const env = world.all[type];
  const links = {};
  for (const [lname, l] of Object.entries(t.links || {})) {
    if (env.statement[l.field] === '') continue;
    links[lname] = pool.find((e) => e && e.type === l.type && q.refOf(e) === env.statement[l.field]);
    assert.ok(links[lname], 'the fixture holds the ' + lname);
  }
  const fields = {};
  for (const fname of Object.keys(t.fields || {})) fields[fname] = env.statement[fname];
  return { type, t, env, links, fields, key: world.K[t.role] };
}

function options(f, more) {
  return Object.assign({ key: f.key, first: true, [f.t.time]: f.env.statement[f.t.time] }, f.links, f.fields, more);
}

function store(answer) {
  let text = null;
  return {
    async read() {
      return text;
    },
    async compareAndSwap(name, expected, next) {
      if (answer === true && expected === text) text = next;
      return answer;
    },
  };
}

test('a custom ledger store is trusted only when compareAndSwap answers exactly true', async () => {
  const f = await fixture();
  const create = (ledger) => q[f.type](options(f, { ledger }));
  const env = await create(store(true));
  assert.strictEqual(env.statement.seq, 1);
  await assert.rejects(create(store(false)), (e) => e.code === LEDGER && /another/.test(e.message));
  for (const odd of [{ acknowledged: true, matchedCount: 0, modifiedCount: 0 }, 1, 'true', null, undefined, [true]]) {
    await assert.rejects(create(store(odd)), (e) => e.code === LEDGER && /true or false/.test(e.message), String(odd));
  }
});

test('the command line refuses to sign a record of a series unless --ledger or --no-ledger is given', async (t) => {
  const f = await fixture();
  const dir = folder();
  const keyFile = path.join(dir, 'signer.key');
  fs.writeFileSync(keyFile, Buffer.from(f.key).toString('hex') + '\n', { mode: 0o600 });
  const args = ['--key', keyFile, '--first', '--' + kebab(f.t.time), f.env.statement[f.t.time]];
  for (const [lname, env] of Object.entries(f.links)) {
    const file = path.join(dir, lname + '.json');
    fs.writeFileSync(file, JSON.stringify(env));
    args.push('--' + kebab(lname), file);
  }
  for (const [fname, value] of Object.entries(f.fields)) {
    if (value === '' || Object.values(f.t.links || {}).some((l) => (l.copy || []).some(([mine]) => mine === fname))) continue;
    args.push('--' + kebab(fname), String(value));
  }
  const ledger = path.join(dir, 'ledger');
  fs.mkdirSync(ledger);
  const help = run(['help'], dir);
  assert.match(help.stdout, /\(--ledger DIR \| --no-ledger\)/);
  for (const [type, x] of Object.entries(F.SPEC.types)) {
    if (!x.chain && !x.once) continue;
    const bare = run([kebab(type), '--out', path.join(dir, type + '.bare.json')], dir);
    assert.strictEqual(bare.status, 64, type + ' ' + bare.stderr);
    assert.match(bare.stderr, /is part of a series, so give --ledger/);
    const both = run([kebab(type), '--ledger', ledger, '--no-ledger', '--out', path.join(dir, type + '.both.json')], dir);
    assert.strictEqual(both.status, 64, both.stderr);
    assert.match(both.stderr, /--ledger or --no-ledger, not both/);
  }
  const cmd = kebab(f.type);
  const missing = run([cmd].concat(args, ['--out', path.join(dir, 'none.json')]), dir);
  assert.strictEqual(missing.status, 64, missing.stderr);
  assert.match(missing.stderr, /is part of a series/);
  assert.ok(!fs.existsSync(path.join(dir, 'none.json')));
  const first = run([cmd].concat(args, ['--ledger', ledger, '--out', path.join(dir, 'one.json')]), dir);
  assert.strictEqual(first.status, 0, first.stderr);
  const second = run([cmd].concat(args, ['--ledger', ledger, '--out', path.join(dir, 'two.json')]), dir);
  assert.strictEqual(second.status, 1, second.stderr);
  assert.match(second.stderr, /already holds/);
  assert.ok(!fs.existsSync(path.join(dir, 'two.json')));
  const unserialised = run([cmd].concat(args, ['--no-ledger', '--out', path.join(dir, 'three.json')]), dir);
  assert.strictEqual(unserialised.status, 0, unserialised.stderr);
  t.diagnostic(f.type + ' checked through the command line');
});
