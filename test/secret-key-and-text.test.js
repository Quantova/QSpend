// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const util = require('util');
const q = require('..');

test('a generated key never shows its bytes when printed or serialised', () => {
  const key = q.generateKey();
  const hex = Buffer.from(key).toString('hex');
  const listed = Array.from(key).join(',');
  const shown = [util.inspect(key), util.inspect({ key }), JSON.stringify({ key }), String(key), `${key}`, util.format('%o', key), util.format('%j', { key }), key.toLocaleString()];
  for (const s of shown) {
    assert.ok(!s.includes(hex), s);
    assert.ok(!s.replace(/\s/g, '').includes(listed.slice(0, 24)), s);
  }
  assert.ok(key instanceof Uint8Array);
  assert.strictEqual(key.length, 32);
  assert.strictEqual(Object.prototype.toString.call(key.slice(0, 4)), '[object Uint8Array]');
  assert.strictEqual(q.keyId(key), q.keyId(Uint8Array.from(key)));
});

test('text with an unassigned code point or a noncharacter is refused', () => {
  const F = require('../lib/format');
  for (const t of ['a\u0378b', 'a\ufffeb', 'a\u{10ffff}b']) assert.ok(F.textProblem(t, 64, 'text'), JSON.stringify(t));
  assert.strictEqual(F.textProblem('plain text', 64, 'text'), null);
});

test('a signing key of too few different byte values or in shared memory is refused', () => {
  const shared = new Uint8Array(new SharedArrayBuffer(32));
  shared.set(q.generateKey());
  assert.throws(() => q.describeKey(new Uint8Array(32)));
  assert.throws(() => q.describeKey(new Uint8Array(32).fill(7)), /too few different byte values/);
  assert.throws(() => q.describeKey(shared));
});

test('a misspelled or unknown option of a signing call is refused and nothing is signed', async () => {
  await assert.rejects(Promise.resolve().then(() => q.appropriation({ key: q.generateKey(), budgetRef: 'B1', line: 'roads', period: '2026', currency: 'EUR', amount: '5', validUntil: new Date(Date.now() + 86400000).toISOString(), approvedAt: new Date(Date.now() - 1000).toISOString(), validUntill: 'x' })), /is not (an option of|used by)/);
  await assert.rejects(Promise.resolve().then(() => q.anchor([], { seed: new Uint8Array(32).fill(5), index: 0, untl: '2030-01-01T00:00:00.000Z' })));
});

test('the folder ledger refuses to run on Windows where folder owners and modes cannot be checked', () => {
  const was = Object.getOwnPropertyDescriptor(process, 'platform');
  Object.defineProperty(process, 'platform', { value: 'win32', configurable: true });
  try {
    assert.throws(() => q.folderLedger(require('os').tmpdir()), /Windows/);
  } finally {
    Object.defineProperty(process, 'platform', was);
  }
});

test('a party salt or party secret of too few different byte values is refused', () => {
  const scope = 'ab'.repeat(32);
  for (const b of [0, 1, 255]) {
    assert.throws(() => q.commitParty('NL-1', { salt: new Uint8Array(32).fill(b) }), /too few different byte values/);
    assert.throws(() => q.commitParty('NL-1', { secret: new Uint8Array(32).fill(b), scope }), /too few different byte values/);
  }
  const salt = new Uint8Array(32);
  globalThis.crypto.getRandomValues(salt);
  assert.ok(q.commitParty('NL-1', { salt }).ref);
  assert.ok(q.commitParty('NL-1', { secret: salt, scope }).ref);
});

test('the working copies of the signing key and randomness are wiped after native signing', () => {
  const w = require('../wasm/qspend_native.js');
  const native = require('../lib/native.js');
  const seen = [];
  const real = { sign: w.sign, publicKey: w.publicKey };
  w.sign = (...a) => { seen.push(...a); return real.sign(...a); };
  w.publicKey = (...a) => { seen.push(...a); return real.publicKey(...a); };
  try {
    const seed = Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + 3) & 255);
    const rnd = Uint8Array.from({ length: 32 }, (_, i) => (i * 11 + 5) & 255);
    native.publicKey(seed);
    native.sign(seed, Buffer.from('m'), rnd);
    const has = (a, n) => Buffer.from(a.buffer, a.byteOffset, a.byteLength).indexOf(Buffer.from(n)) !== -1;
    assert.strictEqual(seen.filter((a) => has(a, seed) || has(a, rnd)).length, 0);
    assert.strictEqual(seed[1], 10);
    assert.strictEqual(rnd[1], 16);
  } finally {
    Object.assign(w, real);
  }
});

test('a ledger refusal never repeats control or direction characters from the folder path', { skip: process.platform === 'win32' }, async () => {
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'ledger-'));
  try {
    const dir = path.join(base, 'led\u001b[31mger\u202e\u0007');
    fs.mkdirSync(dir);
    fs.chmodSync(dir, 0o777);
    const make = q.folderLedger || q.fileLedger;
    const msgs = [];
    const hex = 'a'.repeat(64);
    for (const name of ['qspend.appropriation' + '.' + hex, hex + '.payment.send', hex + '.x']) {
      try {
        await make(dir).read(name);
      } catch (e) {
        msgs.push(e.message);
      }
    }
    assert.ok(msgs.some((m) => /can be written by every user/.test(m)));
    for (const m of msgs) assert.doesNotMatch(m, /[\u0000-\u001f\u007f-\u009f\u202a-\u202e]/u);
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
});

test('a ledger under a folder another group can change, or whose folder was replaced, is refused', { skip: process.platform === 'win32' }, async () => {
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const make = q.folderLedger || q.fileLedger;
  const name = 'qspend.appropriation.' + 'a'.repeat(64);
  const a = fs.mkdtempSync(path.join(os.tmpdir(), 'ledger-'));
  const b = fs.mkdtempSync(path.join(os.tmpdir(), 'ledger-'));
  try {
    fs.chmodSync(a, 0o770);
    const la = path.join(a, 'ledger');
    fs.mkdirSync(la, { mode: 0o700 });
    await assert.rejects(Promise.resolve().then(() => make(la).read(name)), /above the ledger can be changed by another user/);
    fs.chmodSync(la, 0o770);
    await Promise.resolve().then(() => make(la).read(name));
    const lb = path.join(b, 'ledger');
    fs.mkdirSync(lb, { mode: 0o700 });
    const l = make(lb);
    await Promise.resolve().then(() => l.read(name));
    fs.renameSync(lb, lb + '.old');
    fs.mkdirSync(lb, { mode: 0o700 });
    await assert.rejects(Promise.resolve().then(() => l.read(name)), /moved or replaced/);
  } finally {
    fs.rmSync(a, { recursive: true, force: true });
    fs.rmSync(b, { recursive: true, force: true });
  }
});

test('a file that changes while the CLI hashes it is refused and nothing is written', { skip: process.platform === 'win32' }, async () => {
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const { spawnSync } = require('child_process');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'change-'));
  try {
    const doc = path.join(dir, 'doc.bin');
    fs.writeFileSync(doc, Buffer.alloc(4 * 1024 * 1024, 7));
    const hook = path.join(dir, 'hook.js');
    fs.writeFileSync(hook, 'const fs=require(\'fs\');const t=process.env.CHANGE_FILE;const open=fs.promises.open;fs.promises.open=async function(p,...a){const fh=await open.call(this,p,...a);if(p===t){const read=fh.read.bind(fh);let n=0;fh.read=async(...b)=>{const r=await read(...b);n+=1;if(n===1){const fd=fs.openSync(t,\'r+\');fs.writeSync(fd,Buffer.from(\'Z\'),0,1,0);fs.closeSync(fd);}return r;};}return fh;};');
    const iso = (ms) => new Date(ms).toISOString();
    const now = Date.now();
    const app = q.appropriation({ key: q.generateKey(), budgetRef: 'B1', line: 'roads', period: '2026', currency: 'EUR', amount: '1000', validUntil: iso(now + 864e5), approvedAt: iso(now - 9000) });
    const al = q.allotment({ ledger: false, key: q.generateKey(), appropriation: app, unit: 'works', amount: '500', first: true, allottedAt: iso(now - 8000) });
    const com = q.commitment({ ledger: false, key: q.generateKey(), allotment: al, supplier: 'ACME BV', partySecret: crypto.getRandomValues(new Uint8Array(32)), document: Buffer.from('po'), amount: '400', first: true, committedAt: iso(now - 7000) });
    const receiver = q.generateKey();
    const commitment = path.join(dir, 'commitment.json');
    fs.writeFileSync(commitment, JSON.stringify(com));
    const keyFile = path.join(dir, 'key');
    fs.writeFileSync(keyFile, Buffer.from(receiver).toString('hex') + '\n', { mode: 0o600 });
    await new Promise((resolve) => setTimeout(resolve, 50));
    const out = path.join(dir, 'out.json');
    const r = spawnSync(process.execPath, ['-r', hook, path.join(__dirname, '..', 'bin', 'qspend.js')].concat(['receipt', '--key', keyFile, '--commitment', commitment, '--document', doc], ['--out', out]), { env: Object.assign({}, process.env, { CHANGE_FILE: doc, QUANTOVA_OFFLINE: '1' }), encoding: 'utf8' });
    assert.notStrictEqual(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stderr, /changed while it was read/);
    assert.ok(!fs.existsSync(out));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('options inherited from a polluted Object.prototype are ignored', async () => {
  const iso = (ms) => new Date(ms).toISOString();
  const now = Date.now();
  const k = q.generateKey();
  const env = q.appropriation({ key: k, budgetRef: 'B1', line: 'roads', period: '2026', currency: 'EUR', amount: '5', validUntil: iso(now + 864e5), approvedAt: iso(now - 1000) });
  const opts = { type: 'appropriation', network: 'testnet', ministryKeys: [q.keyId(k)], at: iso(now) };
  const before = (await q.verify(env, opts)).status;
  assert.notStrictEqual(before, 'valid');
  Object.prototype.requireAnchor = false;
  Object.prototype.first = true;
  try {
    assert.strictEqual((await q.verify(env, opts)).status, before);
    const app = q.appropriation({ key: q.generateKey(), budgetRef: 'B1', line: 'roads', period: '2026', currency: 'EUR', amount: '1000', validUntil: iso(now + 864e5), approvedAt: iso(now - 9000) });
    assert.throws(() => q.allotment({ ledger: false, key: q.generateKey(), appropriation: app, unit: 'works', amount: '5', allottedAt: iso(now - 8000) }), /first set to true/);
  } finally {
    delete Object.prototype.requireAnchor;
    delete Object.prototype.first;
  }
});

test('a huge byte array or list given as options is refused at once', async () => {
  for (const bad of [Buffer.alloc(50 * 1024 * 1024), new Array(100000).fill('x')]) {
    const started = Date.now();
    assert.throws(() => q.appropriation(bad), (e) => e instanceof Error && !(e instanceof RangeError) && !(e instanceof TypeError));
    await assert.rejects(q.verify({}, bad), (e) => e instanceof Error && !(e instanceof RangeError) && !(e instanceof TypeError));
    assert.ok(Date.now() - started < 1000, 'took ' + (Date.now() - started) + ' ms');
  }
});

test('a signing key, salt or secret made of too few different byte values is refused', () => {
  const pattern = (n) => Uint8Array.from({ length: 32 }, (_, i) => 1 + (i % n));
  const weak = [Uint8Array.from(Buffer.from('secretsecretsecretsecretsecretse')), pattern(2), pattern(12)];
  for (const k of weak) assert.throws(() => q.publicKey(k), /too few different byte values/);
  assert.ok(q.publicKey(pattern(13)).length > 0);
  for (let i = 0; i < 200; i += 1) assert.ok(q.publicKey(q.generateKey()).length > 0);
  const scope = 'ab'.repeat(32);
  for (const s of weak) {
    assert.throws(() => q.commitParty('NL-1', { salt: s }), /too few different byte values/);
    assert.throws(() => q.commitParty('NL-1', { secret: s, scope }), /too few different byte values/);
  }
  assert.ok(q.commitParty('NL-1', { salt: pattern(13) }).ref);
});
