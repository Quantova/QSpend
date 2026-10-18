'use strict';

const fs = require('fs');
const path = require('path');
const test = require('node:test');
const assert = require('node:assert');
const F = require('../lib/format');
const { cliCampaign, runCli, tempDir, SAYS_VALID } = require('./fuzz');
const { honest } = require('./honest');

const BIN = path.join(__dirname, '..', 'bin', F.NAME + '.js');
const ENVELOPE_MAX = 1024 * 1024;
const kebab = (s) => s.replace(/[A-Z]/g, (c) => '-' + c.toLowerCase());

function rootType() {
  return Object.entries(F.SPEC.types).find(([, t]) => Object.keys(t.links || {}).length === 0 && !t.chain && !t.secretParty && !t.deriveFields)[0];
}

test('hostile envelope files make the command line exit non zero quickly and never print VALID', async (t) => {
  const w = await honest();
  const type = rootType();
  const env = Object.assign({}, w.all[type]);
  delete env.anchor;
  const role = F.SPEC.types[type].role;
  const at = new Date(w.now * 1000).toISOString();
  const base = ['verify', '--type', kebab(type), '--' + kebab(role), w.q.keyId(w.K[role]), '--allow-unanchored', '--at', at];
  const dir = tempDir('qcli-ok');
  const good = path.join(dir, 'honest.json');
  fs.writeFileSync(good, JSON.stringify(env));
  try {
    const control = await runCli(BIN, [base[0], good].concat(base.slice(1)));
    assert.strictEqual(control.code, 0, control.out + control.err);
    assert.ok(SAYS_VALID.test(control.out), control.out);
    const results = await cliCampaign({
      bin: BIN,
      tag: 'qcli',
      cap: ENVELOPE_MAX,
      validText: JSON.stringify(env),
      commands: [
        (file) => [base[0], file].concat(base.slice(1)),
        (file) => [base[0], file].concat(base.slice(1), ['--json']),
      ],
    });
    t.diagnostic(results.length + ' runs, slowest ' + Math.max(...results.map((r) => r.ms)) + ' ms');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
