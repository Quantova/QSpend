// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const BIN = path.join(ROOT, 'bin', fs.readdirSync(path.join(ROOT, 'bin')).find((f) => f.endsWith('.js')));
const ID = 'NL-998877665';

const run = (args, cwd) => spawnSync(process.execPath, [BIN].concat(args), { encoding: 'utf8', cwd });

test('a personal identifier given on the command line is refused, only an identity file is read', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'identity-flags-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const help = run(['help'], dir);
  const inline = [
    ['commit-party', '--identity', ID, '--salt-out', path.join(dir, 'a.salt')],
    ['commit-party', '--identity=' + ID, '--salt-out', path.join(dir, 'b.salt')],
  ];
  for (const flag of ['--party-identity', '--taxpayer-identity']) {
    if (help.stdout.includes(flag + '-file')) inline.push(['verify', 'x.json', '--type', 'filing', flag, ID, flag.replace('identity', 'salt') + '-file', 'x.salt']);
  }
  for (const args of inline) {
    const r = run(args, dir);
    assert.strictEqual(r.status, 64, args.join(' ') + '\n' + r.stderr);
    assert.match(r.stderr, /unknown option/);
  }
  assert.doesNotMatch(help.stdout, /--identity (?!-)|--party-identity |--taxpayer-identity /);
  const file = path.join(dir, 'identity.txt');
  fs.writeFileSync(file, ID + '\n', { mode: 0o600 });
  const salt = path.join(dir, 'c.salt');
  const modes = help.stdout.includes('--random-salt') ? ['--random-salt'] : [];
  const ok = run(['commit-party', '--identity-file', file, '--salt-out', salt].concat(modes), dir);
  assert.strictEqual(ok.status, 0, ok.stderr);
  assert.ok(fs.existsSync(salt));
  assert.ok(!ok.stdout.includes(ID));
});
