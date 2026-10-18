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
const OLD = /the installed Qstamp is older than 0\.3\.0 and cannot prove anchors/;

function stub(version, proven, finality, deadline) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qstamp-stub-'));
  fs.mkdirSync(path.join(dir, 'lib'));
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: '@quantovainc/qstamp', version, main: 'index.js' }));
  fs.writeFileSync(path.join(dir, 'index.js'), proven ? 'module.exports = { isProven: () => false };\n' : 'module.exports = {};\n');
  if (finality) fs.writeFileSync(path.join(dir, 'lib', 'finality.js'), '\n');
  if (deadline) fs.writeFileSync(path.join(dir, 'lib', 'deadline.js'), '\n');
  return dir;
}

function loadWith(dir) {
  const script = [
    "const Module = require('module');",
    "const path = require('path');",
    'const original = Module._resolveFilename;',
    `const dir = ${JSON.stringify(dir)};`,
    'Module._resolveFilename = function (request, ...rest) {',
    "  if (request === '@quantovainc/qstamp') return path.join(dir, 'index.js');",
    "  if (request.startsWith('@quantovainc/qstamp/')) return path.join(dir, request.slice(20));",
    '  return original.call(this, request, ...rest);',
    '};',
    `require(${JSON.stringify(ROOT)});`,
  ].join('\n');
  try {
    return spawnSync(process.execPath, ['-e', script], { encoding: 'utf8' });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('the package refuses to load against a Qstamp that cannot prove anchors', () => {
  const missing = loadWith(stub('0.2.1', false, true));
  assert.notStrictEqual(missing.status, 0);
  assert.match(missing.stderr, OLD);

  const unproven = loadWith(stub('0.3.0', false, true));
  assert.notStrictEqual(unproven.status, 0);
  assert.match(unproven.stderr, OLD);

  const old = loadWith(stub('0.2.1', true, false));
  assert.notStrictEqual(old.status, 0);
  assert.match(old.stderr, OLD);

  const current = loadWith(stub('0.3.0', true, false));
  assert.strictEqual(current.status, 0, current.stderr);
});

test('a staged Qstamp is accepted only when it carries both the finality and the deadline modules', () => {
  const finalityOnly = loadWith(stub('0.2.1', true, true, false));
  assert.notStrictEqual(finalityOnly.status, 0);
  assert.match(finalityOnly.stderr, OLD);

  const deadlineOnly = loadWith(stub('0.2.1', true, false, true));
  assert.notStrictEqual(deadlineOnly.status, 0);
  assert.match(deadlineOnly.stderr, OLD);

  const unproven = loadWith(stub('0.2.1', false, true, true));
  assert.notStrictEqual(unproven.status, 0);
  assert.match(unproven.stderr, OLD);

  const prerelease = loadWith(stub('0.3.0-rc.1', true, false, false));
  assert.notStrictEqual(prerelease.status, 0);
  assert.match(prerelease.stderr, OLD);

  const staged = loadWith(stub('0.2.1', true, true, true));
  assert.strictEqual(staged.status, 0, staged.stderr);
});
