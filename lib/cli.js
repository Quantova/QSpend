// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const qx = require('..');
const F = require('./format');

const ENVELOPE_MAX = 1024 * 1024;
const KEY_JSON_MAX = 64 * 1024;
const FILE_MAX = 64 * 1024 * 1024 * 1024;
const IDENTITY_FILE_MAX = 4096;
const RECORD_FILES_MAX = F.SPEC.recordsMax || 2000;
const RPC_MAX = 8;
const SOVEREIGN_ONLY = F.ALGORITHM === 'ML-DSA-87';
const SOVEREIGN_VALUES = SOVEREIGN_ONLY ? ['sovereign'] : [];
const SOVEREIGN_USAGE = SOVEREIGN_ONLY ? ' --sovereign FILE' : '';

function usageError(message) {
  const e = new Error(message);
  e.usage = true;
  return e;
}

const kebab = (s) => s.replace(/[A-Z]/g, (c) => '-' + c.toLowerCase());
const camel = (s) => s.replace(/-([a-z])/g, (m, c) => c.toUpperCase());

function secretFields(t) {
  return t.secretParty ? [t.secretParty.field, t.secretParty.scheme] : [];
}

function typeFlags(type) {
  const t = F.SPEC.types[type];
  const values = ['key', 'out', 'note', kebab(t.time)];
  for (const lname of Object.keys(t.links || {})) values.push(kebab(lname));
  for (const [fname, def] of Object.entries(t.fields || {})) {
    if (secretFields(t).includes(fname)) continue;
    values.push(kebab(fname));
    if (def[3]) values.push(kebab(def[3]));
  }
  if (t.secretParty) values.push(kebab(t.secretParty.identity) + '-file', 'party-secret-file');
  if (t.chain || t.once) values.push('ledger');
  const flags = ['force'];
  if (t.chain || t.once) flags.push('no-ledger');
  if (t.chain) {
    values.push('previous');
    flags.push('first');
  }
  return { flags, values: [...new Set(values)] };
}

function docFields(type) {
  return Object.entries(F.SPEC.types[type].fields || {}).filter(([, def]) => def[0] === 'digest' && def[3]).map(([name, def]) => ({ field: name, doc: def[3] }));
}

const SPEC = {
  keygen: { flags: ['force'], values: [] },
  key: { flags: [], values: [] },
  'commit-party': { flags: ['random-salt'], values: ['identity-file', 'salt-out', 'salt-file', 'secret-file', 'scope'] },
  anchor: { flags: ['trust-single-endpoint', 'allow-loopback'], values: ['seed-file', 'index', 'max-fee'].concat(SOVEREIGN_VALUES), multi: ['rpc', 'allow-endpoint'] },
  complete: { flags: ['trust-single-endpoint', 'allow-loopback'], values: ['pending', 'tx'].concat(SOVEREIGN_VALUES), multi: ['rpc', 'allow-endpoint'] },
};
const TYPE_BY_COMMAND = Object.fromEntries(F.TYPES.map((t) => [kebab(t), t]));
for (const type of F.TYPES) SPEC[kebab(type)] = typeFlags(type);
const ROLE_FLAGS = Object.keys(F.SPEC.roles).map(kebab);
const VERIFY_DOC_FLAGS = [...new Set(F.TYPES.flatMap((t) => docFields(t).flatMap((d) => [kebab(d.doc), kebab(d.field)])))];
for (const [name, c] of Object.entries(F.SPEC.commands || {})) SPEC[name] = { flags: c.flags || [], values: c.values || [], multi: c.multi || [] };
SPEC.verify = {
  flags: ['allow-unanchored', 'all-supplied', 'json', 'trust-single-endpoint', 'trust-custom-endpoints', 'allow-loopback'],
  values: ['type', 'at', 'max-anchor-delay', 'max-anchor-lookups', 'party-field', 'party-identity-file', 'party-salt-file'].concat(VERIFY_DOC_FLAGS, Object.keys(F.SPEC.verifyOptions || {}).map(kebab), SOVEREIGN_VALUES),
  multi: ROLE_FLAGS.concat(['record', 'record-dir', 'rpc', 'allow-endpoint', 'expect-sender']),
};

function fieldHelp(type) {
  const t = F.SPEC.types[type];
  const parts = ['--key FILE'];
  for (const [lname, l] of Object.entries(t.links || {})) parts.push((l.optional ? '[' : '') + '--' + kebab(lname) + ' FILE' + (l.optional ? ']' : ''));
  if (t.secretParty) parts.push('--' + kebab(t.secretParty.identity) + '-file FILE --party-secret-file FILE');
  for (const [fname, def] of Object.entries(t.fields || {})) {
    if (secretFields(t).includes(fname)) continue;
    const copied = Object.values(t.links || {}).some((l) => (l.copy || []).some(([mine]) => mine === fname));
    const optional = copied || (def[0] === 'text' && !def[2]) || def[0] === 'optref';
    const arg = def[0] === 'digest' && def[3] ? '(--' + kebab(def[3]) + ' FILE | --' + kebab(fname) + ' HEX)' : '--' + kebab(fname) + ' ' + ({ key: 'KEY', party: 'HEX', digest: 'HEX', optref: 'HEX', currency: 'CODE', amount: 'N', posamount: 'N', time: 'TIME', size: 'N' }[def[0]] || 'TEXT');
    parts.push(optional ? '[' + arg + ']' : arg);
  }
  if (t.chain) parts.push('(--previous FILE | --first)');
  if (t.chain || t.once) parts.push('(--ledger DIR | --no-ledger)');
  parts.push('[--' + kebab(t.time) + ' TIME] [--note TEXT] --out FILE');
  return '  ' + F.NAME + ' ' + kebab(type) + ' ' + parts.join(' ');
}

const HELP = [
  F.NAME + ', ' + F.SPEC.summary + ' with Quantova time proofs',
  '',
  '  ' + F.NAME + ' keygen <keyfile>',
  '  ' + F.NAME + ' key <keyfile>',
  '  ' + F.NAME + ' commit-party --identity-file FILE (--secret-file FILE --scope HEX --salt-out FILE | --salt-file FILE | --random-salt --salt-out FILE)',
].concat(F.TYPES.map(fieldHelp), [
  '  ' + F.NAME + ' anchor <envelope>... --seed-file <file>' + SOVEREIGN_USAGE + ' [--index N]' + (SOVEREIGN_ONLY ? '' : ' [--rpc URL]...') + ' [--trust-single-endpoint] [--allow-endpoint HOST]... [--allow-loopback] [--max-fee N]',
  '  ' + F.NAME + ' complete <envelope>... --pending FILE' + SOVEREIGN_USAGE + ' [--tx ID]' + (SOVEREIGN_ONLY ? '' : ' [--rpc URL]...') + ' [--trust-single-endpoint] [--allow-endpoint HOST]... [--allow-loopback]',
].concat(Object.entries(F.SPEC.commands || {}).map(([name, c]) => '  ' + F.NAME + ' ' + name + ' ' + c.usage), [
  '  ' + F.NAME + ' verify <envelope> --type TYPE' + SOVEREIGN_USAGE + ' ' + ROLE_FLAGS.map((r) => '--' + r + ' KEY...').join(' ') + ' [--record FILE]... [--record-dir DIR]... [--all-supplied]',
  '              [--party-field NAME --party-identity-file FILE --party-salt-file FILE]',
  '              [document options of the type] [--allow-unanchored] [--at TIME] [--max-anchor-delay SECONDS] [--max-anchor-lookups N]',
  '              ' + Object.keys(F.SPEC.verifyOptions || {}).map((k) => '[--' + kebab(k) + ' HEX] ').join('') + '[--expect-sender ADDRESS]...' + (SOVEREIGN_ONLY ? '' : ' [--rpc URL]... [--trust-custom-endpoints]') + ' [--trust-single-endpoint] [--allow-endpoint HOST]...',
  '              [--allow-loopback] [--json]',
  '',
  'Record types are ' + F.TYPES.map(kebab).join(', ') + '. Roles are ' + ROLE_FLAGS.join(', ') + ', and a key may hold only one role.',
  'A KEY is a 64 hex character key id or a ' + F.KEY_FORMAT + ' file written by the key command. Amounts are whole numbers of minor',
  'units and a CODE is three capital letters, normally an ISO 4217 currency code. Documents are hashed with SHA3-256 as they are',
  'read and never leave this machine. A party is named only by a salted commitment from commit-party, whose salt file stays',
  'with its holder. Identities are read from files only, so they never appear in the shell history or the process list. With',
  '--secret-file, a 32 byte secret made by keygen and kept by the authority, and --scope, the reference of the record that defines',
  'the series, the same party always receives the same commitment in that series, so a repeat is detected. --salt-file reuses',
  'the salt of an earlier commitment and --random-salt draws a new one. Identifiers are made canonical before they are hashed,',
  'so case, spaces, separators and lookalike characters do not change a commitment. A party that may appear only once in a',
  'series is always derived from the secret of the authority, given with --party-secret-file.',
].concat(F.FIXED_SCOPES.length ? ['--scope ' + F.FIXED_SCOPES.join(' or ') + ' is the one scope of every such party of the authority, so a party keeps one commitment across all series.'] : [], [
  'A record in a series names the previous record of the series with --previous, or --first when there is none. Signing',
  'alone does not stop a second record at the same position of a series. Give --ledger with one folder shared by every signer of the series, and the record is',
  'signed only when it follows the latest record the folder holds, and a second record at the same position is refused. A record of',
  'a series is refused without --ledger, unless --no-ledger declares that the integrating system serialises the series itself.',
  'Verification checks the record and every record it relies on, taken from the --record files, and a record in a series is',
  'valid only with --all-supplied, which declares that every record held for the series was given. --record-dir reads every',
  '.json file of a folder as a record. An anchor time is accepted only when the anchor is proven, by a finality certificate or',
  'by official endpoints of the network run by two different operators. An anchor confirmed only by one operator, or by',
  'endpoints given with --rpc, is unproven, treated as not anchored, and the result is indeterminate. --rpc endpoints are',
  'consulted by verify only with --trust-custom-endpoints, loopback endpoints only with --allow-loopback and private network',
  'endpoints only when named with --allow-endpoint. --expect-sender names the account that must have signed each anchor.',
  '--trust-single-endpoint lets one endpoint supply the chain time and stamping data alone. The endpoints consulted are',
  'printed with the result. When several anchors of one record are supplied the earliest that verifies is used.',
  '--max-anchor-lookups bounds the anchoring transactions read from the chain, 8 for each record given plus 32 unless given,',
  'and a record whose anchor was not read within that bound is indeterminate. A verification that reaches its time limit of',
  'two minutes is indeterminate. Without --at the time of verification is read from the chain, and verification stops with',
  'exit code 2 when it cannot be read.',
  '',
].concat(SOVEREIGN_ONLY ? [
  'This build anchors and verifies only on a sovereign network. anchor, complete and verify require --sovereign FILE, a JSON',
  'description of the network with its chainId, genesis, contract, genesisTime, blocks, the rpcs of its operators and',
  'optionally its finality and requireFinality, and never use the public Quantova network. The endpoints are taken from',
  'that file, so --rpc is not accepted, and loopback endpoints are used only with --allow-loopback.',
  '',
] : [], [
  'If anchor is interrupted after its transaction may have been sent, it keeps a pending stamp beside each envelope and',
  'refuses to anchor them again. Finish it with complete, giving the same envelopes in the same order.',
  '',
  'Exit codes are 0 for valid, 1 for invalid, refused or an error, 2 for indeterminate and 64 for usage errors.',
])))).join('\n');

function parse(command, argv) {
  const spec = SPEC[command];
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (!a.startsWith('--')) {
      positional.push(a);
      continue;
    }
    const name = a.slice(2);
    if (spec.flags.includes(name)) {
      if (flags[name]) throw usageError('--' + name + ' was given twice');
      flags[name] = true;
    } else if (spec.values.includes(name) || (spec.multi || []).includes(name)) {
      const v = argv[i + 1];
      if (v === undefined || v.startsWith('--')) throw usageError('--' + name + ' needs a value');
      if (v.length === 0) throw usageError('--' + name + ' was given an empty value');
      i += 1;
      if ((spec.multi || []).includes(name)) (flags[name] = flags[name] || []).push(v);
      else if (flags[name] !== undefined) throw usageError('--' + name + ' was given twice');
      else flags[name] = v;
    } else {
      throw usageError('unknown option ' + safe(a).slice(0, 40));
    }
  }
  return { positional, flags };
}

function hexNibble(code) {
  if (code >= 48 && code <= 57) return code - 48;
  if (code >= 97 && code <= 102) return code - 87;
  if (code >= 65 && code <= 70) return code - 55;
  return -1;
}

function readSeed(file, what) {
  if (!file) throw usageError(what + ' is required');
  const fd = openRegular(file, 'key file');
  const raw = Buffer.allocUnsafeSlow(131);
  const seed = new Uint8Array(32);
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) throw usageError('the key file must be a regular file');
    if (process.platform !== 'win32') {
      if ((st.mode & 0o077) !== 0) throw usageError('the key file ' + file + ' is readable by other users, restrict it with chmod 600');
      if (typeof process.getuid === 'function' && st.uid !== process.getuid()) throw usageError('the key file ' + file + ' is not owned by the current user');
    }
    const n = fs.readSync(fd, raw, 0, raw.length, 0);
    if (n > 66) throw usageError('the key file must hold only a 32 byte seed as 64 hex characters');
    let end = n;
    while (end > 0 && (raw[end - 1] === 10 || raw[end - 1] === 13 || raw[end - 1] === 32)) end -= 1;
    if (end !== 64) throw usageError('the key file must hold a 32 byte seed as 64 hex characters');
    for (let i = 0; i < 32; i += 1) {
      const hi = hexNibble(raw[2 * i]);
      const lo = hexNibble(raw[2 * i + 1]);
      if (hi < 0 || lo < 0) throw usageError('the key file must hold a 32 byte seed as 64 hex characters');
      seed[i] = (hi << 4) | lo;
    }
    return seed;
  } catch (e) {
    seed.fill(0);
    throw e;
  } finally {
    raw.fill(0);
    fs.closeSync(fd);
  }
}

function openRegular(file, what) {
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0);
  let fd;
  try {
    fd = fs.openSync(file, flags);
  } catch (e) {
    throw usageError(e.code === 'ELOOP' ? 'the ' + what + ' must not be a symbolic link' : 'the ' + what + ' ' + safe(file) + ' could not be opened');
  }
  if (!fs.fstatSync(fd).isFile()) {
    fs.closeSync(fd);
    throw usageError('the ' + what + ' must be a regular file');
  }
  return fd;
}

function statOf(file) {
  try {
    return fs.lstatSync(file);
  } catch (e) {
    if (e.code === 'ENOENT') return null;
    throw e;
  }
}

const pendingTemp = new Set();

function cleanupTemp() {
  for (const t of pendingTemp) {
    try {
      fs.rmSync(t, { force: true });
    } catch (e) {
      continue;
    }
  }
}

for (const [sig, code] of [['SIGINT', 130], ['SIGTERM', 143], ['SIGHUP', 129]]) {
  process.on(sig, () => {
    cleanupTemp();
    process.exit(code);
  });
}

function atomicWrite(dest, data, force) {
  const existing = statOf(dest);
  if (existing && existing.isSymbolicLink()) throw usageError('refusing to write through the symbolic link ' + safe(dest));
  if (existing && !existing.isFile()) throw usageError('something other than a file exists at ' + safe(dest));
  if (existing && !force) throw usageError('a file already exists at ' + safe(dest) + ', pass --force to replace it');
  const dir = path.dirname(dest);
  const tmp = path.join(dir, '.' + path.basename(dest) + '.' + crypto.randomBytes(6).toString('hex') + '.tmp');
  pendingTemp.add(tmp);
  try {
    const fd = fs.openSync(tmp, 'wx', 0o600);
    try {
      fs.fchmodSync(fd, 0o600);
      fs.writeSync(fd, data);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    if (force) {
      fs.renameSync(tmp, dest);
    } else {
      try {
        fs.linkSync(tmp, dest);
      } catch (e) {
        if (e.code === 'EEXIST') throw usageError('a file already exists at ' + safe(dest) + ', pass --force to replace it');
        throw e;
      }
      fs.rmSync(tmp, { force: true });
    }
    try {
      const dfd = fs.openSync(dir, 'r');
      try {
        fs.fsyncSync(dfd);
      } finally {
        fs.closeSync(dfd);
      }
    } catch (e) {
      void e;
    }
  } finally {
    fs.rmSync(tmp, { force: true });
    pendingTemp.delete(tmp);
  }
}

function strictJson(text) {
  const value = JSON.parse(text);
  const stack = [];
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    const top = stack[stack.length - 1];
    if (ch === '"') {
      let j = i + 1;
      while (text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      if (top && top.keys && top.expectKey) {
        const key = JSON.parse(text.slice(i, j + 1));
        if (top.keys.has(key)) throw new Error('the JSON repeats the key ' + JSON.stringify(key));
        top.keys.add(key);
        top.expectKey = false;
      }
      i = j;
    } else if (ch === '{') {
      stack.push({ keys: new Set(), expectKey: true });
    } else if (ch === '[') {
      stack.push({ keys: null });
    } else if (ch === '}' || ch === ']') {
      stack.pop();
    } else if (ch === ',' && top && top.keys) {
      top.expectKey = true;
    }
  }
  return value;
}

function readJson(file, what, invalidExit, limit) {
  const max = limit || ENVELOPE_MAX;
  const fd = openRegular(file, what);
  const buf = Buffer.alloc(max + 1);
  let n;
  try {
    n = fs.readSync(fd, buf, 0, buf.length, 0);
  } finally {
    fs.closeSync(fd);
  }
  const bad = (message) => {
    const e = new Error(message);
    if (invalidExit) e.invalid = true;
    else e.usage = true;
    return e;
  };
  if (n > max) throw bad('the ' + what + ' is larger than ' + max + ' bytes');
  try {
    return strictJson(buf.subarray(0, n).toString('utf8'));
  } catch (e) {
    throw bad('the ' + what + ' ' + safe(file) + ' is not valid JSON');
  }
}

function asciiJson(value) {
  return JSON.stringify(value, null, 2).replace(/[\u007f-\uffff]/g, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
}

function safe(value) {
  return String(value).replace(/[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff\ufff9-\ufffb\u00ad\u180e\ufe00-\ufe0f]|\uDB40[\uDC00-\uDC7F]/g, '?');
}

function withSeed(file, what, fn) {
  const seed = readSeed(file, what);
  try {
    return fn(seed);
  } finally {
    seed.fill(0);
  }
}

async function withSeedAsync(file, what, fn) {
  const seed = readSeed(file, what);
  try {
    return await fn(seed);
  } finally {
    seed.fill(0);
  }
}

async function cmdKeygen(positional, flags) {
  if (positional.length !== 1) throw usageError('keygen takes one key file path');
  const seed = qx.generateKey();
  const text = Buffer.alloc(65);
  try {
    const digits = '0123456789abcdef';
    for (let i = 0; i < 32; i += 1) {
      text[2 * i] = digits.charCodeAt(seed[i] >> 4);
      text[2 * i + 1] = digits.charCodeAt(seed[i] & 15);
    }
    text[64] = 10;
    atomicWrite(positional[0], text, flags.force);
    console.log('key id ' + qx.keyId(seed));
  } finally {
    seed.fill(0);
    text.fill(0);
  }
  return 0;
}

async function cmdKey(positional) {
  if (positional.length !== 1) throw usageError('key takes one key file path');
  const desc = withSeed(positional[0], 'a key file', (seed) => qx.describeKey(seed));
  process.stdout.write(asciiJson(desc) + '\n');
  return 0;
}

function need(flags, name) {
  if (flags[name] === undefined) throw usageError('--' + name + ' is required');
  return flags[name];
}

function readAll(fd, what, max) {
  const size = fs.fstatSync(fd).size;
  if (size > max) {
    const err = new Error('the ' + what + ' is larger than ' + max + ' bytes');
    err.invalid = true;
    throw err;
  }
  const buf = Buffer.alloc(size);
  let off = 0;
  while (off < size) {
    const n = fs.readSync(fd, buf, off, size - off, off);
    if (n === 0) break;
    off += n;
  }
  return buf.subarray(0, off);
}

function seqFlag(value, name) {
  if (!/^\d{1,9}$/.test(value)) throw usageError('--' + name + ' is a whole number');
  return Number(value);
}

function distinctFiles(files) {
  const seen = new Set();
  for (const f of files) {
    const st = statOf(f);
    if (!st || !st.isFile()) throw usageError('the envelope ' + safe(f) + ' is not a regular file');
    const id = st.dev + ':' + st.ino;
    if (seen.has(id)) throw usageError('the envelope ' + safe(f) + ' was given twice');
    seen.add(id);
    try {
      fs.accessSync(path.dirname(f), fs.constants.W_OK);
      fs.accessSync(f, fs.constants.W_OK);
    } catch (e) {
      throw usageError('the envelope ' + safe(f) + ' or its folder is not writable, so the anchor could not be saved');
    }
  }
}

function pendingPath(file) {
  return file + '.pending.json';
}

function saveAnchored(files, anchored) {
  let lost = false;
  anchored.forEach((env, i) => {
    try {
      atomicWrite(files[i], asciiJson(env) + '\n', true);
      console.log('anchored ' + safe(files[i]) + ' in transaction ' + safe(env.anchor.anchor.tx));
    } catch (e) {
      lost = true;
      console.error('the anchored envelope could not be written to ' + safe(files[i]) + ', it follows on standard output');
      process.stdout.write(asciiJson(env) + '\n');
    }
  });
  return lost ? 1 : 0;
}

async function cmdAnchor(positional, flags) {
  if (positional.length === 0) throw usageError('anchor takes one or more envelopes');
  if (positional.length > BATCH_MAX) throw usageError('at most ' + BATCH_MAX + ' envelopes can be anchored at once');
  const sovereign = sovereignNetwork(flags);
  for (const f of positional) if (Buffer.byteLength(path.basename(pendingPath(f))) > 200) throw usageError('the name of ' + safe(f) + ' is too long to keep a pending stamp beside it');
  distinctFiles(positional);
  for (const f of positional) {
    if (statOf(pendingPath(f))) throw usageError('an unfinished anchor exists in ' + safe(pendingPath(f)) + ', finish it with complete first');
  }
  const pendingFile = pendingPath(positional[0]);
  const envs = positional.map((f) => readJson(f, 'envelope', true, ENVELOPE_MAX));
  let index = 0;
  if (flags.index !== undefined) index = seqFlag(flags.index, 'index');
  const seed = readSeed(flags['seed-file'] || process.env.QSTAMP_SEED_FILE, '--seed-file of a funded Quantova account');
  let saved = false;
  const keep = (pending) => {
    const text = asciiJson(pending) + '\n';
    for (const f of positional) atomicWrite(pendingPath(f), text, saved);
    saved = true;
  };
  let anchored;
  try {
    const where = sovereign === undefined ? { network: 'testnet' } : { sovereign };
    anchored = await qx.anchor(envs, Object.assign({ seed, index, maxFee: flags['max-fee'], onPending: keep }, where, endpointOptions(flags)));
  } catch (e) {
    if (e && e.pending && typeof e.pending === 'object') {
      let message = 'the anchoring transaction may already have been sent, ' + friendly(e);
      try {
        keep(e.pending);
        message += ', the pending stamp was saved in ' + safe(pendingFile) + ', finish it with ' + F.NAME + ' complete ' + positional.map(safe).join(' ') + ' --pending ' + safe(pendingFile);
      } catch (e2) {
        message += ', the pending stamp could not be saved and follows on standard error, keep it to finish the anchor';
        process.stderr.write(asciiJson(e.pending) + '\n');
      }
      throw new Error(message);
    }
    throw e;
  } finally {
    seed.fill(0);
  }
  const code = saveAnchored(positional, anchored);
  if (code === 0 && saved) for (const f of positional) fs.rmSync(pendingPath(f), { force: true });
  return code;
}

async function cmdComplete(positional, flags) {
  if (positional.length === 0) throw usageError('complete takes the envelopes given to anchor, in the same order');
  if (positional.length > BATCH_MAX) throw usageError('at most ' + BATCH_MAX + ' envelopes can be completed at once');
  const sovereign = sovereignNetwork(flags);
  distinctFiles(positional);
  const pendingFile = need(flags, 'pending');
  const pending = readJson(pendingFile, 'pending stamp');
  if (flags.tx !== undefined) {
    if (!/^QTX1[0-9A-Z]{20,120}$/.test(flags.tx)) throw usageError('--tx is the QTX1 identifier of the stamp transaction');
    if (pending && typeof pending === 'object' && typeof pending.tx === 'string' && pending.tx !== flags.tx) throw usageError('the pending stamp already names another transaction');
    if (pending && typeof pending === 'object') pending.tx = flags.tx;
  }
  const envs = positional.map((f) => readJson(f, 'envelope', true, ENVELOPE_MAX)).map((e) => {
    if (e && typeof e === 'object' && !Array.isArray(e)) delete e.anchor;
    return e;
  });
  const anchored = await qx.complete(envs, pending, Object.assign(sovereign === undefined ? {} : { sovereign }, endpointOptions(flags)));
  const code = saveAnchored(positional, anchored);
  if (code === 0) {
    fs.rmSync(pendingFile, { force: true });
    for (const f of positional) fs.rmSync(pendingPath(f), { force: true });
  }
  return code;
}

const BATCH_MAX = 1000;
const SALT_PREFIX = F.SALT_FORMAT + ' ';

async function hashFile(file, what) {
  let fh;
  try {
    fh = await fs.promises.open(file, fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK || 0));
  } catch (e) {
    throw usageError('the ' + what + ' ' + safe(file) + ' could not be opened');
  }
  const h = crypto.createHash('sha3-256');
  const buf = Buffer.alloc(1024 * 1024);
  let size = 0;
  try {
    const first = await fh.stat({ bigint: true });
    if (!first.isFile()) throw usageError('the ' + what + ' must be a regular file');
    for (;;) {
      const { bytesRead } = await fh.read(buf, 0, buf.length, null);
      if (bytesRead === 0) break;
      size += bytesRead;
      if (size > FILE_MAX) throw usageError('the ' + what + ' is larger than ' + FILE_MAX + ' bytes');
      h.update(buf.subarray(0, bytesRead));
    }
    const last = await fh.stat({ bigint: true });
    if (last.mtimeNs !== first.mtimeNs || last.ctimeNs !== first.ctimeNs || last.size !== first.size || BigInt(size) !== last.size) throw usageError('the ' + what + ' ' + safe(file) + ' changed while it was read, nothing was signed');
  } finally {
    await fh.close();
  }
  return { digest: h.digest('hex'), size };
}

function openPublic(file, what) {
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK || 0));
  } catch (e) {
    throw usageError('the ' + what + ' ' + safe(file) + ' could not be opened');
  }
  if (!fs.fstatSync(fd).isFile()) {
    fs.closeSync(fd);
    throw usageError('the ' + what + ' must be a regular file');
  }
  return fd;
}

function readSmall(file, what, max) {
  const fd = openPublic(file, what);
  try {
    return readAll(fd, what, max);
  } finally {
    fs.closeSync(fd);
  }
}

function saltText(salt) {
  const digits = '0123456789abcdef';
  const out = Buffer.allocUnsafeSlow(SALT_PREFIX.length + 65);
  out.write(SALT_PREFIX, 0, 'ascii');
  for (let i = 0; i < 32; i += 1) {
    out[SALT_PREFIX.length + 2 * i] = digits.charCodeAt(salt[i] >> 4);
    out[SALT_PREFIX.length + 2 * i + 1] = digits.charCodeAt(salt[i] & 15);
  }
  out[out.length - 1] = 10;
  return out;
}

function readSalt(file) {
  const fd = openRegular(file, 'salt file');
  const raw = Buffer.allocUnsafeSlow(200);
  const salt = new Uint8Array(32);
  try {
    const st = fs.fstatSync(fd);
    if (process.platform !== 'win32') {
      if ((st.mode & 0o077) !== 0) throw usageError('the salt file ' + safe(file) + ' is readable by other users, restrict it with chmod 600');
      if (typeof process.getuid === 'function' && st.uid !== process.getuid()) throw usageError('the salt file ' + safe(file) + ' is not owned by the current user');
    }
    const n = fs.readSync(fd, raw, 0, raw.length, 0);
    let end = n;
    while (end > 0 && (raw[end - 1] === 10 || raw[end - 1] === 13)) end -= 1;
    if (end !== SALT_PREFIX.length + 64 || raw.subarray(0, SALT_PREFIX.length).toString('ascii') !== SALT_PREFIX) throw usageError('the salt file must hold a ' + F.SALT_FORMAT + ' line written by commit-party');
    for (let i = 0; i < 32; i += 1) {
      const hi = hexNibble(raw[SALT_PREFIX.length + 2 * i]);
      const lo = hexNibble(raw[SALT_PREFIX.length + 2 * i + 1]);
      if (hi < 0 || lo < 0) throw usageError('the salt file must hold a ' + F.SALT_FORMAT + ' line written by commit-party');
      salt[i] = (hi << 4) | lo;
    }
    return salt;
  } catch (e) {
    salt.fill(0);
    throw e;
  } finally {
    raw.fill(0);
    fs.closeSync(fd);
  }
}

function identityOf(file, follow) {
  let st = null;
  try {
    st = follow ? fs.statSync(file) : fs.lstatSync(file);
  } catch (e) {
    st = null;
  }
  let dir = path.dirname(path.resolve(file));
  try {
    dir = fs.realpathSync(dir);
  } catch (e) {
    dir = path.dirname(path.resolve(file));
  }
  return { path: path.join(dir, path.basename(file)).normalize('NFC').toLowerCase(), ino: st ? st.dev + ':' + st.ino : null, st };
}

function checkPaths(dests, sources) {
  const seen = [];
  const clash = (a, b) => a.path === b.path || (a.ino !== null && a.ino === b.ino);
  for (const [flag, f] of sources) if (f !== undefined) seen.push([flag, identityOf(f, true)]);
  for (const [flag, f, mayExist] of dests) {
    if (f === undefined) continue;
    const id = identityOf(f, false);
    if (id.st && id.st.isSymbolicLink()) throw usageError('refusing to write through the symbolic link ' + safe(f));
    if (id.st && !id.st.isFile()) throw usageError('something other than a file exists at ' + safe(f));
    if (id.st && !mayExist) throw usageError('a file already exists at ' + safe(f) + (flag === '--salt-out' ? ', a salt file is never replaced' : ', pass --force to replace it'));
    for (const [other, oid] of seen) if (clash(id, oid)) throw usageError(flag + ' must not be the same file as ' + other);
    seen.push([flag, id]);
  }
}

function hexFlag(value, name) {
  if (!/^[0-9a-f]{64}$/.test(value)) throw usageError('--' + name + ' is 64 lowercase hex characters');
  return value;
}

function capList(list, name, max) {
  const l = list || [];
  if (l.length > max) throw usageError('at most ' + max + ' values can be given for --' + name);
  return l;
}

function sovereignNetwork(flags) {
  if (!SOVEREIGN_ONLY) return undefined;
  if (flags.sovereign === undefined) throw usageError(F.NAME + ' anchors and verifies only on a sovereign network, give its description with --sovereign FILE');
  if (flags.rpc !== undefined) throw usageError('the endpoints of a sovereign network are listed in its --sovereign file, not with --rpc');
  if (flags['trust-custom-endpoints']) throw usageError('--trust-custom-endpoints does not apply to a sovereign network');
  const net = readJson(flags.sovereign, 'sovereign network', false, KEY_JSON_MAX);
  try {
    require('./core').sovereign().network(net);
  } catch (e) {
    throw usageError('the sovereign network in ' + safe(flags.sovereign) + ' is not valid, ' + friendly(e));
  }
  return net;
}

function endpointOptions(flags) {
  const out = {};
  const rpc = capList(flags.rpc, 'rpc', RPC_MAX);
  if (rpc.length) out.clients = rpc;
  const allowed = capList(flags['allow-endpoint'], 'allow-endpoint', RPC_MAX);
  if (allowed.length) out.endpointAllowList = allowed;
  if (flags['trust-single-endpoint']) out.trustSingleEndpoint = true;
  if (flags['trust-custom-endpoints']) out.trustCustomEndpoints = true;
  if (flags['allow-loopback']) out.allowLoopback = true;
  return out;
}

function keyRef(value, name) {
  if (/^[0-9a-f]{64}$/.test(value)) return value;
  const desc = readJson(value, name + ' key', false, KEY_JSON_MAX);
  if (!desc || desc.format !== F.KEY_FORMAT || typeof desc.publicKey !== 'string') throw usageError('--' + name + ' is a key id or a ' + F.KEY_FORMAT + ' file');
  return desc;
}

function sizeFlag(value) {
  if (!/^\d{1,15}$/.test(value)) throw usageError('--content-size is a whole number of bytes');
  return Number(value);
}

function writeEnvelope(file, env, force) {
  atomicWrite(file, asciiJson(env) + '\n', force);
}

function identityFrom(flags, fileFlag) {
  if (flags[fileFlag] === undefined) throw usageError('--' + fileFlag + ' is required, identities are read from a file so they never appear in the shell history or the process list');
  const raw = readSmall(flags[fileFlag], 'identity file', IDENTITY_FILE_MAX);
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(raw);
  } catch (e) {
    throw usageError('the identity file must be UTF-8 text');
  }
  return text.replace(/\r?\n$/, '');
}

async function digestFrom(flags, fileFlag, digestFlag, what, required) {
  if (flags[fileFlag] !== undefined && flags[digestFlag] !== undefined) throw usageError('give --' + fileFlag + ' or --' + digestFlag + ', not both');
  if (flags[fileFlag] !== undefined) return hashFile(flags[fileFlag], what);
  if (flags[digestFlag] !== undefined) return { digest: hexFlag(flags[digestFlag], digestFlag), size: null };
  if (required) throw usageError('give --' + fileFlag + ' or --' + digestFlag);
  return null;
}

function amountFlag(value, name) {
  if (!/^(0|[1-9][0-9]{0,29})$/.test(value)) throw usageError('--' + name + ' is a whole number of minor units');
  return value;
}

async function cmdCommitParty(positional, flags) {
  if (positional.length) throw usageError('commit-party takes options only');
  const modes = [flags['salt-file'] !== undefined, flags['secret-file'] !== undefined, !!flags['random-salt']];
  if (modes.filter(Boolean).length !== 1) throw usageError('give exactly one of --secret-file with --scope, --salt-file or --random-salt');
  if (flags.scope !== undefined && flags['secret-file'] === undefined) throw usageError('--scope goes with --secret-file');
  if (flags['salt-file'] !== undefined) {
    if (flags['salt-out'] !== undefined) throw usageError('--salt-out does not apply with --salt-file, the salt is already kept');
    const salt = readSalt(flags['salt-file']);
    let c;
    try {
      c = qx.commitParty(identityFrom(flags, 'identity-file'), { salt });
    } finally {
      salt.fill(0);
    }
    c.salt.fill(0);
    console.log('party commitment ' + c.ref + ', from the salt in ' + safe(flags['salt-file']));
    return 0;
  }
  const out = need(flags, 'salt-out');
  checkPaths([['--salt-out', out, false]], [['--identity-file', flags['identity-file']], ['--secret-file', flags['secret-file']]]);
  let c;
  if (flags['secret-file'] !== undefined) {
    const rawScope = need(flags, 'scope');
    const scope = F.FIXED_SCOPES.includes(rawScope) ? rawScope : hexFlag(rawScope, 'scope');
    const secret = readSeed(flags['secret-file'], '--secret-file');
    try {
      c = qx.commitParty(identityFrom(flags, 'identity-file'), { secret, scope });
    } finally {
      secret.fill(0);
    }
  } else {
    c = qx.commitParty(identityFrom(flags, 'identity-file'));
  }
  const text = saltText(c.salt);
  try {
    atomicWrite(out, text, false);
  } finally {
    text.fill(0);
    c.salt.fill(0);
  }
  console.log('party commitment ' + c.ref + ', salt written to ' + safe(out));
  return 0;
}

function ledgerRequired(type) {
  const e = usageError(F.article(type) + ' is part of a series, so give --ledger with the folder shared by every signer of the series, or --no-ledger when the integrating system serialises the series itself, nothing was signed');
  e.code = F.NAME.toUpperCase() + '_LEDGER_REQUIRED';
  return e;
}

function recordFiles(flags) {
  const files = (flags.record || []).slice();
  for (const dir of flags['record-dir'] || []) {
    let names;
    try {
      names = fs.readdirSync(dir);
    } catch (e) {
      throw usageError('the record folder ' + safe(dir) + ' could not be read');
    }
    for (const n of names.sort()) {
      if (!n.endsWith('.json') || n.startsWith('.')) continue;
      const f = path.join(dir, n);
      const st = statOf(f);
      if (st && st.isFile()) files.push(f);
    }
  }
  if (files.length > RECORD_FILES_MAX) throw usageError('at most ' + RECORD_FILES_MAX + ' records can be given');
  return files;
}

async function cmdCreate(type, positional, flags) {
  if (positional.length) throw usageError(kebab(type) + ' takes options only');
  const t = F.SPEC.types[type];
  if (t.chain || t.once) {
    if (flags.ledger !== undefined && flags['no-ledger']) throw usageError('give --ledger or --no-ledger, not both');
    if (flags.ledger === undefined && !flags['no-ledger']) throw ledgerRequired(type);
  }
  const out = need(flags, 'out');
  const sources = [['--key', flags.key]];
  for (const lname of Object.keys(t.links || {})) sources.push(['--' + kebab(lname), flags[kebab(lname)]]);
  for (const [, def] of Object.entries(t.fields || {})) if (def[3]) sources.push(['--' + kebab(def[3]), flags[kebab(def[3])]]);
  if (t.chain) sources.push(['--previous', flags.previous]);
  if (flags.ledger !== undefined) {
    let st;
    try {
      st = fs.lstatSync(flags.ledger);
    } catch (e) {
      throw usageError('the ledger folder ' + safe(flags.ledger) + ' could not be opened');
    }
    if (!st.isDirectory()) throw usageError('--ledger is a folder, never a symbolic link');
  }
  if (t.secretParty) sources.push(['--' + kebab(t.secretParty.identity) + '-file', flags[kebab(t.secretParty.identity) + '-file']], ['--party-secret-file', flags['party-secret-file']]);
  checkPaths([['--out', out, !!flags.force]], sources);
  const opts = {};
  for (const [lname, l] of Object.entries(t.links || {})) {
    const f = flags[kebab(lname)];
    if (f !== undefined) opts[lname] = readJson(f, lname, true);
    else if (!l.optional) throw usageError('--' + kebab(lname) + ' is required');
  }
  const sizes = {};
  for (const [fname, def] of Object.entries(t.fields || {})) {
    const flag = kebab(fname);
    if (def[0] === 'digest' && def[3]) {
      const d = await digestFrom(flags, kebab(def[3]), flag, def[3].replace(/[A-Z]/g, (c) => ' ' + c.toLowerCase()), false);
      if (d) {
        opts[fname] = d.digest;
        if (d.size !== null) sizes[def[3]] = d.size;
      }
      continue;
    }
    if (def[0] === 'size' && def[3] && sizes[def[3]] !== undefined) {
      if (flags[flag] !== undefined) throw usageError('--' + flag + ' goes with a digest, the size of --' + kebab(def[3]) + ' is measured');
      opts[fname] = sizes[def[3]];
      continue;
    }
    if (flags[flag] === undefined) continue;
    const v = flags[flag];
    if (def[0] === 'key') opts[fname] = keyRef(v, flag);
    else if (def[0] === 'amount' || def[0] === 'posamount') opts[fname] = amountFlag(v, flag);
    else if (def[0] === 'digest' || def[0] === 'party' || def[0] === 'optref') opts[fname] = hexFlag(v, flag);
    else if (def[0] === 'size') opts[fname] = sizeFlag(v);
    else opts[fname] = v;
  }
  if (t.chain) {
    if ((flags.previous === undefined) === !flags.first) throw usageError('give --previous with the last ' + type + ' of the series, or --first when there is none, exactly one');
    if (flags.first) opts.first = true;
    else opts.previous = readJson(flags.previous, 'previous ' + type, true);
  }
  if (flags[kebab(t.time)] !== undefined) opts[t.time] = flags[kebab(t.time)];
  if (flags.note !== undefined) opts.note = flags.note;
  if (flags.ledger !== undefined) opts.ledger = flags.ledger;
  let env;
  if (t.secretParty) {
    const idFlag = kebab(t.secretParty.identity) + '-file';
    opts[t.secretParty.identity] = identityFrom(flags, idFlag);
    const secret = readSeed(need(flags, 'party-secret-file'), '--party-secret-file');
    try {
      env = await withSeedAsync(need(flags, 'key'), '--key', (seed) => qx.create(type, Object.assign({ key: seed, partySecret: secret }, opts)));
    } finally {
      secret.fill(0);
    }
  } else {
    env = await withSeedAsync(need(flags, 'key'), '--key', (seed) => qx.create(type, Object.assign({ key: seed }, opts)));
  }
  writeEnvelope(out, env, flags.force);
  const seq = t.chain ? ', position ' + env.statement.seq + ' of its series' : '';
  console.log(type + ' ' + env.statement[t.id] + seq + ' sealed as ' + qx.refOf(env) + ', written to ' + safe(out));
  return 0;
}

async function cmdVerify(positional, flags) {
  if (positional.length !== 1) throw usageError('verify takes one envelope');
  const sovereign = sovereignNetwork(flags);
  const type = TYPE_BY_COMMAND[need(flags, 'type')];
  if (!type) throw usageError('--type is one of ' + Object.keys(TYPE_BY_COMMAND).join(', '));
  const docs = docFields(type);
  const allowedDocs = new Set(docs.flatMap((d) => [kebab(d.doc), kebab(d.field)]));
  for (const f of VERIFY_DOC_FLAGS) if (flags[f] !== undefined && !allowedDocs.has(f)) throw usageError('--' + f + ' does not apply when verifying ' + F.article(type));
  for (const k of Object.keys(F.SPEC.verifyOptions || {})) if (flags[kebab(k)] !== undefined && !F.optionApplies(k, type)) throw usageError('--' + kebab(k) + ' does not apply when verifying ' + F.article(type));
  const env = readJson(positional[0], 'envelope', true);
  const opts = { type, requireAnchor: !flags['allow-unanchored'] };
  for (const role of Object.keys(F.SPEC.roles)) {
    const list = capList(flags[kebab(role)], kebab(role), 64);
    if (list.length) opts[role + 'Keys'] = list.map((k) => keyRef(k, kebab(role)));
  }
  const records = recordFiles(flags);
  if (records.length) opts.records = records.map((f) => readJson(f, 'record', true));
  if (flags['all-supplied']) opts.allSupplied = true;
  for (const d of docs) {
    const c = await digestFrom(flags, kebab(d.doc), kebab(d.field), 'document', false);
    if (c) opts[d.field] = c.digest;
  }
  const hasIdentity = flags['party-identity-file'] !== undefined;
  const partyFlags = [flags['party-field'] !== undefined, hasIdentity, flags['party-salt-file'] !== undefined];
  if (partyFlags.some(Boolean) && !partyFlags.every(Boolean)) throw usageError('--party-field, a party identity and --party-salt-file go together');
  if (hasIdentity) opts.party = { field: camel(flags['party-field']), identity: identityFrom(flags, 'party-identity-file'), salt: readSalt(flags['party-salt-file']) };
  if (flags['max-anchor-delay'] !== undefined) opts.maxAnchorDelay = seqFlag(flags['max-anchor-delay'], 'max-anchor-delay');
  if (flags['max-anchor-lookups'] !== undefined) opts.maxAnchorLookups = seqFlag(flags['max-anchor-lookups'], 'max-anchor-lookups');
  if (flags.at !== undefined) opts.at = flags.at;
  for (const k of Object.keys(F.SPEC.verifyOptions || {})) if (flags[kebab(k)] !== undefined) opts[k] = hexFlag(flags[kebab(k)], kebab(k));
  Object.assign(opts, endpointOptions(flags));
  if (sovereign !== undefined) opts.sovereign = sovereign;
  const senders = capList(flags['expect-sender'], 'expect-sender', 64);
  if (senders.length) opts.expectedSender = senders;
  let res;
  try {
    res = await qx.verify(env, opts);
  } finally {
    if (opts.party) opts.party.salt.fill(0);
  }
  if (flags.json) {
    process.stdout.write(asciiJson(res) + '\n');
  } else {
    if (res.type) console.log('type  ' + res.type);
    for (const ch of res.checks) console.log((ch.ok ? 'ok    ' : ch.transport ? 'retry ' : ch.indeterminate ? 'open  ' : 'FAIL  ') + safe(ch.name) + '  ' + safe(ch.detail));
    for (const n of res.notices || []) console.log('note  ' + safe(n));
    if ((res.endpoints || []).length) {
      console.log('endpoints  ' + res.endpoints.map(safe).join(', '));
      if (res.officialEndpoints === false) console.log('notice  endpoints other than the official ones of this network were consulted, an anchor confirmed only by them is not proven');
    }
    console.log(res.status.toUpperCase());
  }
  return res.status === 'valid' ? 0 : res.status === 'indeterminate' ? 2 : 1;
}

async function main() {
  const [command, ...rest] = process.argv.slice(2);
  if (!command || command === 'help' || command === '--help' || command === '-h') {
    console.log(HELP);
    return command ? 0 : 64;
  }
  if (!Object.hasOwn(SPEC, command)) throw usageError('unknown command ' + safe(command).slice(0, 40));
  const { positional, flags } = parse(command, rest);
  const run = { keygen: cmdKeygen, key: cmdKey, 'commit-party': cmdCommitParty, anchor: cmdAnchor, complete: cmdComplete, verify: cmdVerify }[command];
  if (run) return run(positional, flags);
  const extra = (F.SPEC.commands || {})[command];
  if (extra) return extra.run(positional, flags, { qx, F, need, readJson, hashFile, atomicWrite, asciiJson, usageError, safe, checkPaths });
  return cmdCreate(TYPE_BY_COMMAND[command], positional, flags);
}

function friendly(e) {
  if (e && typeof e.syscall === 'string' && typeof e.code === 'string') return 'a file could not be ' + (e.syscall === 'open' || e.syscall === 'read' ? 'opened' : 'written') + ' (' + e.code + ')';
  return (e && e.message) || String(e);
}

const EVIDENCE = /not a valid envelope|not validly signed|must be an? [a-z]+ envelope|does not belong to these|already anchored|signature that does not verify|not signed by the key it names|must not sign this|cannot be dated before|cannot exceed the|belongs to another series|is in another currency|already used the same|running total above|must not hold the key/;

function run() {
  main().then(
    (code) => {
      process.exitCode = code;
    },
    (e) => {
      console.error(safe(friendly(e)).slice(0, 600));
      const invalidInput = e && e.code === F.NAME.toUpperCase() + '_INVALID_INPUT';
      if (e && e.code === F.NAME.toUpperCase() + '_NO_CHAIN_TIME') process.exitCode = 2;
      else process.exitCode = e && (e.usage || (invalidInput && !EVIDENCE.test(e.message || ''))) ? 64 : 1;
    },
  );
}

module.exports = { run };
