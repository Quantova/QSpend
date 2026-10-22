// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const qstamp = require('@quantovainc/qstamp');
const native = require('./native');
const F = require('./format');

function requireProvingQstamp() {
  const dir = path.dirname(require.resolve('@quantovainc/qstamp/package.json'));
  const version = /^(\d+)\.(\d+)\.(\d+)$/.exec(String(require(path.join(dir, 'package.json')).version));
  const released = !!version && (Number(version[1]) > 0 || Number(version[2]) >= 3);
  const staged = fs.existsSync(path.join(dir, 'lib', 'deadline.js')) && fs.existsSync(path.join(dir, 'lib', 'finality.js'));
  if (typeof qstamp.isProven !== 'function' || !(released || staged)) {
    throw new Error('the installed Qstamp is older than 0.3.0 and cannot prove anchors');
  }
}
requireProvingQstamp();

function requireSeed(key) {
  if (!((ArrayBuffer.isView(key) && key instanceof Uint8Array)) || key.length !== 32 || !(key.buffer instanceof ArrayBuffer)) {
    F.reject('a signing key is a 32 byte Uint8Array seed, kept by its holder and wiped with fill(0) after use');
  }
  if (new Set(key).size < 13) F.reject('a signing key made of too few different byte values is refused, draw one with generateKey');
  return key;
}

function sovereign() {
  try {
    return require('./sovereign');
  } catch (e) {
    if (e && e.code === 'MODULE_NOT_FOUND' && String(e.message).includes('./sovereign')) F.reject('sovereign networks are not part of this package');
    throw e;
  }
}

const HIDDEN = 'SecretKey [hidden]';

class SecretKey extends Uint8Array {
  static get [Symbol.species]() {
    return Uint8Array;
  }

  toJSON() {
    return HIDDEN;
  }

  toString() {
    return HIDDEN;
  }

  toLocaleString() {
    return HIDDEN;
  }

  [require('util').inspect.custom]() {
    return HIDDEN;
  }
}

function generateKey() {
  const seed = new SecretKey(32);
  globalThis.crypto.getRandomValues(seed);
  if (seed.every((b) => b === 0)) throw new Error('the secure random source returned only zeros');
  return seed;
}

function publicKey(key) {
  return native.publicKey(requireSeed(key));
}

function keyId(key) {
  return F.keyIdOf(publicKey(key));
}

function describeKey(key) {
  const pk = publicKey(key);
  return { format: F.KEY_FORMAT, algorithm: F.ALGORITHM, id: F.keyIdOf(pk), publicKey: Buffer.from(pk).toString('base64') };
}

function randomHex(n) {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return Buffer.from(b).toString('hex');
}

function keyIdFrom(value, what) {
  if (typeof value === 'string') {
    if (!/^[0-9a-f]{64}$/.test(value)) F.reject(what + ' is a key id of 64 lowercase hex characters');
    return value;
  }
  if ((ArrayBuffer.isView(value) && value instanceof Uint8Array)) return F.keyIdOf(value);
  if (value && typeof value === 'object' && value.format === F.KEY_FORMAT && typeof value.publicKey === 'string') {
    const raw = Buffer.from(value.publicKey, 'base64');
    if (raw.toString('base64') !== value.publicKey) F.reject(what + ' holds a public key that is not canonical base64');
    const id = F.keyIdOf(raw);
    if (value.id !== undefined && value.id !== id) F.reject(what + ' names an id that does not match its public key');
    return id;
  }
  F.reject(what + ' is a key id, a public key or a ' + F.KEY_FORMAT + ' description');
}

function signatureOk(p) {
  return p.signerId === F.keyIdOf(p.publicKey) && p.signerId === F.boundKey(p) && native.verify(p.publicKey, F.payload(p.type, p.statement), p.signature);
}

function signedEnvelope(envelope, type, what) {
  let p;
  try {
    p = F.parse(envelope);
  } catch (e) {
    F.reject(what + ' is not a valid envelope, ' + e.message);
  }
  if (p.type !== type) F.reject(what + ' must be ' + F.article(type) + ' envelope');
  if (!signatureOk(p)) F.reject(what + ' is not validly signed by the key it names');
  return p;
}

function sign(type, statement, key) {
  const pk = publicKey(key);
  const problem = F.statementProblem(type, statement);
  if (problem) F.reject(problem);
  const message = F.payload(type, statement);
  const rnd = new Uint8Array(32);
  globalThis.crypto.getRandomValues(rnd);
  let signature;
  try {
    signature = native.sign(key, message, rnd);
  } finally {
    rnd.fill(0);
  }
  if (!native.verify(pk, message, signature)) throw new Error('the new signature did not verify, nothing was produced');
  return {
    format: F.FORMAT,
    type,
    algorithm: F.ALGORITHM,
    signer: { id: F.keyIdOf(pk), publicKey: Buffer.from(pk).toString('base64') },
    statement,
    signature: Buffer.from(signature).toString('base64'),
  };
}

function scopeOf(value) {
  if (typeof value === 'string' && F.FIXED_SCOPES.includes(value)) return F.fixedScope(value);
  return value;
}

function commitParty(identity, options) {
  F.partyIdentity(identity);
  const o = options === undefined ? {} : options;
  if (o === null || typeof o !== 'object') F.reject('the options of commitParty are an object with salt, or secret and scope');
  if (o.salt !== undefined && o.secret !== undefined) F.reject('give salt, or secret and scope, not both');
  if (o.scope !== undefined && o.secret === undefined) F.reject('scope goes with secret');
  let salt;
  if (o.salt !== undefined) {
    if (!((ArrayBuffer.isView(o.salt) && o.salt instanceof Uint8Array)) || o.salt.length !== 32) F.reject('salt is a 32 byte Uint8Array');
    if (new Set(o.salt).size < 13) F.reject('a salt made of too few different byte values is refused, draw it from a secure random source');
    salt = Uint8Array.from(o.salt);
  } else if (o.secret !== undefined) {
    salt = F.partySalt(o.secret, scopeOf(o.scope), identity);
  } else {
    salt = new Uint8Array(32);
    globalThis.crypto.getRandomValues(salt);
  }
  return { salt, ref: F.partyRef(salt, identity) };
}

const claimed = (p) => Date.parse(p.statement[F.CLAIMED[p.type]]);

function fieldValue(f, options, links, type) {
  const t = F.SPEC.types[type];
  for (const [lname, l] of Object.entries(t.links || {})) {
    for (const [mine, theirs] of l.copy || []) {
      if (mine === f.name && options[f.name] === undefined && links[lname]) return links[lname].statement[theirs];
    }
  }
  if (f.kind === 'digest' && f.doc && options[f.doc] !== undefined) {
    if (options[f.name] !== undefined) F.reject('give ' + f.doc + ' or ' + f.name + ', not both');
    if (!((ArrayBuffer.isView(options[f.doc]) && options[f.doc] instanceof Uint8Array))) F.reject(f.doc + ' is a Uint8Array');
    return F.sha3(options[f.doc]).toString('hex');
  }
  if (f.kind === 'size' && f.doc && options[f.doc] !== undefined) {
    if (options[f.name] !== undefined) F.reject('give ' + f.doc + ' or ' + f.name + ', not both');
    return options[f.doc].length;
  }
  const v = options[f.name];
  if (v === undefined) {
    if (f.kind === 'text' && !f.required) return '';
    if (f.kind === 'optref') return '';
    F.reject(f.name + ' is required');
  }
  if (f.kind === 'key') return keyIdFrom(v, f.name);
  return v;
}

function create(type, options) {
  if (!F.TYPES.includes(type)) F.reject('type must be one of ' + F.TYPES.join(', '));
  if (!options || typeof options !== 'object' || Array.isArray(options) || ArrayBuffer.isView(options) || options instanceof ArrayBuffer) F.reject(type + ' needs options');
  const t = F.SPEC.types[type];
  const given = Object.keys(options);
  const read = new Set(['ledger']);
  const source = Object.assign(Object.create(null), options);
  options = new Proxy(source, {
    get(target, prop, receiver) {
      if (typeof prop === 'string') read.add(prop);
      return Reflect.get(target, prop, receiver);
    },
  });
  requireSeed(options.key);
  const signer = keyId(options.key);
  const st = {};
  st[t.id] = randomHex(16);
  st[t.signer] = signer;
  const links = {};
  for (const [lname, l] of Object.entries(t.links || {})) {
    if (options[lname] === undefined) {
      if (l.optional) {
        st[l.field] = '';
        continue;
      }
      F.reject(lname + ' is required, give the ' + lname + ' envelope this ' + type + ' relies on');
    }
    const e = signedEnvelope(options[lname], l.type, 'the ' + lname);
    if (e.signerId === signer && !l.sameRole) F.reject('the key that signed the ' + lname + ' must not sign this ' + type);
    links[lname] = e;
    st[l.field] = F.refOf(e);
  }
  if (t.secretParty) {
    const sp = t.secretParty;
    if (options[sp.identity] === undefined || options.partySecret === undefined) F.reject('give ' + sp.identity + ' and partySecret, the ' + sp.field + ' is derived from the secret of the authority so the same party always receives the same commitment');
    const salt = F.partySalt(options.partySecret, sp.fixedScope ? F.fixedScope(sp.fixedScope) : st[t.links[sp.scope].field], options[sp.identity]);
    let ref;
    try {
      ref = F.partyRef(salt, options[sp.identity]);
    } finally {
      salt.fill(0);
    }
    if (options[sp.field] !== undefined && options[sp.field] !== ref) F.reject('the ' + sp.field + ' given differs from the one derived from the secret of the authority');
    if (options[sp.scheme] !== undefined && options[sp.scheme] !== F.PARTY_SCHEME) F.reject(sp.scheme + ' is ' + F.PARTY_SCHEME);
    st[sp.field] = ref;
    st[sp.scheme] = F.PARTY_SCHEME;
  }
  if (t.derive) {
    const derived = t.derive(options, links, { F, claimed, signatureOk });
    for (const [k, v] of Object.entries(derived)) {
      if (!Object.prototype.hasOwnProperty.call(t.fields || {}, k)) throw new Error('the specification derives an unknown field ' + k);
      if (options[k] !== undefined && options[k] !== v) F.reject('give ' + k + ' or let it be derived, not a different value');
      st[k] = v;
    }
  }
  for (const [fname, def] of Object.entries(t.fields || {})) {
    if (st[fname] !== undefined) continue;
    st[fname] = fieldValue({ name: fname, kind: def[0], max: def[1], required: def[2], doc: def[3] }, options, links, type);
  }
  const at = options[t.time] === undefined ? new Date().toISOString() : options[t.time];
  const tp = F.timeProblem(at, t.time);
  if (tp) F.reject(tp);
  st[t.time] = at;
  st.note = options.note === undefined ? '' : options.note;
  for (const [lname, l] of Object.entries(t.links || {})) {
    const e = links[lname];
    if (!e) continue;
    for (const [mine, theirs] of (l.copy || []).concat(l.match || [])) {
      if (st[mine] !== e.statement[theirs]) F.reject('the ' + mine + ' of this ' + type + ' must equal the ' + theirs + ' of the ' + lname);
    }
    for (const [mine, theirs] of l.max || []) {
      if (typeof st[mine] === 'string' && /^\d+$/.test(st[mine]) && BigInt(st[mine]) > BigInt(e.statement[theirs])) F.reject('the ' + mine + ' of this ' + type + ' cannot exceed the ' + theirs + ' of the ' + lname);
    }
    if (!l.after && Date.parse(at) < claimed(e)) F.reject('this ' + type + ' cannot be dated before the ' + lname);
  }
  if (t.chain) {
    const c = t.chain;
    if ((options.previous === undefined) === (options.first !== true)) F.reject('give the previous ' + type + ' of the series, or first set to true when there is none');
    let seq = 1;
    let prevRef = '';
    let total = c.total ? BigInt(st[c.amount]) : null;
    if (options.previous !== undefined) {
      const prev = signedEnvelope(options.previous, type, 'the previous ' + type);
      if (prev.statement[c.scope] !== st[c.scope]) F.reject('the previous ' + type + ' belongs to another series');
      if (st.currency !== undefined && prev.statement.currency !== st.currency) F.reject('the previous ' + type + ' is in another currency');
      if (Date.parse(at) < claimed(prev)) F.reject('this ' + type + ' cannot be dated before the previous ' + type);
      if (prev.statement.seq >= F.SEQ_MAX) F.reject('this series has reached the largest number of records');
      if (t.signCheckPrevious) {
        const pp = t.signCheckPrevious(st, prev);
        if (pp) F.reject(pp);
      }
      const mine = uniqueKey(t, st);
      if (mine !== null && uniqueKey(t, prev.statement) === mine) F.reject('the previous ' + type + ' already used the same ' + uniqueName(t));
      seq = prev.statement.seq + 1;
      prevRef = F.refOf(prev);
      if (c.total) total += BigInt(prev.statement[c.total]);
    }
    if (c.total && c.cap) {
      const capLink = links[c.cap[0]];
      if (!capLink) F.reject('the ' + c.cap[0] + ' is required to check the running total');
      if (total > BigInt(capLink.statement[c.cap[1]])) F.reject('this ' + type + ' would take the running total above the ' + c.cap[1] + ' of the ' + c.cap[0]);
    }
    st.seq = seq;
    st[c.prev] = prevRef;
    if (c.total) st[c.total] = total.toString();
  }
  if (t.signCheck) {
    const p = t.signCheck(st, links, { claimed, F });
    if (p) F.reject(p);
  }
  const unused = given.find((k) => !read.has(k));
  if (unused !== undefined) F.reject('the option ' + unused.replace(/[^A-Za-z0-9_]/g, '?').slice(0, 40) + ' is not used by ' + type + ', so nothing was signed rather than ignore it');
  if (options.ledger === false || (options.ledger === undefined && !t.chain && !t.once)) return sign(type, st, options.key);
  if (!t.chain && !t.once) F.reject(F.article(type) + ' is not part of a series, so it takes no ledger');
  if (options.ledger === undefined) F.reject(F.article(type) + ' is part of a series, so give ledger, the series ledger shared by every signer, or ledger false when the integrating system keeps the series itself');
  return inLedger(type, t, st, ledgerOf(options.ledger), Uint8Array.from(options.key));
}

function ledgerError(message) {
  const e = new Error(String(message).replace(/[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]/gu, '?'));
  e.code = F.NAME.toUpperCase() + '_LEDGER';
  return e;
}

const SERIES_FORMAT = F.NAME + '-series/1';
const SERIES_NAME = /^([a-z][a-z0-9]*)\.([a-z][a-zA-Z0-9]*)\.([0-9a-f]{64})$/;
const SERIES_FILE_MAX = 9999999;
const SERIES_MAX = 65536;
const FS = fs.constants;
const CREATE_FLAGS = FS.O_WRONLY | FS.O_CREAT | FS.O_EXCL | (FS.O_NOFOLLOW || 0);
const READ_FLAGS = FS.O_RDONLY | (FS.O_NOFOLLOW || 0) | (FS.O_NONBLOCK || 0);

function seriesName(type, value) {
  return F.NAME + '.' + type + '.' + value;
}

function uniqueKey(t, st) {
  const u = t.chain && t.chain.unique;
  if (!u) return null;
  if (typeof u === 'function') return u(st, F);
  return st[u];
}

function uniqueName(t) {
  return typeof t.chain.unique === 'function' ? t.chain.uniqueName || 'value' : t.chain.unique;
}

function usedValue(type, st) {
  const t = F.SPEC.types[type];
  const k = uniqueKey(t, st);
  if (k === null || k === undefined) return null;
  return F.sha3(Buffer.from('quantova/' + F.NAME + '/used/1', 'ascii'), Buffer.from([0]), Buffer.from(st[t.chain.scope], 'hex'), Buffer.from([0]), Buffer.from(String(k), 'utf8')).toString('hex');
}

function seriesOf(name) {
  const m = typeof name === 'string' ? SERIES_NAME.exec(name) : null;
  if (!m || m[1] !== F.NAME) return null;
  const base = m[2].endsWith('Used') ? m[2].slice(0, -4) : null;
  if (base !== null && F.TYPES.includes(base) && F.SPEC.types[base].chain && F.SPEC.types[base].chain.unique) return { type: base, value: m[3], used: true };
  if (!F.TYPES.includes(m[2])) return null;
  const t = F.SPEC.types[m[2]];
  if (t.chain) return { type: m[2], scope: t.chain.scope, value: m[3], chain: true };
  if (t.once) return { type: m[2], scope: t.once, value: m[3], chain: false };
  return null;
}

function seriesText(name, seq, envelope) {
  return JSON.stringify({ format: SERIES_FORMAT, series: name, seq, ref: F.refOf(F.parse(envelope)), envelope }) + '\n';
}

function headOf(text, name) {
  if (text === null || text === undefined) return null;
  const damaged = () => ledgerError('the ledger entry of the series ' + name.slice(0, 120) + ' is damaged, nothing was signed');
  if (typeof text !== 'string' || text.length > SERIES_MAX) throw damaged();
  let h;
  try {
    h = JSON.parse(text);
  } catch (e) {
    throw damaged();
  }
  if (!h || h.format !== SERIES_FORMAT || h.series !== name || !Number.isSafeInteger(h.seq) || h.seq < 1 || typeof h.ref !== 'string' || !/^[0-9a-f]{64}$/.test(h.ref)) throw damaged();
  let p;
  try {
    p = F.parse(h.envelope);
  } catch (e) {
    throw damaged();
  }
  if (F.refOf(p) !== h.ref || !signatureOk(p) || seriesText(name, h.seq, h.envelope) !== text) throw damaged();
  const s = seriesOf(name);
  if (!s || p.type !== s.type) throw damaged();
  if (s.used ? usedValue(p.type, p.statement) !== s.value || h.seq !== 1 : p.statement[s.scope] !== s.value || h.seq !== (s.chain ? p.statement.seq : 1)) throw damaged();
  return { seq: h.seq, ref: h.ref, envelope: h.envelope };
}

function readEntry(file, seq) {
  const bad = () => ledgerError('the ledger entry ' + path.basename(file) + ' is not a small regular file');
  let fd;
  try {
    fd = fs.openSync(file, READ_FLAGS);
  } catch (e) {
    if (e.code === 'ELOOP') throw bad();
    throw ledgerError('the ledger entry ' + path.basename(file) + ' could not be opened (' + e.code + ')');
  }
  let text;
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.size > SERIES_MAX) throw bad();
    const buf = Buffer.alloc(st.size);
    let off = 0;
    while (off < buf.length) {
      const n = fs.readSync(fd, buf, off, buf.length - off, off);
      if (n === 0) break;
      off += n;
    }
    text = buf.subarray(0, off).toString('utf8');
  } finally {
    fs.closeSync(fd);
  }
  let h = null;
  try {
    h = JSON.parse(text);
  } catch (e) {
    h = null;
  }
  if (!h || h.seq !== seq) throw ledgerError('the ledger entry ' + path.basename(file) + ' does not hold position ' + seq + ' of its series, nothing was signed');
  return text;
}

function syncDir(dir) {
  try {
    const fd = fs.openSync(dir, 'r');
    try {
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
  } catch (e) {
    if (e.code !== 'EISDIR' && e.code !== 'EPERM' && e.code !== 'EINVAL') throw e;
  }
}

const WRITE_RIGHTS = /\b(add_file|add_subdirectory|delete_child|delete|write|append|writeattr|writeextattr|writesecurity|chown)\b/;

function listing(file, args, dir) {
  try {
    return execFileSync(file, args, { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (e) {
    throw ledgerError('the permissions of the folder ' + (typeof dir === 'string' ? dir.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g, '?').slice(0, 200) : 'of type ' + typeof dir) + ' could not be read');
  }
}

function aclLetsOthersWrite(dir) {
  if (process.platform === 'win32') return false;
  if (process.platform === 'darwin') {
    return listing('/bin/ls', ['-lde', dir], dir).split('\n').some((l) => /^\s*\d+: /.test(l) && / allow /.test(l) && WRITE_RIGHTS.test(l));
  }
  for (const tool of ['/usr/bin/getfacl', '/bin/getfacl']) {
    if (fs.existsSync(tool)) {
      return listing(tool, ['-cp', dir], dir).split('\n').some((l) => /^(default:)?(user|group):[^:]+:[r-]w/.test(l.trim()));
    }
  }
  let version = '';
  try {
    version = execFileSync('/bin/ls', ['--version'], { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] });
  } catch (e) {
    version = '';
  }
  if (!/GNU coreutils/.test(version)) throw ledgerError('access control lists cannot be read on this system, install getfacl so the ledger folder can be checked');
  return /^.{10}\+/.test(listing('/bin/ls', ['-ld', dir], dir));
}

function exposedPlace(dir, ownerUid, depth, includeLast, sharedGid) {
  const self = typeof process.getuid === 'function' ? process.getuid() : null;
  const safe = (p, st) => (self === null || st.uid === 0 || st.uid === self || st.uid === ownerUid) && !((st.mode & 0o002) && !(st.mode & 0o1000)) && !((st.mode & 0o020) && !(st.mode & 0o1000) && !(st.uid === 0 && st.gid === 0) && st.gid !== sharedGid) && !aclLetsOthersWrite(p);
  if (depth > 32) throw ledgerError('the ledger folder is reached through too many symbolic links');
  const full = path.resolve(dir);
  const parts = full.split(path.sep).filter(Boolean);
  let cur = path.parse(full).root;
  if (!safe(cur, fs.statSync(cur))) return cur;
  for (let i = 0; i < parts.length; i += 1) {
    const next = path.join(cur, parts[i]);
    const last = i === parts.length - 1;
    const st = fs.lstatSync(next);
    if (st.isSymbolicLink()) {
      const target = path.resolve(path.dirname(next), fs.readlinkSync(next));
      const bad = exposedPlace(target, ownerUid, depth + 1, !last || includeLast, sharedGid);
      if (bad) return bad;
      cur = fs.realpathSync(target);
      continue;
    }
    if ((!last || includeLast) && !safe(next, st)) return next;
    cur = next;
  }
  return null;
}

function folderLedger(dir) {
  if (process.platform === 'win32') throw ledgerError('the folder ledger checks the owner, mode and access list of every folder, which Windows does not expose, so on Windows give a ledger store of your own with read and compareAndSwap');
  if (typeof dir !== 'string' || dir.length === 0) F.reject('a ledger folder is a path');
  let placed = null;
  const base = () => {
    let st;
    try {
      st = fs.statSync(dir);
    } catch (e) {
      throw ledgerError('the ledger folder ' + dir.slice(0, 200) + ' could not be opened');
    }
    if (!st.isDirectory()) throw ledgerError('the ledger folder ' + dir.slice(0, 200) + ' is not a folder');
    if (placed && (placed.dev !== st.dev || placed.ino !== st.ino)) throw ledgerError('the ledger folder ' + dir.slice(0, 200) + ' was moved or replaced after it was first checked, nothing was signed');
    if (st.mode & 0o002) throw ledgerError('the ledger folder ' + dir.slice(0, 200) + ' can be written by every user of this machine, restrict it to the signers of the series');
    if (placed === null) {
      if (aclLetsOthersWrite(fs.realpathSync(dir))) throw ledgerError('the ledger folder ' + dir.slice(0, 200) + ' carries an access control list that lets others write, remove it so that only its mode decides who may write');
      const above = exposedPlace(dir, st.uid, 0, false, st.mode & 0o020 ? st.gid : null);
      if (above) throw ledgerError('the folder ' + above.slice(0, 200) + ' above the ledger can be changed by another user, so the ledger could be replaced, move the ledger under folders only its signers control');
      placed = { dev: st.dev, ino: st.ino };
    }
    return dir;
  };
  const check = (name) => {
    if (typeof name !== 'string' || !SERIES_NAME.test(name)) F.reject('a ledger entry is named by the package, the record type and the reference that defines the series');
  };
  const held = (root, name, seq) => {
    try {
      fs.lstatSync(path.join(root, name + '.' + seq + '.json'));
      return true;
    } catch (e) {
      if (e.code === 'ENOENT') return false;
      throw ledgerError('the ledger entry ' + name.slice(0, 120) + '.' + seq + '.json could not be read (' + e.code + ')');
    }
  };
  const head = (root, name) => {
    if (!held(root, name, 1)) return 0;
    let low = 1;
    let high = 2;
    while (high <= SERIES_FILE_MAX && held(root, name, high)) {
      low = high;
      high *= 2;
    }
    high = Math.min(high, SERIES_FILE_MAX + 1);
    while (high - low > 1) {
      const mid = Math.floor((low + high) / 2);
      if (held(root, name, mid)) low = mid;
      else high = mid;
    }
    return low;
  };
  const highest = (root, name) => {
    let files;
    try {
      files = fs.readdirSync(root);
    } catch (e) {
      throw ledgerError('the ledger folder could not be listed (' + e.code + ')');
    }
    const prefix = name + '.';
    let best = 0;
    for (const f of files) {
      if (!f.startsWith(prefix) || !f.endsWith('.json')) continue;
      const n = f.slice(prefix.length, -5);
      if (/^[1-9][0-9]{0,6}$/.test(n) && Number(n) <= F.SEQ_MAX && Number(n) > best) best = Number(n);
    }
    return best;
  };
  return {
    async read(name) {
      check(name);
      const root = base();
      const seq = head(root, name);
      if (seq === 0) return null;
      return readEntry(path.join(root, name + '.' + seq + '.json'), seq);
    },
    async compareAndSwap(name, expected, next) {
      check(name);
      const root = base();
      const want = headOf(next, name);
      if (want === null) F.reject('the next state of a series names its latest record');
      const have = headOf(expected, name);
      if (want.seq !== (have ? have.seq + 1 : 1)) return false;
      if ((await this.read(name)) !== expected) return false;
      const top = highest(root, name);
      if (top !== want.seq - 1) {
        if (top > want.seq - 1 && head(root, name) === top) return false;
        throw ledgerError('the ledger of the series ' + name.slice(0, 120) + ' is missing a record below its latest one, the file ' + name.slice(0, 120) + '.' + top + '.json lies above the last record that follows on without a gap, so it is damaged and nothing was signed, restore the whole folder from its backup or remove that file if it does not belong to the series');
      }
      const file = path.join(root, name + '.' + want.seq + '.json');
      const tmp = path.join(root, '.' + name + '.' + want.seq + '.' + crypto.randomBytes(16).toString('hex') + '.tmp');
      try {
        const fd = fs.openSync(tmp, CREATE_FLAGS, 0o600);
        try {
          fs.writeSync(fd, next);
          fs.fsyncSync(fd);
        } finally {
          fs.closeSync(fd);
        }
        try {
          fs.linkSync(tmp, file);
        } catch (e) {
          if (e.code === 'EEXIST') return false;
          throw ledgerError('the ledger entry could not be written (' + e.code + ')');
        }
        syncDir(root);
        return true;
      } finally {
        fs.rmSync(tmp, { force: true });
      }
    },
  };
}

function ledgerOf(value) {
  if (typeof value === 'string') return folderLedger(value);
  if (value && typeof value === 'object' && typeof value.read === 'function' && typeof value.compareAndSwap === 'function') return value;
  F.reject('ledger is the folder of the series ledger, or an object with read and compareAndSwap that stores each value atomically');
}

async function inLedger(type, t, st, store, key) {
  try {
    const name = seriesName(type, t.chain ? st[t.chain.scope] : st[t.once]);
    const text = await store.read(name);
    const head = headOf(text, name);
    if (t.chain) {
      if (st.seq === 1 && head !== null) throw ledgerError('the ledger already holds ' + type + ' ' + head.seq + ' of this series, so this ' + type + ' cannot be the first, give the latest ' + type + ' as previous');
      if (st.seq > 1 && (head === null || head.ref !== st[t.chain.prev] || head.seq !== st.seq - 1)) {
        throw ledgerError('the previous ' + type + ' given is not the latest ' + type + ' of the series in the ledger, which holds ' + (head ? type + ' ' + head.seq : 'no ' + type) + ', nothing was signed');
      }
    } else if (head !== null) {
      throw ledgerError('the ledger already holds ' + F.article(type) + ' for this ' + t.once + ', nothing was signed');
    }
    const used = t.chain ? usedValue(type, st) : null;
    if (head !== null) await markUsed(store, type, head.envelope);
    if (used !== null) {
      const usedName = seriesName(type + 'Used', used);
      if (headOf(await store.read(usedName), usedName) !== null) throw ledgerError('an earlier ' + type + ' of this series in the ledger already used the same ' + uniqueName(t) + ', nothing was signed');
    }
    const env = sign(type, st, key);
    const swapped = await store.compareAndSwap(name, text, seriesText(name, t.chain ? st.seq : 1, env));
    if (typeof swapped !== 'boolean') throw ledgerError('the ledger store answered compareAndSwap with ' + (swapped === null ? 'null' : typeof swapped) + ' where true or false was expected, nothing was issued, read the latest record of the series before trying again');
    if (swapped !== true) {
      throw ledgerError('another ' + type + ' was recorded for this series while this one was signed, nothing was issued, read the latest record and try again');
    }
    await markUsed(store, type, env);
    return env;
  } finally {
    key.fill(0);
  }
}

async function markUsed(store, type, envelope) {
  const p = F.parse(envelope);
  const used = usedValue(type, p.statement);
  if (used === null) return;
  const usedName = seriesName(type + 'Used', used);
  const text = await store.read(usedName);
  const held = headOf(text, usedName);
  if (held !== null) {
    if (held.ref !== F.refOf(p)) throw ledgerError('the ledger marks the ' + uniqueName(F.SPEC.types[type]) + ' of the latest ' + type + ' as used by another record, nothing was signed');
    return;
  }
  const written = await store.compareAndSwap(usedName, text, seriesText(usedName, 1, envelope));
  if (written !== true && headOf(await store.read(usedName), usedName) === null) throw ledgerError('the ledger could not record that the ' + uniqueName(F.SPEC.types[type]) + ' of the latest ' + type + ' is used, nothing further was signed');
}

async function ledgerLatest(ledger, type, ref) {
  if (!F.TYPES.includes(type)) F.reject('type must be one of ' + F.TYPES.join(', '));
  const t = F.SPEC.types[type];
  if (!t.chain && !t.once) F.reject(F.article(type) + ' is not part of a series, so it takes no ledger');
  if (typeof ref !== 'string' || !/^[0-9a-f]{64}$/.test(ref)) F.reject('the series is named by the reference of the record that defines it, 64 lowercase hex characters');
  const name = seriesName(type, ref);
  const head = headOf(await ledgerOf(ledger).read(name), name);
  return head === null ? null : head.envelope;
}

function batch(envelopes) {
  const list = Array.isArray(envelopes) ? envelopes : [envelopes];
  if (list.length === 0) F.reject('at least one envelope is needed');
  const copies = list.map((e) => {
    try {
      return F.plainCopy(e);
    } catch (err) {
      return F.reject('an envelope is not plain data');
    }
  });
  const parsed = copies.map((e) => {
    const p = F.parse(e);
    if (!signatureOk(p)) F.reject('an envelope is not validly signed by the key it names');
    return p;
  });
  return { copies, parsed };
}

function attach(copies, receipts) {
  if (!Array.isArray(receipts) || receipts.length !== copies.length) throw new Error('the anchoring returned an unexpected number of receipts');
  return copies.map((e, i) => Object.assign({}, e, { anchor: receipts[i] }));
}

async function anchor(envelopes, options) {
  const { copies, parsed } = batch(envelopes);
  if (parsed.some((p) => p.anchor !== undefined)) F.reject('an envelope is already anchored');
  if (!options || typeof options !== 'object') F.reject('anchor needs the stamping options of a funded Quantova account');
  const records = parsed.map((p) => ({ alg: 'sha3-256', digest: F.anchorDigest(p) }));
  if (options.sovereign !== undefined) return attach(copies, await sovereign().stamp(Object.assign({}, options, { records, kind: F.KIND })));
  return attach(copies, await qstamp.stamp(Object.assign({}, options, { records, kind: F.KIND })));
}

async function complete(envelopes, pending, options) {
  const plain = (Array.isArray(envelopes) ? envelopes : [envelopes]).map((e) => {
    let c;
    try {
      c = F.plainCopy(e);
    } catch (err) {
      return F.reject('an envelope is not plain data');
    }
    if (c && typeof c === 'object' && !Array.isArray(c)) delete c.anchor;
    return c;
  });
  const { copies, parsed } = batch(plain);
  let p;
  try {
    p = F.plainCopy(pending);
  } catch (e) {
    F.reject('the pending stamp is not plain data');
  }
  if (!p || typeof p !== 'object' || !Array.isArray(p.records) || p.records.length !== parsed.length || String(p.kind) !== String(F.KIND)) {
    F.reject('the pending stamp does not belong to these envelopes');
  }
  parsed.forEach((c, i) => {
    const r = p.records[i];
    if (!r || r.alg !== 'sha3-256' || r.digest !== F.anchorDigest(c).toString('hex')) F.reject('the pending stamp does not belong to these envelopes, or they are in another order');
  });
  if (options && options.sovereign !== undefined) return attach(copies, await sovereign().complete(p, options));
  return attach(copies, await qstamp.complete(p, options || {}));
}

module.exports = {
  generateKey, publicKey, keyId, describeKey, keyIdFrom, commitParty, create, anchor, complete, signedEnvelope, signatureOk, sovereign, folderLedger, ledgerOf, ledgerLatest,
};
