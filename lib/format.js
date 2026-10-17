// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const nodeCrypto = require('crypto');
const SPEC = require('./spec');

const NAME = SPEC.name;
const VERSION = SPEC.version || 1;
const FORMAT = NAME + '/' + VERSION;
const KEY_FORMAT = NAME + '-key/1';
const SALT_FORMAT = NAME + '-salt/1';
const ALGORITHM = 'ML-DSA-65';
const KIND = SPEC.kind;
const TYPES = Object.freeze(Object.keys(SPEC.types));
const domain = (part) => Buffer.from('quantova/' + NAME + '/' + part + '/1', 'ascii');
const KEY_DOMAIN = domain('key');
const REF_DOMAIN = domain('ref');
const ANCHOR_DOMAIN = domain('anchor');
const PARTY_DOMAIN = domain('party');
const PARTY_SALT_DOMAIN = domain('party-salt');
const MAGIC = Buffer.from(SPEC.magic, 'ascii');
const PUBLIC_KEY_BYTES = 1952;
const SIGNATURE_BYTES = 3309;
const NOTE_MAX = 1000;
const SEQ_MAX = 1000000;
const PARTY_MAX = 256;
const HEX32 = /^[0-9a-f]{64}$/;
const HEX16 = /^[0-9a-f]{32}$/;
const CURRENCY = /^[A-Z]{3}$/;
const AMOUNT = /^(0|[1-9][0-9]{0,29})$/;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const UNSAFE_TEXT = /[\p{Cc}\p{Cf}\p{Co}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000\u2800\u115f\u1160\u3164\uffa0]/u;
const HEX_KINDS = new Set(['id', 'key', 'ref', 'optref', 'digest', 'party']);
const ASCII_KINDS = new Set(['currency', 'amount', 'posamount', 'time']);

function fail(message) {
  const e = new Error('the envelope is not valid, ' + message);
  e.code = NAME.toUpperCase() + '_INVALID_ENVELOPE';
  throw e;
}

function reject(message) {
  const e = new Error(message);
  e.code = NAME.toUpperCase() + '_INVALID_INPUT';
  throw e;
}

function layoutOf(type) {
  const t = SPEC.types[type];
  const out = [{ name: t.id, kind: 'id' }, { name: t.signer, kind: 'key' }];
  for (const l of Object.values(t.links || {})) out.push({ name: l.field, kind: l.optional ? 'optref' : 'ref' });
  for (const [name, def] of Object.entries(t.fields || {})) out.push({ name, kind: def[0], max: def[1], required: def[2], doc: def[3] });
  if (t.chain) {
    out.push({ name: 'seq', kind: 'seq' }, { name: t.chain.prev, kind: 'optref' });
    if (t.chain.total) out.push({ name: t.chain.total, kind: 'amount' });
  }
  out.push({ name: t.time, kind: 'time' }, { name: 'note', kind: 'note' });
  const reserved = ['key', 'previous', 'first', 'note', 'type', 'requireAnchor', 'at', 'maxAnchorDelay', 'records', 'allSupplied', 'party', 'rpc', 'client', 'clients', 'contract', 'trustCustomContract'].concat(Object.keys(SPEC.roles).map((r) => r + 'Keys'));
  for (const lname of Object.keys(t.links || {})) if (reserved.includes(lname)) throw new Error('the specification uses the reserved name ' + lname);
  for (const l of Object.values(t.links || {})) if (l.sameRole && SPEC.types[l.type].role !== t.role) throw new Error('the specification allows one signer only across the same role');
  const names = new Set(Object.keys(t.links || {}).concat(reserved, [t.time]));
  for (const f of out) {
    if (f.doc && (names.has(f.doc) || out.some((g) => g.name === f.doc))) throw new Error('the specification uses ' + f.doc + ' for two different options');
  }
  const seen = new Set();
  for (const f of out) {
    if (seen.has(f.name)) throw new Error('the specification repeats the field ' + f.name);
    seen.add(f.name);
  }
  return Object.freeze(out.map((f) => Object.freeze(f)));
}

const LAYOUT = Object.freeze(Object.fromEntries(TYPES.map((t) => [t, layoutOf(t)])));
const FIELDS = Object.freeze(Object.fromEntries(TYPES.map((t) => [t, Object.freeze(LAYOUT[t].map((f) => f.name))])));
const SIGNER = Object.freeze(Object.fromEntries(TYPES.map((t) => [t, SPEC.types[t].signer])));
const CLAIMED = Object.freeze(Object.fromEntries(TYPES.map((t) => [t, SPEC.types[t].time])));

function sha3(...parts) {
  const h = nodeCrypto.createHash('sha3-256');
  for (const p of parts) h.update(p);
  return h.digest();
}

function keyIdOf(publicKey) {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== PUBLIC_KEY_BYTES) reject('a public key is ' + PUBLIC_KEY_BYTES + ' bytes');
  return sha3(KEY_DOMAIN, Buffer.from([0]), publicKey).toString('hex');
}

function textProblem(value, max, what, required) {
  if (typeof value !== 'string') return what + ' must be text';
  if (required && value.length === 0) return what + ' must not be empty';
  if (value.length > max) return what + ' is longer than ' + max + ' characters';
  if (!value.isWellFormed()) return what + ' holds a broken Unicode surrogate';
  if (value.normalize('NFC') !== value) return what + ' must be in Unicode normal form C';
  if (UNSAFE_TEXT.test(value)) return what + ' holds control, invisible or direction characters';
  return null;
}

function timeProblem(value, what) {
  if (typeof value !== 'string' || !ISO_UTC.test(value)) return what + ' must be an ISO 8601 UTC time with milliseconds and a Z suffix';
  const ms = Date.parse(value);
  if (!Number.isFinite(ms) || new Date(ms).toISOString() !== value) return what + ' is not a real calendar time';
  return null;
}

function fieldProblem(f, v) {
  const what = f.name;
  switch (f.kind) {
    case 'id': return typeof v === 'string' && HEX16.test(v) ? null : what + ' must be 32 lowercase hex characters';
    case 'key': case 'ref': case 'digest': case 'party': return typeof v === 'string' && HEX32.test(v) ? null : what + ' must be 64 lowercase hex characters';
    case 'optref': return v === '' || (typeof v === 'string' && HEX32.test(v)) ? null : what + ' must be empty or 64 lowercase hex characters';
    case 'text': return textProblem(v, f.max, what, f.required);
    case 'note': return textProblem(v, NOTE_MAX, what, false);
    case 'currency': return typeof v === 'string' && CURRENCY.test(v) ? null : what + ' must be three capital letters';
    case 'amount': return typeof v === 'string' && AMOUNT.test(v) ? null : what + ' must be a whole number of minor units without leading zeros';
    case 'posamount': return typeof v === 'string' && AMOUNT.test(v) && v !== '0' ? null : what + ' must be a whole number of minor units greater than zero';
    case 'time': return timeProblem(v, what);
    case 'seq': return typeof v === 'number' && Number.isSafeInteger(v) && v >= 1 && v <= SEQ_MAX ? null : what + ' must be a whole number from 1 to ' + SEQ_MAX;
    case 'size': return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && !Object.is(v, -0) ? null : what + ' must be a whole number from 0';
    default: throw new Error('unknown field kind ' + f.kind);
  }
}

function sameKeys(obj, fields) {
  return Object.keys(obj).sort().join(',') === fields.slice().sort().join(',');
}

function article(word) {
  return (/^[aeiou]/.test(word) ? 'an ' : 'a ') + word;
}

function statementProblem(type, st) {
  if (st === null || typeof st !== 'object' || Array.isArray(st)) return 'the statement must be an object';
  if (!TYPES.includes(type)) return 'type must be one of ' + TYPES.join(', ');
  if (!sameKeys(st, FIELDS[type])) return article(type) + ' statement holds exactly ' + FIELDS[type].join(', ');
  for (const f of LAYOUT[type]) {
    const p = fieldProblem(f, st[f.name]);
    if (p) return p;
  }
  const t = SPEC.types[type];
  if (t.chain) {
    const prev = st[t.chain.prev];
    if ((st.seq === 1) !== (prev === '')) return 'only the first ' + type + ' of its series names no previous ' + type;
    if (t.chain.total) {
      const total = st[t.chain.total];
      const amount = st[t.chain.amount];
      if (st.seq === 1 && total !== amount) return 'the running total of the first ' + type + ' is its amount';
      if (st.seq > 1 && BigInt(total) <= BigInt(amount)) return 'the running total must include the earlier records of the series';
    }
  }
  if (t.shape) {
    const p = t.shape(st);
    if (p) return p;
  }
  return null;
}

function field(buf) {
  if (buf.length > 0xffff) reject('a signed field is too long');
  const len = Buffer.alloc(2);
  len.writeUInt16BE(buf.length);
  return Buffer.concat([len, buf]);
}

function u64(n) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return field(b);
}

function encode(f, v) {
  if (HEX_KINDS.has(f.kind) || f.kind === 'optref') return field(Buffer.from(v, 'hex'));
  if (ASCII_KINDS.has(f.kind)) return field(Buffer.from(v, 'ascii'));
  if (f.kind === 'seq' || f.kind === 'size') return u64(v);
  return field(Buffer.from(v, 'utf8'));
}

function payload(type, st) {
  const parts = [MAGIC, Buffer.from([VERSION]), field(Buffer.from(type, 'ascii'))];
  for (const f of LAYOUT[type]) parts.push(encode(f, st[f.name]));
  return Buffer.concat(parts);
}

function decodeBase64(value, bytes, what) {
  if (typeof value !== 'string' || value.length !== Math.ceil(bytes / 3) * 4) fail(what + ' must be base64 of ' + bytes + ' bytes');
  const raw = Buffer.from(value, 'base64');
  if (raw.toString('base64') !== value || raw.length !== bytes) fail(what + ' is not canonical base64 of ' + bytes + ' bytes');
  return raw;
}

function exactKeys(obj, required, optional, where) {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) fail(where + ' must be an object');
  const allowed = new Set(required.concat(optional));
  for (const k of Object.keys(obj)) if (!allowed.has(k)) fail(where + ' holds an unexpected field');
  for (const k of required) if (!Object.prototype.hasOwnProperty.call(obj, k)) fail(where + ' is missing ' + k);
}

function plainCopy(value, depth) {
  const d = depth === undefined ? 0 : depth;
  if (d > 6) throw new Error('nested too deeply');
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('not a finite number');
    return value;
  }
  if (typeof value !== 'object') throw new Error('not plain data');
  const proto = Object.getPrototypeOf(value);
  if (Array.isArray(value)) {
    if (proto !== Array.prototype) throw new Error('not a plain array');
    if (value.length > 4096) throw new Error('a list is too long');
    const out = [];
    for (let i = 0; i < value.length; i += 1) {
      const desc = Object.getOwnPropertyDescriptor(value, i);
      if (!desc || !('value' in desc)) throw new Error('not plain data');
      out.push(plainCopy(desc.value, d + 1));
    }
    return out;
  }
  if (proto !== Object.prototype && proto !== null) throw new Error('not a plain object');
  const out = {};
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') throw new Error('not plain data');
    const desc = Object.getOwnPropertyDescriptor(value, key);
    if (!('value' in desc) || !desc.enumerable) throw new Error('not plain data');
    Object.defineProperty(out, key, { value: plainCopy(desc.value, d + 1), enumerable: true, writable: true, configurable: true });
  }
  return out;
}

function partyIdentity(identity) {
  if (typeof identity !== 'string' || !identity.isWellFormed()) reject('the party identity must be well formed text');
  const id = identity.normalize('NFC');
  const p = textProblem(id, PARTY_MAX, 'the party identity', true);
  if (p) reject(p);
  return id;
}

function partyRef(salt, identity) {
  if (!(salt instanceof Uint8Array) || salt.length !== 32) reject('the party salt is 32 bytes');
  return sha3(PARTY_DOMAIN, Buffer.from([0]), salt, Buffer.from(partyIdentity(identity), 'utf8')).toString('hex');
}

function partySalt(secret, scope, identity) {
  if (!(secret instanceof Uint8Array) || secret.length !== 32) reject('the party secret is a 32 byte Uint8Array held by the authority');
  if (typeof scope !== 'string' || !HEX32.test(scope)) reject('the scope is the reference of the record that defines the series, 64 lowercase hex characters');
  const d = sha3(PARTY_SALT_DOMAIN, Buffer.from([0]), secret, Buffer.from(scope, 'hex'), Buffer.from(partyIdentity(identity), 'utf8'));
  const out = Uint8Array.from(d);
  d.fill(0);
  return out;
}

function parse(envelope) {
  let env;
  try {
    env = plainCopy(envelope);
  } catch (e) {
    fail('it is not plain data');
  }
  exactKeys(env, ['format', 'type', 'algorithm', 'signer', 'statement', 'signature'], ['anchor'], 'the envelope');
  if (env.format !== FORMAT) fail('format must be ' + FORMAT);
  if (env.algorithm !== ALGORITHM) fail('algorithm must be ' + ALGORITHM);
  if (!TYPES.includes(env.type)) fail('type must be one of ' + TYPES.join(', '));
  exactKeys(env.signer, ['id', 'publicKey'], [], 'signer');
  if (typeof env.signer.id !== 'string' || !HEX32.test(env.signer.id)) fail('signer.id must be 64 lowercase hex characters');
  const publicKey = decodeBase64(env.signer.publicKey, PUBLIC_KEY_BYTES, 'signer.publicKey');
  const problem = statementProblem(env.type, env.statement);
  if (problem) fail(problem);
  const signature = decodeBase64(env.signature, SIGNATURE_BYTES, 'signature');
  const anchor = Object.prototype.hasOwnProperty.call(env, 'anchor') ? env.anchor : undefined;
  return { type: env.type, signerId: env.signer.id, publicKey, statement: env.statement, signature, anchor };
}

function refOf(parsed) {
  return sha3(REF_DOMAIN, Buffer.from([0]), payload(parsed.type, parsed.statement), parsed.signature).toString('hex');
}

function anchorDigest(parsed) {
  return sha3(ANCHOR_DOMAIN, Buffer.from([0]), payload(parsed.type, parsed.statement), parsed.signature);
}

function boundKey(parsed) {
  return parsed.statement[SIGNER[parsed.type]];
}

module.exports = {
  SPEC, NAME, FORMAT, KEY_FORMAT, SALT_FORMAT, ALGORITHM, KIND, TYPES, LAYOUT, FIELDS, SIGNER, CLAIMED, PUBLIC_KEY_BYTES, SIGNATURE_BYTES, NOTE_MAX, SEQ_MAX,
  sha3, keyIdOf, partyIdentity, partyRef, partySalt, textProblem, timeProblem, fieldProblem, statementProblem, payload, parse, refOf, anchorDigest, boundKey, reject, plainCopy, article,
};
