// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const qstamp = require('@quantovainc/qstamp');
const native = require('./native');
const F = require('./format');

function requireSeed(key) {
  if (!(key instanceof Uint8Array) || key.length !== 32) {
    F.reject('a signing key is a 32 byte Uint8Array seed, kept by its holder and wiped with fill(0) after use');
  }
  return key;
}

function generateKey() {
  const seed = new Uint8Array(32);
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
  if (value instanceof Uint8Array) return F.keyIdOf(value);
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

function commitParty(identity) {
  F.partyIdentity(identity);
  const salt = new Uint8Array(32);
  globalThis.crypto.getRandomValues(salt);
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
    if (!(options[f.doc] instanceof Uint8Array)) F.reject(f.doc + ' is a Uint8Array');
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
  if (!options || typeof options !== 'object') F.reject(type + ' needs options');
  const t = F.SPEC.types[type];
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
      if (c.unique && prev.statement[c.unique] === st[c.unique]) F.reject('the previous ' + type + ' already used the same ' + c.unique);
      if (prev.statement.seq >= F.SEQ_MAX) F.reject('this series has reached the largest number of records');
      if (t.signCheckPrevious) {
        const pp = t.signCheckPrevious(st, prev);
        if (pp) F.reject(pp);
      }
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
  return sign(type, st, options.key);
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
  return attach(copies, await qstamp.complete(p, options || {}));
}

module.exports = {
  generateKey, publicKey, keyId, describeKey, keyIdFrom, commitParty, create, anchor, complete, signedEnvelope, signatureOk,
};
