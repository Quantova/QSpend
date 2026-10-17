// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const qstamp = require('@quantovainc/qstamp');
const F = require('./format');
const C = require('./core');

const CLOCK_SKEW_MS = 5 * 60 * 1000;
const DEFAULT_ANCHOR_DELAY_S = 24 * 60 * 60;
const ANCHOR_DELAY_MAX_S = 366 * 24 * 60 * 60;
const RECORDS_MAX = F.SPEC.recordsMax || 2000;
const RECEIPTS_PER_RECORD = 8;
const PASS = ['rpc', 'client', 'clients', 'contract', 'trustCustomContract', 'trustSingleEndpoint'];
const ROLE_OPTIONS = Object.fromEntries(Object.keys(F.SPEC.roles).map((r) => [r, r + 'Keys']));
const COMMON = ['type', 'requireAnchor', 'at', 'maxAnchorDelay', 'records', 'allSupplied', 'party'].concat(PASS, Object.values(ROLE_OPTIONS));

function plain(text) {
  return String(text).replace(/:\s+/g, ', ').replace(/;\s*/g, ', ').slice(0, 300);
}

function statusOf(checks) {
  if (checks.some((c) => !c.ok && !c.transport && !c.indeterminate)) return 'invalid';
  if (checks.some((c) => !c.ok)) return 'indeterminate';
  return 'valid';
}

function iso(ms) {
  return new Date(ms).toISOString();
}

function claimedMs(p) {
  return Date.parse(p.statement[F.CLAIMED[p.type]]);
}

function docOptions(type) {
  const out = [];
  for (const [name, def] of Object.entries(F.SPEC.types[type].fields || {})) {
    if (def[0] === 'digest' && def[3]) out.push({ field: name, doc: def[3] });
  }
  return out;
}

function keyList(opts, name) {
  const v = opts[name];
  if (v === undefined) return null;
  if (!Array.isArray(v) || v.length === 0 || v.length > 64) F.reject(name + ' is a list of 1 to 64 trusted keys');
  return new Set(v.map((k, i) => C.keyIdFrom(k, name + ' ' + (i + 1))));
}

function rolesOf(opts) {
  const roles = {};
  for (const [role, option] of Object.entries(ROLE_OPTIONS)) roles[role] = keyList(opts, option);
  const names = Object.keys(roles);
  for (let i = 0; i < names.length; i += 1) {
    for (let j = i + 1; j < names.length; j += 1) {
      const a = roles[names[i]];
      const b = roles[names[j]];
      if (a && b) for (const k of a) if (b.has(k)) F.reject('the key ' + k + ' is trusted as both ' + names[i] + ' and ' + names[j] + ', a key may hold only one role');
    }
  }
  return roles;
}

function anchorOptions(opts) {
  const out = {};
  for (const k of PASS) if (opts[k] !== undefined) out[k] = opts[k];
  return out;
}

function unanchored(ctx, label) {
  if (ctx.req) ctx.add(label, false, 'not anchored, so its time is only the claim of its signer', false, true);
  else ctx.add(label, true, 'not anchored, the time is the claim of the signer and was not proven');
  return null;
}

async function checkReceipt(p, receipt, ctx, label, add) {
  try {
    if (receipt === null || typeof receipt !== 'object' || Array.isArray(receipt)) {
      add(label, false, 'the anchor is not a Qstamp receipt');
      return null;
    }
    if (receipt.kind !== String(F.KIND)) {
      add(label, false, 'the anchor was not recorded under the ' + F.SPEC.title + ' record kind');
      return null;
    }
    if (!receipt.record || receipt.record.alg !== 'sha3-256') {
      add(label, false, 'the anchor does not record a SHA3 digest');
      return null;
    }
    const result = await qstamp.verify(receipt, Object.assign(anchorOptions(ctx.opts), { digest: F.anchorDigest(p) }));
    for (const e of result.endpoints || []) ctx.net.endpoints.add(e);
    if ((result.endpoints || []).length) ctx.net.official = ctx.net.official !== false && result.officialEndpoints === true;
    for (const c of result.checks) add(label + ' ' + c.name, c.ok, c.detail, c.transport);
    if (result.status !== 'valid') return null;
    const ms = receipt.anchor.time * 1000;
    const stated = claimedMs(p);
    if (stated > ms + CLOCK_SKEW_MS) {
      add(label + ' time', false, 'the stated time is later than the anchor time ' + iso(ms));
      return null;
    }
    if (ms - stated > ctx.delayMs) {
      add(label + ' time', false, 'anchored at ' + iso(ms) + ', more than ' + Math.round(ctx.delayMs / 3600000) + ' hours after its stated time, so the stated time is not proven', false, true);
      return { ms, proven: false };
    }
    if (ctx.atGiven && ms > ctx.atMs) {
      add(label + ' time', false, 'anchored at ' + iso(ms) + ', after the time given for verification, so it was not proven at that time', false, true);
      return { ms, proven: false };
    }
    add(label + ' time', true, 'recorded by ' + iso(ms));
    return { ms, proven: true };
  } catch (e) {
    add(label, false, 'the anchor could not be checked, ' + ((e && e.message) || 'unknown error'));
    return null;
  }
}

async function checkAnchor(p, ctx, label) {
  const receipts = p.receipts || (p.anchor === undefined ? [] : [p.anchor]);
  const bare = p.receipts ? p.bare : p.anchor === undefined;
  if (receipts.length === 0) return unanchored(ctx, label);
  if (receipts.length === 1 && !bare) return checkReceipt(p, receipts[0], ctx, label, ctx.add);
  let fallback = null;
  for (const receipt of receipts) {
    const sub = [];
    const res = await checkReceipt(p, receipt, ctx, label, (...a) => sub.push(a));
    if (res && sub.every((a) => a[1])) {
      for (const a of sub) ctx.add(...a);
      return res;
    }
    if (!fallback || (!fallback.res && res)) fallback = { sub, res };
  }
  if (!fallback.res && bare) {
    ctx.add(label + ' copies', true, 'ignored ' + receipts.length + ' attached anchor that does not verify, the record was also supplied without one');
    return unanchored(ctx, label);
  }
  for (const a of fallback.sub) ctx.add(...a);
  return fallback.res;
}

function prefix(label) {
  return label ? label + ' ' : '';
}

async function checkRecord(p, ctx, label) {
  const ref = F.refOf(p);
  if (ctx.seen.has(ref)) return ctx.seen.get(ref);
  const t = F.SPEC.types[p.type];
  const info = { ref, anchor: null };
  ctx.seen.set(ref, info);
  const pre = prefix(label);
  const set = ctx.roles[t.role];
  if (set === null) F.reject('the trusted ' + F.SPEC.roles[t.role] + ' keys are required, give ' + ROLE_OPTIONS[t.role]);
  const ok = set.has(p.signerId);
  ctx.add(pre + 'signer', ok, ok ? 'signed by a trusted ' + F.SPEC.roles[t.role] : 'signed by a key that is not a trusted ' + F.SPEC.roles[t.role]);
  if (claimedMs(p) > ctx.atMs + CLOCK_SKEW_MS) ctx.add(pre + 'time', false, 'the record is dated after the time of verification');
  info.anchor = await checkAnchor(p, ctx, pre + 'anchor');
  const links = {};
  for (const [lname, l] of Object.entries(t.links || {})) {
    const lref = p.statement[l.field];
    if (lref === '') continue;
    const e = ctx.pool.get(lref);
    const lpre = pre + lname;
    if (!e) {
      ctx.add(lpre, false, 'the ' + lname + ' this record relies on was not supplied' + (ctx.opts.allSupplied === true ? ', although every record was declared supplied' : ''), false, ctx.opts.allSupplied !== true);
      continue;
    }
    if (e.type !== l.type) {
      ctx.add(lpre, false, 'the record named as the ' + lname + ' is not ' + F.article(l.type));
      continue;
    }
    links[lname] = e;
    ctx.add(lpre, true, 'the ' + lname + ' this record names is supplied and validly signed');
    for (const [mine, theirs] of (l.copy || []).concat(l.match || [])) {
      const same = p.statement[mine] === e.statement[theirs];
      ctx.add(lpre + ' ' + mine, same, same ? 'the ' + mine + ' matches the ' + lname : 'the ' + mine + ' differs from the ' + theirs + ' of the ' + lname);
    }
    for (const [mine, theirs] of l.max || []) {
      const within = BigInt(p.statement[mine]) <= BigInt(e.statement[theirs]);
      ctx.add(lpre + ' ' + mine, within, within ? 'the ' + mine + ' is within the ' + theirs + ' of the ' + lname : 'the ' + mine + ' exceeds the ' + theirs + ' of the ' + lname);
    }
    if (!l.after && claimedMs(e) > claimedMs(p)) ctx.add(lpre + ' order', false, 'this record is dated before the ' + lname + ' it relies on');
    if (e.signerId === p.signerId && !l.sameRole) ctx.add(lpre + ' separation', false, 'the same key signed this record and the ' + lname);
    await checkRecord(e, ctx, lpre);
  }
  if (t.chain) await checkChain(p, t, links, ctx, pre);
  if (t.gather) {
    for (const [glabel, r] of t.gather(p, ctx.pool, { F, ctx, claimedMs })) await checkRecord(r, ctx, pre + glabel);
  }
  const probes = new Map();
  if (t.probe) {
    for (const r of t.probe(p, ctx.pool, { F, ctx, claimedMs })) {
      const sub = Object.assign({}, ctx, { checks: [], seen: new Map(ctx.seen), scopes: new Set(), notices: [] });
      sub.add = (name, ok, detail, transport, indeterminate) => sub.checks.push({ name, ok: !!ok, transport: !!transport, indeterminate: !!indeterminate });
      const res = await checkRecord(r, sub, '');
      probes.set(F.refOf(r), { status: statusOf(sub.checks), anchor: res.anchor });
    }
  }
  if (t.verifyCheck) {
    for (const [name, okv, detail, indeterminate, notice] of t.verifyCheck(p, links, { claimedMs, F, info, ctx, pool: ctx.pool, anchorOf: (r) => (ctx.seen.get(F.refOf(r)) || {}).anchor, probeOf: (r) => probes.get(F.refOf(r)) || null })) {
      ctx.add(pre + name, okv, detail, false, !!indeterminate);
      if (notice) ctx.notices.push(plain(notice));
    }
  }
  return info;
}

async function checkChain(p, t, links, ctx, pre) {
  const c = t.chain;
  const scopeKey = p.type + ' ' + p.statement[c.scope];
  ctx.scopes.add(scopeKey);
  if (c.total && c.cap) {
    const capRec = links[c.cap[0]];
    if (capRec) {
      const within = BigInt(p.statement[c.total]) <= BigInt(capRec.statement[c.cap[1]]);
      ctx.add(pre + 'running total', within, within ? 'the running total ' + p.statement[c.total] + ' is within the ' + c.cap[1] + ' of the ' + c.cap[0] : 'the running total ' + p.statement[c.total] + ' exceeds the ' + c.cap[1] + ' of the ' + c.cap[0]);
    }
  }
  if (p.statement.seq === 1) return;
  const prev = ctx.pool.get(p.statement[c.prev]);
  if (!prev) {
    ctx.add(pre + 'series', false, p.type + ' ' + (p.statement.seq - 1) + ' of this series was not supplied' + (ctx.opts.allSupplied === true ? ', although every record was declared supplied' : ''), false, ctx.opts.allSupplied !== true);
    return;
  }
  const linkOk = prev.type === p.type && prev.statement[c.scope] === p.statement[c.scope] && prev.statement.seq + 1 === p.statement.seq
    && (!c.total || BigInt(prev.statement[c.total]) + BigInt(p.statement[c.amount]) === BigInt(p.statement[c.total]))
    && (p.statement.currency === undefined || prev.statement.currency === p.statement.currency);
  ctx.add(pre + 'series', linkOk, linkOk ? p.type + ' ' + p.statement.seq + ' continues ' + p.type + ' ' + prev.statement.seq + ' of the same series' : p.type + ' ' + p.statement.seq + ' does not continue the previous ' + p.type + ' in series, position, total or currency');
  if (claimedMs(prev) > claimedMs(p)) ctx.add(pre + 'series order', false, p.type + ' ' + p.statement.seq + ' is dated before ' + p.type + ' ' + prev.statement.seq);
  if (c.unique) {
    let cur = prev;
    const value = p.statement[c.unique];
    while (cur) {
      if (cur.statement[c.unique] === value) {
        ctx.add(pre + 'repeat', false, 'the same ' + c.unique + ' appears twice in this series');
        break;
      }
      cur = cur.statement.seq > 1 ? ctx.pool.get(cur.statement[c.prev]) : null;
      if (cur && cur.type !== p.type) cur = null;
    }
  }
  if (linkOk) await checkRecord(prev, ctx, p.type + ' ' + prev.statement.seq);
}

function forks(ctx) {
  for (const scopeKey of ctx.scopes) {
    const [type, scope] = scopeKey.split(' ');
    const c = F.SPEC.types[type].chain;
    const trusted = ctx.roles[F.SPEC.types[type].role];
    const bySeq = new Map();
    const flagged = new Set();
    for (const [ref, r] of ctx.pool) {
      if (r.type !== type || r.statement[c.scope] !== scope) continue;
      if (!trusted || !trusted.has(r.signerId)) continue;
      const held = bySeq.get(r.statement.seq);
      if (held !== undefined && held !== ref) {
        if (!flagged.has(r.statement.seq)) ctx.add('conflicting ' + type, false, 'two different ' + type + ' records hold position ' + r.statement.seq + ' of the same series');
        flagged.add(r.statement.seq);
      } else {
        bySeq.set(r.statement.seq, ref);
      }
    }
  }
}

function parsePool(opts, ctx) {
  const pool = new Map();
  const list = opts.records === undefined ? [] : opts.records;
  if (!Array.isArray(list) || list.length > RECORDS_MAX) F.reject('records is a list of at most ' + RECORDS_MAX + ' envelopes');
  let untrusted = 0;
  list.forEach((env, i) => {
    let r;
    try {
      r = F.parse(env);
    } catch (e) {
      ctx.add('supplied record ' + (i + 1), true, 'ignored, not a valid envelope, ' + e.message);
      return;
    }
    if (!C.signatureOk(r)) {
      ctx.add('supplied record ' + (i + 1), true, 'ignored, not validly signed by the key it names');
      return;
    }
    const set = ctx.roles[F.SPEC.types[r.type].role];
    if (set && !set.has(r.signerId)) untrusted += 1;
    const ref = F.refOf(r);
    if (!pool.has(ref)) {
      r.receipts = [];
      r.receiptKeys = new Set();
      r.bare = false;
      pool.set(ref, r);
    }
    const held = pool.get(ref);
    if (r.anchor === undefined) {
      held.bare = true;
      return;
    }
    const key = JSON.stringify(r.anchor);
    if (held.receiptKeys.has(key)) return;
    if (held.receipts.length >= RECEIPTS_PER_RECORD) {
      ctx.add('supplied record ' + (i + 1), true, 'ignored, its record already carries ' + RECEIPTS_PER_RECORD + ' different anchors');
      return;
    }
    held.receiptKeys.add(key);
    held.receipts.push(r.anchor);
  });
  if (untrusted) ctx.add('supplied records', true, untrusted + ' supplied record signed by a key that is not trusted for its role is used only where a trusted record names it, and never to find a conflict');
  return pool;
}

async function verify(envelope, options) {
  if (options === null || typeof options !== 'object') F.reject('options is an object naming the expected type and the trusted keys');
  const opts = options;
  if (!F.TYPES.includes(opts.type)) F.reject('type is required and is one of ' + F.TYPES.join(', '));
  const docs = docOptions(opts.type);
  const allowed = new Set(COMMON.concat(docs.flatMap((d) => [d.doc, d.field])));
  for (const k of Object.keys(opts)) if (!allowed.has(k)) F.reject('the option ' + k + ' does not apply to ' + F.article(opts.type));
  if (opts.allSupplied !== undefined && typeof opts.allSupplied !== 'boolean') F.reject('allSupplied is true or false');
  let delayMs = DEFAULT_ANCHOR_DELAY_S * 1000;
  if (opts.maxAnchorDelay !== undefined) {
    const v = opts.maxAnchorDelay;
    if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 60 || v > ANCHOR_DELAY_MAX_S) F.reject('maxAnchorDelay is a whole number of seconds from 60 to ' + ANCHOR_DELAY_MAX_S);
    delayMs = v * 1000;
  }
  let atMs;
  if (opts.at !== undefined) {
    const tp = F.timeProblem(opts.at, 'at');
    if (tp) F.reject(tp);
    atMs = Date.parse(opts.at);
  } else {
    try {
      atMs = (await qstamp.chainTime(anchorOptions(opts))).early;
    } catch (e) {
      atMs = Date.now();
    }
  }
  const checks = [];
  const ctx = {
    opts, req: opts.requireAnchor !== false, atMs, atGiven: opts.at !== undefined, delayMs, roles: rolesOf(opts),
    checks, seen: new Map(), scopes: new Set(), pool: null, notices: [], net: { endpoints: new Set(), official: null },
    add: (name, ok, detail, transport, indeterminate) => checks.push({ name, ok: !!ok, detail: plain(detail), transport: !!transport, indeterminate: !!indeterminate }),
  };
  const finish = (extra) => {
    const status = statusOf(checks);
    return Object.assign({ valid: status === 'valid', status }, extra, { endpoints: [...ctx.net.endpoints], officialEndpoints: ctx.net.official, notices: ctx.notices.slice(), checks: checks.map((c) => Object.assign({}, c)) });
  };
  let p;
  try {
    p = F.parse(envelope);
  } catch (e) {
    ctx.add('format', false, e.message);
    return finish({ type: null });
  }
  if (p.type !== opts.type) {
    ctx.add('format', false, F.article(p.type) + ' was given where ' + F.article(opts.type) + ' was expected');
    return finish({ type: p.type });
  }
  ctx.add('format', true, 'a well formed ' + p.type + ' record');
  const sigOk = C.signatureOk(p);
  ctx.add('signature', sigOk, sigOk ? 'the ML-DSA-65 signature is valid' : 'the signature does not verify or does not belong to the key named in the record');
  const ref = F.refOf(p);
  const base = { type: p.type, ref, signerKeyId: p.signerId, statement: p.statement };
  if (!sigOk) return finish(base);
  ctx.pool = parsePool(opts, ctx);
  ctx.pool.set(ref, p);
  for (const d of docs) {
    const given = [d.doc, d.field].filter((k) => opts[k] !== undefined);
    if (given.length > 1) F.reject('give ' + d.doc + ' or ' + d.field + ', not both');
    if (given.length === 0) continue;
    let digest;
    if (opts[d.doc] !== undefined) {
      if (!(opts[d.doc] instanceof Uint8Array)) F.reject(d.doc + ' is a Uint8Array');
      digest = F.sha3(opts[d.doc]).toString('hex');
    } else {
      if (typeof opts[d.field] !== 'string' || !/^[0-9a-f]{64}$/.test(opts[d.field])) F.reject(d.field + ' is 64 lowercase hex characters');
      digest = opts[d.field];
    }
    const same = digest === p.statement[d.field];
    ctx.add(d.doc, same, same ? 'the document matches the fingerprint that was signed' : 'the document differs from the one that was signed');
  }
  if (opts.party !== undefined) {
    const pt = opts.party;
    if (!pt || typeof pt !== 'object' || typeof pt.field !== 'string' || !(pt.salt instanceof Uint8Array)) F.reject('party is an object with field, identity and a 32 byte salt');
    const f = F.LAYOUT[p.type].find((x) => x.name === pt.field && x.kind === 'party');
    if (!f) F.reject('party.field must name a party field of ' + F.article(p.type));
    const same = F.partyRef(pt.salt, pt.identity) === p.statement[pt.field];
    ctx.add('party', same, same ? 'the party matches the private commitment in the record' : 'the party or its salt differs from the commitment in the record');
  }
  const info = await checkRecord(p, ctx, '');
  forks(ctx);
  if (ctx.scopes.size > 0) {
    if (opts.allSupplied === true) ctx.add('completeness', true, 'the verifier declared that every record it holds for these series was supplied');
    else ctx.add('completeness', false, 'the verifier did not declare that every record it holds for these series was supplied, so a conflicting record could be missing', false, true);
  }
  return finish(Object.assign(base, { anchoredAt: info.anchor && info.anchor.proven ? iso(info.anchor.ms) : null }));
}

module.exports = { verify };
