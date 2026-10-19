// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const { performance } = require('perf_hooks');
const qstamp = require('@quantovainc/qstamp');
const F = require('./format');
const C = require('./core');

const CLOCK_SKEW_MS = 5 * 60 * 1000;
const DEFAULT_ANCHOR_DELAY_S = 24 * 60 * 60;
const ANCHOR_DELAY_MAX_S = 366 * 24 * 60 * 60;
const RECORDS_MAX = F.SPEC.recordsMax || 2000;
const RECEIPTS_PER_RECORD = 8;
const BASE_ANCHOR_LOOKUPS = 32;
const ANCHOR_LOOKUPS_MAX = RECEIPTS_PER_RECORD * RECORDS_MAX;
const LOOKUP_POOL = 4;
const DEFAULT_DEADLINE_MS = 120000;
const DEFAULT_KEY_STATUS_MS = 10000;
const TIME_LIMIT_MAX_MS = 3600000;
const REVOKED_AT_MAX_S = 1e11;
const QSTAMP_DEADLINE_MIN_MS = 100;
const PASS = ['rpc', 'client', 'clients', 'contract', 'trustCustomContract', 'trustSingleEndpoint', 'trustCustomEndpoints', 'allowLoopback', 'endpointAllowList', 'expectedSender'];
const ENDPOINTS = ['rpc', 'client', 'clients'];
const CLIENT_EXTRAS = ['finality', 'getFinality', 'eventProof', 'getEventProof', 'storageAt', 'contractMap'];
const ROLE_OPTIONS = Object.fromEntries(Object.keys(F.SPEC.roles).map((r) => [r, r + 'Keys']));
const SPEC_OPTIONS = Object.keys(F.SPEC.verifyOptions || {});
const COMMON = ['type', 'requireAnchor', 'at', 'maxAnchorDelay', 'maxAnchorLookups', 'deadlineMs', 'records', 'allSupplied', 'party', 'keyStatus', 'keyStatusTimeoutMs', 'sovereign'].concat(PASS, Object.values(ROLE_OPTIONS), SPEC_OPTIONS);

function plain(text) {
  return String(text).replace(/:\s+/g, ', ').replace(/;\s*/g, ', ').slice(0, 300);
}

function provenOf(result) {
  if (!result || (result.status !== 'valid' && result.status !== 'unproven')) return false;
  return typeof qstamp.isProven === 'function' && qstamp.isProven(result) === true;
}

function statusOf(checks) {
  if (checks.some((c) => !c.ok && !c.transport && !c.indeterminate)) return 'invalid';
  if (checks.some((c) => !c.ok)) return 'indeterminate';
  return 'valid';
}

function iso(ms) {
  return new Date(ms).toISOString();
}

function limiter(size) {
  let active = 0;
  const waiting = [];
  const release = () => {
    const next = waiting.shift();
    if (next) next();
    else active -= 1;
  };
  return async (fn) => {
    if (active >= size) await new Promise((resolve) => waiting.push(resolve));
    else active += 1;
    try {
      return await fn();
    } finally {
      release();
    }
  };
}

async function within(ms, work) {
  let timer;
  const late = new Promise((resolve) => {
    timer = setTimeout(() => resolve({ late: true }), Math.max(0, ms));
  });
  try {
    return await Promise.race([Promise.resolve().then(work).then((value) => ({ value }), (error) => ({ failed: true, error })), late]);
  } finally {
    clearTimeout(timer);
  }
}

function timeLeft(ctx) {
  return ctx.deadline - performance.now();
}

function bounded(ctx, options) {
  return Object.assign(options, { deadlineMs: Math.min(TIME_LIMIT_MAX_MS, Math.max(QSTAMP_DEADLINE_MIN_MS, Math.floor(timeLeft(ctx)))), signal: ctx.stop.signal });
}

function msOption(opts, name, fallback) {
  const v = opts[name];
  if (v === undefined) return fallback;
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 1 || v > TIME_LIMIT_MAX_MS) F.reject(name + ' is a whole number of milliseconds from 1 to ' + TIME_LIMIT_MAX_MS);
  return v;
}

function genesisOf(opts) {
  if (opts.sovereign !== undefined) {
    const g = opts.sovereign.genesisTime;
    return Number.isSafeInteger(g) && g > 0 ? g : 1;
  }
  const times = Object.values(qstamp.NETWORKS || {}).map((n) => n && n.genesisTime).filter((g) => Number.isSafeInteger(g) && g > 0);
  return times.length ? Math.min(...times) : 1;
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
  const max = F.SPEC.roleKeysMax || 64;
  if (!Array.isArray(v) || v.length === 0 || v.length > max) F.reject(name + ' is a list of 1 to ' + max + ' trusted keys');
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

function remembered(inner) {
  const memo = new Map();
  const once = (key, fn) => {
    if (!memo.has(key)) {
      const pending = Promise.resolve().then(fn);
      memo.set(key, pending);
      pending.catch(() => memo.delete(key));
    }
    return memo.get(key);
  };
  const out = {
    base: inner.base,
    nodeInfo: () => once('info', () => inner.nodeInfo()),
    transaction: (id) => once('tx ' + id, () => inner.transaction(id)),
    events: (h) => once('events ' + h, () => inner.events(h)),
    block: (h) => once('block ' + h, () => inner.block(h)),
  };
  if (typeof inner.operator === 'string') out.operator = inner.operator;
  for (const name of CLIENT_EXTRAS) if (typeof inner[name] === 'function') out[name] = (...args) => inner[name](...args);
  return out;
}

function endpointsFor(ctx, receipt) {
  const opts = ctx.opts;
  const out = anchorOptions(opts);
  if (opts.clients !== undefined && !Array.isArray(opts.clients)) return out;
  const given = [];
  if (Array.isArray(opts.clients)) given.push(...opts.clients);
  if (opts.client !== undefined) given.push(opts.client);
  if (opts.rpc !== undefined) given.push(...(Array.isArray(opts.rpc) ? opts.rpc : [opts.rpc]));
  for (const k of ENDPOINTS) delete out[k];
  if (given.length === 0) return out;
  out.clients = given.map((target) => {
    if (!target || typeof target !== 'object' || typeof target.transaction !== 'function') return target;
    let byChain = ctx.endpointCache.get(target);
    if (!byChain) {
      byChain = new Map();
      ctx.endpointCache.set(target, byChain);
    }
    if (!byChain.has(receipt.chain.id)) byChain.set(receipt.chain.id, remembered(target));
    return byChain.get(receipt.chain.id);
  });
  return out;
}

async function anchorResult(receipt, options, ctx) {
  if (ctx.opts.sovereign !== undefined) return C.sovereign().verify(receipt, Object.assign(options, { sovereign: ctx.opts.sovereign }));
  return qstamp.verify(receipt, options);
}

function unanchored(ctx, label) {
  if (ctx.req) ctx.add(label, false, 'not anchored, so its time is only the claim of its signer', false, true);
  else ctx.add(label, true, 'not anchored, the time is the claim of the signer and was not proven');
  return null;
}

function belongs(p, receipt) {
  if (receipt === null || typeof receipt !== 'object' || Array.isArray(receipt)) return false;
  try {
    qstamp.validateReceipt(JSON.parse(JSON.stringify(receipt)));
  } catch (e) {
    return false;
  }
  if (receipt.kind !== String(F.KIND) || receipt.record.alg !== 'sha3-256') return false;
  if (receipt.record.digest !== F.anchorDigest(p).toString('hex')) return false;
  const leaf = qstamp.leafHash(receipt.record.alg, Buffer.from(receipt.record.digest, 'hex'), Buffer.from(receipt.record.salt, 'hex'));
  const root = qstamp.rootFromPath(leaf, receipt.proof.index, receipt.proof.size, receipt.proof.path.map((x) => Buffer.from(x, 'hex')));
  return !!root && root.equals(Buffer.from(receipt.root, 'hex'));
}

function position(receipt) {
  return [receipt.anchor.time, receipt.chain.id, receipt.chain.genesis, receipt.anchor.height, receipt.anchor.tx, receipt.proof.index];
}

function byPosition(a, b) {
  const x = position(a);
  const y = position(b);
  for (let i = 0; i < x.length; i += 1) {
    if (x[i] < y[i]) return -1;
    if (x[i] > y[i]) return 1;
  }
  return 0;
}

function lookupAllowed(ctx, receipt) {
  let key;
  try {
    qstamp.validateReceipt(JSON.parse(JSON.stringify(receipt)));
    key = [receipt.chain.id, receipt.chain.genesis, receipt.anchor.tx, receipt.anchor.height].join(' ');
  } catch (e) {
    return true;
  }
  if (ctx.lookups.has(key)) return true;
  if (ctx.lookups.size >= ctx.lookupsMax) return false;
  ctx.lookups.add(key);
  return true;
}

function direct(ctx) {
  return { add: ctx.add, notice: (n) => ctx.notices.push(n), seen: null };
}

async function lookup(ctx, receipt, options, label, add) {
  if (timeLeft(ctx) <= 0) {
    ctx.clock.expired = true;
    add(label, false, 'the anchor was not checked, the verification reached its time limit of ' + Math.round(ctx.deadlineMs / 1000) + ' seconds', false, true);
    return null;
  }
  const got = await ctx.lookup(() => within(timeLeft(ctx), () => anchorResult(receipt, bounded(ctx, options), ctx)));
  if (got.late) {
    ctx.clock.expired = true;
    add(label, false, 'the anchor was not checked, the verification reached its time limit of ' + Math.round(ctx.deadlineMs / 1000) + ' seconds', false, true);
    return null;
  }
  if (got.failed) throw got.error;
  return got.value;
}

async function checkReceipt(p, receipt, ctx, label, sink) {
  const { add, seen } = sink;
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
    if (!lookupAllowed(ctx, receipt)) {
      add(label, false, 'the anchor was not checked, the verification reached its limit of ' + ctx.lookupsMax + ' anchoring transactions, give a larger maxAnchorLookups to check every anchor', false, true);
      return null;
    }
    const result = await lookup(ctx, receipt, Object.assign(endpointsFor(ctx, receipt), { digest: F.anchorDigest(p) }), label, add);
    if (result === null) return null;
    for (const e of result.endpoints || []) ctx.net.endpoints.add(e);
    if ((result.endpoints || []).length) ctx.net.official = ctx.net.official !== false && result.officialEndpoints === true;
    if (provenOf(result)) {
      for (const c of result.checks) {
        if (c.ok) add(label + ' ' + c.name, true, c.detail);
        else sink.notice(plain(label + ' ' + c.name + ', ' + c.detail));
      }
    } else if (result.status === 'valid' || result.status === 'unproven') {
      for (const c of result.checks) add(label + ' ' + c.name, c.ok, c.name === 'proof' ? c.detail + ', so it is treated as not anchored' : c.detail, false, !c.ok);
      if (!result.checks.some((c) => !c.ok && c.name === 'proof')) add(label + ' proof', false, 'the anchor is not proven by a finality certificate or by official endpoints of two different operators, so it is treated as not anchored', false, true);
      return null;
    } else {
      for (const c of result.checks) add(label + ' ' + c.name, c.ok, c.detail, c.transport);
      return null;
    }
    const ms = receipt.anchor.time * 1000;
    const stated = claimedMs(p);
    if (stated > ms + CLOCK_SKEW_MS) {
      if (seen) seen.contradicts = true;
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

function sameChain(a, b) {
  return a.chain.id === b.chain.id && a.chain.genesis === b.chain.genesis;
}

function couldBeEarlier(u, proven, stated) {
  if (sameChain(u, proven) && u.anchor.height >= proven.anchor.height) return false;
  return u.anchor.time * 1000 < stated - CLOCK_SKEW_MS || u.anchor.time < proven.anchor.time;
}

async function checkAnchor(p, ctx, label) {
  const receipts = p.receipts || (p.anchor === undefined ? [] : [p.anchor]);
  const bare = p.receipts ? p.bare : p.anchor === undefined;
  if (receipts.length === 0) return unanchored(ctx, label);
  if (receipts.length === 1 && !bare) return checkReceipt(p, receipts[0], ctx, label, direct(ctx));
  const own = receipts.filter((r) => belongs(p, r)).sort(byPosition);
  if (own.length === 0) {
    if (bare) {
      ctx.add(label + ' copies', true, 'ignored ' + receipts.length + ' attached anchor that does not belong to this record, the record was also supplied without one');
      return unanchored(ctx, label);
    }
    return checkReceipt(p, receipts[0], ctx, label, direct(ctx));
  }
  const stated = claimedMs(p);
  const examine = (receipt) => {
    const sink = { checks: [], notices: [], seen: {} };
    sink.add = (...a) => sink.checks.push(a);
    sink.notice = (n) => sink.notices.push(n);
    return checkReceipt(p, receipt, ctx, label, sink).then((res) => ({ res, sink }));
  };
  const flush = (sink) => {
    for (const a of sink.checks) ctx.add(...a);
    for (const n of sink.notices) ctx.notices.push(n);
  };
  const ahead = [];
  let next = 0;
  const settle = () => Promise.allSettled(ahead.splice(0));
  const unsure = [];
  let verified = null;
  let open = null;
  let first = null;
  for (let i = 0; i < own.length; i += 1) {
    while (next < own.length && ahead.length < LOOKUP_POOL) {
      ahead.push(examine(own[next]));
      next += 1;
    }
    const { res, sink } = await ahead.shift();
    if (sink.seen.contradicts) {
      flush(sink);
      await settle();
      return null;
    }
    if (res && sink.checks.every((a) => a[1])) {
      flush(sink);
      await settle();
      const counted = unsure.filter((u) => couldBeEarlier(u, own[i], stated)).length;
      const ignored = unsure.length - counted;
      if (counted) ctx.add(label + ' earlier copies', false, counted + ' anchor of this record that claims an earlier time could not be checked, so the earliest anchor is not established', false, true);
      if (ignored) ctx.notices.push(plain(label + ' copies, ignored ' + ignored + ' anchor of this record that claims an earlier time at a height the chain reached only after the proven anchor, which an honest chain cannot hold'));
      return res;
    }
    const seen = { sink, res };
    if (sink.checks.every((a) => a[1] || a[3] || a[4])) {
      unsure.push(own[i]);
      if (!open) open = seen;
    }
    if (res && !verified) verified = seen;
    if (!first) first = seen;
  }
  const fallback = verified || open || first;
  if (!fallback.res && bare && unsure.length === 0) {
    ctx.add(label + ' copies', true, 'ignored ' + own.length + ' attached anchor that does not verify, the record was also supplied without one');
    return unanchored(ctx, label);
  }
  flush(fallback.sink);
  if (unsure.length > 1) ctx.add(label + ' copies', false, unsure.length + ' anchors of this record could not be checked and none of the others is proven, so the earliest anchor is not established', false, true);
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
  if (ctx.opts.keyStatus !== undefined) await keyCheck(p, info, ctx, pre);
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
      const sub = Object.assign({}, ctx, { checks: [], seen: new Map(ctx.seen), scopes: new Set(), notices: [], facts: null });
      sub.add = (name, ok, detail, transport, indeterminate) => sub.checks.push({ name, ok: !!ok, transport: !!transport, indeterminate: !!indeterminate });
      const res = await checkRecord(r, sub, '');
      probes.set(F.refOf(r), { status: statusOf(sub.checks), anchor: res.anchor });
    }
  }
  if (t.verifyCheck) {
    for (const [name, okv, detail, indeterminate, notice] of t.verifyCheck(p, links, { claimedMs, F, info, ctx, pool: ctx.pool, anchorOf: (r) => (ctx.seen.get(F.refOf(r)) || {}).anchor, probeOf: (r) => probes.get(F.refOf(r)) || null, top: pre === '', fact: (name, value) => { if (pre === '' && ctx.facts) ctx.facts[name] = value; } })) {
      ctx.add(pre + name, okv, detail, false, !!indeterminate);
      if (notice) ctx.notices.push(plain(notice));
    }
  }
  return info;
}

function errorText(e) {
  try {
    return String((e && e.message) || e);
  } catch (err) {
    return 'unknown error';
  }
}

function registryAnswer(st, ctx) {
  try {
    if (st === null || typeof st !== 'object' || Array.isArray(st)) return { problem: 'an answer that is not an object' };
    const revoked = st.revoked;
    if (typeof revoked !== 'boolean') return { problem: 'an answer whose revoked value is not true or false' };
    if (!revoked) return { revoked };
    const revokedAt = st.revokedAt;
    if (!Number.isSafeInteger(revokedAt) || revokedAt < ctx.genesisS || revokedAt > REVOKED_AT_MAX_S) {
      return { problem: 'a revocation whose revokedAt is not a whole number of seconds since 1970 between the genesis of the network and ' + REVOKED_AT_MAX_S };
    }
    return { revoked, revokedAt };
  } catch (e) {
    return { problem: 'an answer that could not be read' };
  }
}

async function keyCheck(p, info, ctx, pre) {
  let pending = ctx.keyStates.get(p.signerId);
  if (!pending) {
    pending = within(Math.min(ctx.keyStatusMs, Math.max(0, timeLeft(ctx))), () => ctx.opts.keyStatus(p.signerId));
    ctx.keyStates.set(p.signerId, pending);
  }
  const r = await pending;
  if (r.late) {
    if (timeLeft(ctx) <= 0) ctx.clock.expired = true;
    ctx.add(pre + 'key status', false, 'the key registry did not answer in time, so the status of the signing key is unknown', true, true);
    return;
  }
  if (r.failed) {
    ctx.add(pre + 'key status', false, 'the key registry could not be read, ' + errorText(r.error), true, true);
    return;
  }
  const st = registryAnswer(r.value, ctx);
  if (st.problem) {
    ctx.add(pre + 'key status', false, 'the key registry gave ' + st.problem + ', so the status of the signing key is unknown', false, true);
    return;
  }
  if (!st.revoked) {
    ctx.add(pre + 'key status', true, 'the key registry holds no revocation of the signing key');
    return;
  }
  const proven = !!(info.anchor && info.anchor.proven);
  const at = proven ? info.anchor.ms : claimedMs(p);
  const before = at < st.revokedAt * 1000;
  ctx.add(pre + 'key status', before && proven, before
    ? (proven ? 'anchored before the key was revoked' : 'dated before the key was revoked, but only by the claim of a key that is now revoked')
    : 'signed by a key the registry revoked at ' + iso(st.revokedAt * 1000), false, before && !proven);
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
  const bySeq = new Map();
  const flagged = new Set();
  for (const [ref, r] of ctx.pool) {
    const t = F.SPEC.types[r.type];
    if (!t.chain) continue;
    const scopeKey = r.type + ' ' + r.statement[t.chain.scope];
    if (!ctx.scopes.has(scopeKey)) continue;
    const trusted = ctx.roles[t.role];
    if (!trusted || !trusted.has(r.signerId)) continue;
    const key = scopeKey + ' ' + r.statement.seq;
    const held = bySeq.get(key);
    if (held !== undefined && held !== ref) {
      if (!flagged.has(key)) ctx.add('conflicting ' + r.type, false, 'two different ' + r.type + ' records hold position ' + r.statement.seq + ' of the same series');
      flagged.add(key);
    } else {
      bySeq.set(key, ref);
    }
  }
}

function pooled(pool, r) {
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
    return held;
  }
  const key = JSON.stringify(r.anchor);
  if (!held.receiptKeys.has(key)) {
    held.receiptKeys.add(key);
    held.receipts.push(r.anchor);
  }
  return held;
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
    pooled(pool, r);
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
  for (const k of SPEC_OPTIONS) if (opts[k] !== undefined && !F.optionApplies(k, opts.type)) F.reject('the option ' + k + ' does not apply to ' + F.article(opts.type));
  for (const k of SPEC_OPTIONS) if (opts[k] !== undefined && (typeof opts[k] !== 'string' || !/^[0-9a-f]{64}$/.test(opts[k]))) F.reject(k + ' is ' + F.SPEC.verifyOptions[k]);
  let delayMs = DEFAULT_ANCHOR_DELAY_S * 1000;
  if (opts.maxAnchorDelay !== undefined) {
    const v = opts.maxAnchorDelay;
    if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 60 || v > ANCHOR_DELAY_MAX_S) F.reject('maxAnchorDelay is a whole number of seconds from 60 to ' + ANCHOR_DELAY_MAX_S);
    delayMs = v * 1000;
  }
  const started = performance.now();
  const stop = new AbortController();
  const supplied = Array.isArray(opts.records) ? opts.records.length : 0;
  let lookupsMax = Math.min(ANCHOR_LOOKUPS_MAX, RECEIPTS_PER_RECORD * (supplied + 1) + BASE_ANCHOR_LOOKUPS);
  if (opts.maxAnchorLookups !== undefined) {
    const v = opts.maxAnchorLookups;
    if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 1 || v > ANCHOR_LOOKUPS_MAX) F.reject('maxAnchorLookups is a whole number from 1 to ' + ANCHOR_LOOKUPS_MAX);
    lookupsMax = v;
  }
  const deadlineMs = msOption(opts, 'deadlineMs', DEFAULT_DEADLINE_MS);
  if (opts.keyStatus !== undefined && typeof opts.keyStatus !== 'function') F.reject('keyStatus is a function that returns the registry status of a key');
  if (opts.keyStatusTimeoutMs !== undefined && opts.keyStatus === undefined) F.reject('keyStatusTimeoutMs goes with keyStatus');
  const keyStatusMs = msOption(opts, 'keyStatusTimeoutMs', DEFAULT_KEY_STATUS_MS);
  if (opts.sovereign !== undefined) {
    if (ENDPOINTS.some((k) => opts[k] !== undefined)) F.reject('the endpoints of a sovereign network are given in sovereign.rpcs, not in rpc, client or clients');
    C.sovereign().network(opts.sovereign);
  }
  const roles = rolesOf(opts);
  let atMs;
  if (opts.at !== undefined) {
    const tp = F.timeProblem(opts.at, 'at');
    if (tp) F.reject(tp);
    atMs = Date.parse(opts.at);
  } else {
    const limits = { deadlineMs: Math.max(QSTAMP_DEADLINE_MIN_MS, Math.floor(started + deadlineMs - performance.now())), signal: stop.signal };
    const read = await within(started + deadlineMs - performance.now(), () => (opts.sovereign !== undefined ? C.sovereign().chainTime(Object.assign(anchorOptions(opts), limits, { sovereign: opts.sovereign })) : qstamp.chainTime(Object.assign(anchorOptions(opts), limits))));
    if (read.late) stop.abort();
    if (read.late || read.failed || !read.value || !Number.isFinite(read.value.early)) {
      const why = read.late ? 'the time limit of the verification was reached' : read.failed ? errorText(read.error) : 'the chain gave no time';
      const err = new Error('the chain time could not be established, so no result was given, check the endpoints or give at to verify at a stated time, ' + why);
      err.code = F.NAME.toUpperCase() + '_NO_CHAIN_TIME';
      throw err;
    }
    atMs = read.value.early;
  }
  const checks = [];
  const ctx = {
    opts, req: opts.requireAnchor !== false, atMs, atGiven: opts.at !== undefined, delayMs, roles,
    checks, seen: new Map(), scopes: new Set(), pool: null, notices: [], net: { endpoints: new Set(), official: null },
    lookups: new Set(), lookupsMax, endpointCache: new Map(), memo: new Map(), keyStates: new Map(), facts: {},
    deadline: started + deadlineMs, deadlineMs, clock: { expired: false }, lookup: limiter(LOOKUP_POOL), keyStatusMs, genesisS: genesisOf(opts), stop,
    add: (name, ok, detail, transport, indeterminate) => checks.push({ name, ok: !!ok, detail: plain(detail), transport: !!transport, indeterminate: !!indeterminate }),
  };
  const finish = (extra) => {
    stop.abort();
    if (ctx.clock.expired) ctx.add('time limit', false, 'the verification reached its time limit of ' + Math.round(deadlineMs / 1000) + ' seconds before every anchor and key was checked, give a larger deadlineMs to check them all', false, true);
    const status = statusOf(checks);
    return Object.assign({ valid: status === 'valid', status }, extra, { facts: Object.assign({}, ctx.facts), endpoints: [...ctx.net.endpoints], officialEndpoints: ctx.net.official, notices: ctx.notices.slice(), checks: checks.map((c) => Object.assign({}, c)) }, { valid: status === 'valid', status });
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
  ctx.add('signature', sigOk, sigOk ? 'the ' + F.ALGORITHM + ' signature is valid' : 'the signature does not verify or does not belong to the key named in the record');
  const ref = F.refOf(p);
  const base = { type: p.type, ref, signerKeyId: p.signerId, statement: p.statement };
  if (!sigOk) return finish(base);
  ctx.pool = parsePool(opts, ctx);
  p = pooled(ctx.pool, p);
  ctx.target = p;
  for (const d of docs) {
    const given = [d.doc, d.field].filter((k) => opts[k] !== undefined);
    if (given.length > 1) F.reject('give ' + d.doc + ' or ' + d.field + ', not both');
    if (given.length === 0) continue;
    let digest;
    if (opts[d.doc] !== undefined) {
      if (!((ArrayBuffer.isView(opts[d.doc]) && opts[d.doc] instanceof Uint8Array))) F.reject(d.doc + ' is a Uint8Array');
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
    if (!pt || typeof pt !== 'object' || typeof pt.field !== 'string' || !((ArrayBuffer.isView(pt.salt) && pt.salt instanceof Uint8Array))) F.reject('party is an object with field, identity and a 32 byte salt');
    const f = F.LAYOUT[p.type].find((x) => x.name === pt.field && x.kind === 'party');
    if (!f) F.reject('party.field must name a party field of ' + F.article(p.type));
    const sp = F.SPEC.types[p.type].secretParty;
    const want = p.statement[pt.field];
    const same = F.partyRef(pt.salt, pt.identity) === want || (!(sp && sp.field === pt.field) && F.legacyPartyRef(pt.salt, pt.identity) === want);
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
