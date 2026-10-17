// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const path = require('path');
const crypto = require('crypto');

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function polymod(values) {
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i += 1) if ((top >>> i) & 1) chk ^= GEN[i];
  }
  return chk >>> 0;
}

function bech32m(hrp, bytes) {
  const h = hrp.toLowerCase();
  const data = [];
  let acc = 0;
  let bits = 0;
  for (const v of bytes) {
    acc = (acc << 8) | v;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      data.push((acc >> bits) & 31);
    }
  }
  if (bits > 0) data.push((acc << (5 - bits)) & 31);
  const expand = [...h].map((c) => c.charCodeAt(0) >> 5).concat([0], [...h].map((c) => c.charCodeAt(0) & 31));
  const mod = polymod(expand.concat(data, [0, 0, 0, 0, 0, 0])) ^ 0x2bc830a3;
  const checksum = [];
  for (let p = 0; p < 6; p += 1) checksum.push((mod >> (5 * (5 - p))) & 31);
  return (h + '1' + data.concat(checksum).map((d) => CHARSET[d]).join('')).toUpperCase();
}

const base = path.dirname(require.resolve('@quantovainc/qstamp'));
const qstamp = require('@quantovainc/qstamp');
const wire = require(path.join(base, 'lib', 'wire'));
const { core } = require(require.resolve('@quantovainc/qcore', { paths: [base] }));

const SEED = new Uint8Array(32).fill(7);

function makeChain(startTime) {
  const net = qstamp.NETWORKS.testnet;
  const chain = { chainId: net.chainId, genesis: net.genesis, height: Math.max(1000, (startTime - net.genesisTime) * 5), time: startTime, txs: new Map(), events: new Map(), blocks: new Map(), next: null, reads: 0 };
  chain.block = (t) => {
    chain.height += 1;
    chain.time = t === undefined ? chain.time + 1 : t;
    chain.blocks.set(chain.height, { block: bech32m('QBK', crypto.randomBytes(32)), height: chain.height, time: chain.time });
    chain.events.set(chain.height, []);
    return chain.blocks.get(chain.height);
  };
  chain.block(startTime);
  chain.submit = (from, to, argsHex) => {
    const raw = Buffer.from(argsHex, 'hex');
    const words = raw.subarray(124);
    const blk = chain.block(chain.next === null ? undefined : chain.next);
    chain.next = null;
    const tx = bech32m('QTX', crypto.randomBytes(32));
    const anchored = words.subarray(0, 32);
    const kind = words.readBigUInt64BE(32).toString();
    chain.txs.set(tx, { status: 'finalised', height: blk.height, block: blk.block, from, to, kind: 'call', raw: raw.toString('hex') });
    chain.events.get(blk.height).push({ contract: to, selector: wire.STAMPED_SELECTOR, data: wire.stampedEventData(from, anchored, kind) });
    return tx;
  };
  return chain;
}

function endpoint(chain, name, overrides) {
  const ov = overrides || {};
  const copy = (v) => (v ? Object.assign({}, v) : null);
  return {
    base: 'https://' + name + '.example',
    async nodeInfo() {
      if (ov.nodeInfo) return ov.nodeInfo(chain);
      return { chain_id: chain.chainId, genesis_hash: chain.genesis, head_height: chain.height };
    },
    async block(h) {
      chain.reads += 1;
      return copy(chain.blocks.get(h));
    },
    async events(h) {
      chain.reads += 1;
      return { events: (chain.events.get(h) || []).map((e) => Object.assign({}, e)) };
    },
    async transaction(id) {
      chain.reads += 1;
      return copy(chain.txs.get(id));
    },
    async call(seed, index, to, argsHex) {
      return { outcome: { verdict: 'accepted', tx_id: chain.submit(core.address(seed, index), to, argsHex) } };
    },
  };
}

const realVerify = qstamp.verify;

async function simulatedProof(receipt, options) {
  const r = await realVerify(receipt, options);
  if (r.status !== 'unproven' || r.trust !== 'custom-endpoints' || !r.checks.every((c) => c.ok || c.name === 'proof')) return r;
  return Object.assign({}, r, {
    valid: true,
    status: 'valid',
    proven: true,
    trust: 'finality-proof',
    trustDetail: 'a finality certificate simulated by the test chain certifies the block',
    checks: r.checks.filter((c) => c.ok),
  });
}

function proofs(on) {
  qstamp.verify = on ? simulatedProof : realVerify;
}

function network(startTime) {
  const chain = makeChain(startTime);
  const clients = [endpoint(chain, 'a'), endpoint(chain, 'b')];
  proofs(true);
  return { chain, clients, opts: { clients, trustCustomEndpoints: true } };
}

function stamper(q, net) {
  return async (envs, t) => {
    net.chain.next = t === undefined ? null : t;
    const out = await q.anchor(envs, { seed: SEED, index: 0, clients: net.clients });
    return Array.isArray(envs) ? out : out[0];
  };
}

function forged(receipt, timeDelta, n) {
  const out = JSON.parse(JSON.stringify(receipt));
  out.anchor.tx = bech32m('QTX', crypto.createHash('sha256').update('forged ' + n).digest());
  out.anchor.time = receipt.anchor.time - timeDelta;
  out.anchor.height = Math.max(0, receipt.anchor.height - 1 - n);
  return out;
}

const iso = (s) => new Date(s * 1000).toISOString();
const failing = (r) => r.checks.filter((c) => !c.ok).map((c) => c.name + ': ' + c.detail);

module.exports = { network, stamper, endpoint, forged, iso, failing, proofs, bech32m, SEED };
