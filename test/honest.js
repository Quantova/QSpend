'use strict';

const q = require('..');
const { network, stamper, iso } = require('./chain');

async function honest() {
  const now = Math.floor(Date.now() / 1000);
  const net = network(now - 86400);
  const at = stamper(q, net);
  const K = {};
  for (const r of q.ROLES) K[r] = q.generateKey();
  const t0 = now - 80000;
  const app = await at(q.appropriation({ key: K.ministry, budgetRef: 'B1', line: 'roads', period: '2026', currency: 'EUR', amount: '1000000', validUntil: iso(now + 30 * 86400), approvedAt: iso(t0) }), t0 + 5);
  const allot = await at(q.allotment({ ledger: false, key: K.budget, appropriation: app, unit: 'works', amount: '1000000', first: true, allottedAt: iso(t0 + 10) }), t0 + 15);
  const com = await at(q.commitment({ ledger: false, key: K.officer, allotment: allot, supplier: 'ACME BV', partySecret: Uint8Array.from({ length: 32 }, (_, i) => (4 + i) & 255), document: Buffer.from('po'), amount: '50000', first: true, committedAt: iso(t0 + 20) }), t0 + 25);
  const rec = await at(q.receipt({ key: K.receiver, commitment: com, document: Buffer.from('grn'), receivedAt: iso(t0 + 30) }), t0 + 35);
  const inv = await at(q.invoice({ key: K.intake, commitment: com, receipt: rec, invoiceNumber: 'INV-1001', document: Buffer.from('scan'), amount: '20000', receivedAt: iso(t0 + 40) }), t0 + 45);
  const pay = await at(q.payment({ ledger: false, key: K.treasury, commitment: com, invoice: inv, first: true, paidAt: iso(t0 + 50) }), t0 + 55);
  net.chain.block(now);
  const roles = Object.fromEntries(Object.entries(K).map(([r, k]) => [r + 'Keys', [q.keyId(k)]]));
  return { q, net, now, K, roles, at, all: { appropriation: app, allotment: allot, commitment: com, receipt: rec, invoice: inv, payment: pay } };
}

module.exports = { honest };
