// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const UP = { allotment: 'appropriationRef', commitment: 'allotmentRef', receipt: 'commitmentRef', invoice: 'commitmentRef', payment: 'commitmentRef' };

function appropriationOf(p, pool) {
  let cur = p;
  for (let i = 0; i < 4 && cur && cur.type !== 'appropriation'; i += 1) cur = UP[cur.type] ? pool.get(cur.statement[UP[cur.type]]) : null;
  return cur && cur.type === 'appropriation' ? cur : null;
}

function lapse(p, links, h) {
  const app = appropriationOf(p, h.pool);
  if (!app) return [];
  const until = app.statement.validUntil;
  const untilMs = Date.parse(until);
  const a = h.info.anchor;
  if (a && a.proven) {
    const ok = a.ms <= untilMs;
    return [['appropriation period', ok, ok ? 'anchored within the period of the appropriation, which lapses at ' + until : 'anchored after the appropriation lapsed at ' + until]];
  }
  if (h.claimedMs(p) > untilMs) return [['appropriation period', false, 'dated after the appropriation lapsed at ' + until]];
  if (h.ctx.req) return [['appropriation period', false, 'not anchored with a proven time, so it is not proven to come before the appropriation lapsed at ' + until, true]];
  return [['appropriation period', true, 'dated within the period of the appropriation, which lapses at ' + until + ', anchors were not required']];
}

module.exports = Object.freeze({
  version: 2,
  name: 'qspend',
  wasm: () => require('../wasm/qspend_native.js'),
  verifyOptions: { awardRef: 'the reference of the procurement award, 64 lowercase hex characters' },
  verifyOptionTypes: { awardRef: Object.freeze(['commitment', 'receipt', 'invoice', 'payment']) },
  title: 'QSpend',
  kind: 1102,
  magic: 'QSPN',
  summary: 'post quantum public spending integrity for governments',
  roles: {
    ministry: 'finance ministry key',
    budget: 'budget office key',
    officer: 'authorising officer key',
    receiver: 'receiving officer key',
    intake: 'invoice intake key',
    treasury: 'treasury officer key',
  },
  types: {
    appropriation: {
      role: 'ministry', id: 'appropriationId', signer: 'ministryKeyId', time: 'approvedAt',
      fields: { budgetRef: ['text', 128, true], line: ['text', 128, true], period: ['text', 64, true], currency: ['currency'], amount: ['posamount'], validUntil: ['time'] },
      shape: (st) => (Date.parse(st.validUntil) <= Date.parse(st.approvedAt) ? 'an appropriation lapses only after it was approved' : null),
    },
    allotment: {
      role: 'budget', id: 'allotmentId', signer: 'budgetKeyId', time: 'allottedAt',
      links: { appropriation: { field: 'appropriationRef', type: 'appropriation', copy: [['currency', 'currency']] } },
      fields: { unit: ['text', 128, true], currency: ['currency'], amount: ['posamount'] },
      chain: { scope: 'appropriationRef', prev: 'prevAllotmentRef', total: 'allottedTotal', amount: 'amount', cap: ['appropriation', 'amount'] },
      signCheck: (st, links) => (Date.parse(st.allottedAt) > Date.parse(links.appropriation.statement.validUntil) ? 'the appropriation lapsed before this allotment' : null),
      verifyCheck: lapse,
    },
    commitment: {
      role: 'officer', id: 'commitmentId', signer: 'officerKeyId', time: 'committedAt',
      links: { allotment: { field: 'allotmentRef', type: 'allotment', copy: [['currency', 'currency']] } },
      fields: { supplierRef: ['party'], partyScheme: ['text', 64, true], documentDigest: ['digest', 0, false, 'document'], awardRef: ['optref'], currency: ['currency'], amount: ['posamount'] },
      secretParty: { field: 'supplierRef', scheme: 'partyScheme', fixedScope: 'supplier', identity: 'supplier' },
      chain: { scope: 'allotmentRef', prev: 'prevCommitmentRef', total: 'committedTotal', amount: 'amount', cap: ['allotment', 'amount'] },
      verifyCheck: (p, links, h) => {
        const out = lapse(p, links, h);
        const want = h.ctx.opts.awardRef;
        const target = h.ctx.target;
        const named = target && target !== p && ['receipt', 'invoice', 'payment'].includes(target.type) && target.statement.commitmentRef === h.F.refOf(p);
        if (want === undefined || (p !== target && !named)) return out;
        const ok = p.statement.awardRef === want;
        out.push(['award', ok, ok ? 'the commitment cites the procurement award given' : p.statement.awardRef === '' ? 'the commitment cites no procurement award' : 'the commitment cites a different procurement award']);
        return out;
      },
    },
    receipt: {
      role: 'receiver', id: 'receiptId', signer: 'receiverKeyId', time: 'receivedAt',
      links: { commitment: { field: 'commitmentRef', type: 'commitment' } },
      fields: { documentDigest: ['digest', 0, false, 'document'] },
      verifyCheck: lapse,
    },
    invoice: {
      role: 'intake', id: 'invoiceId', signer: 'intakeKeyId', time: 'receivedAt',
      links: {
        commitment: { field: 'commitmentRef', type: 'commitment', copy: [['currency', 'currency']], max: [['amount', 'amount']] },
        receipt: { field: 'receiptRef', type: 'receipt', match: [['commitmentRef', 'commitmentRef']] },
      },
      fields: { invoiceNumber: ['text', 64, true], invoiceDigest: ['digest', 0, false, 'document'], currency: ['currency'], amount: ['posamount'] },
      verifyCheck: lapse,
    },
    payment: {
      role: 'treasury', id: 'paymentId', signer: 'treasuryKeyId', time: 'paidAt',
      links: {
        commitment: { field: 'commitmentRef', type: 'commitment', copy: [['currency', 'currency']] },
        invoice: { field: 'invoiceRef', type: 'invoice', copy: [['amount', 'amount']], match: [['commitmentRef', 'commitmentRef'], ['currency', 'currency']] },
      },
      fields: { currency: ['currency'], amount: ['posamount'] },
      chain: { scope: 'commitmentRef', prev: 'prevPaymentRef', total: 'paidTotal', amount: 'amount', cap: ['commitment', 'amount'], unique: 'invoiceRef' },
      verifyCheck: (p, links, h) => {
        const inv = links.invoice;
        if (!inv) return lapse(p, links, h);
        const payers = h.ctx.roles.treasury;
        const intake = h.ctx.roles.intake;
        const officers = h.ctx.roles.officer;
        const own = h.F.refOf(p);
        const invRef = h.F.refOf(inv);
        const supplierOf = (commitmentRef) => {
          const c = h.pool.get(commitmentRef);
          return c && c.type === 'commitment' && officers && officers.has(c.signerId) ? c.statement.supplierRef : null;
        };
        const supplier = supplierOf(p.statement.commitmentRef);
        let same = 0;
        let elsewhere = 0;
        let unsure = 0;
        for (const r of h.pool.values()) {
          if (r.type !== 'payment' || !payers || !payers.has(r.signerId) || h.F.refOf(r) === own) continue;
          const other = h.pool.get(r.statement.invoiceRef);
          if (!other || other.type !== 'invoice' || h.F.refOf(other) === invRef || !intake || !intake.has(other.signerId)) continue;
          const sameDocument = other.statement.invoiceDigest === inv.statement.invoiceDigest;
          const sameNumber = h.F.sameIdentifier(other.statement.invoiceNumber, inv.statement.invoiceNumber);
          const sameCommitment = r.statement.commitmentRef === p.statement.commitmentRef;
          const sameSupplier = sameCommitment || (supplier !== null && supplierOf(r.statement.commitmentRef) === supplier);
          if (sameDocument || (sameNumber && sameSupplier)) {
            if (sameCommitment) same += 1;
            else elsewhere += 1;
          } else if (sameNumber) {
            unsure += 1;
          }
        }
        const twice = same + elsewhere > 0;
        if (!twice && unsure) return [['invoice paid once', false, 'another supplied payment pays an invoice with the same invoice number under a commitment whose supplier commitment differs or was not supplied, so it is not shown whether the same invoice was paid twice', true]].concat(lapse(p, links, h));
        return lapse(p, links, h).concat([['invoice paid once', !twice, twice ? 'another supplied payment ' + (elsewhere ? 'under ' + (same ? 'this and another commitment' : 'another commitment') : 'of this commitment') + ' pays a different invoice record with the same invoice document, or the same invoice number from the same supplier' : 'no other supplied payment pays the same invoice document, or the same invoice number from the same supplier']]);
      },
    },
  },
});
