// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

module.exports = Object.freeze({
  name: 'qspend',
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
      fields: { budgetRef: ['text', 128, true], line: ['text', 128, true], period: ['text', 64, true], currency: ['currency'], amount: ['posamount'] },
    },
    allotment: {
      role: 'budget', id: 'allotmentId', signer: 'budgetKeyId', time: 'allottedAt',
      links: { appropriation: { field: 'appropriationRef', type: 'appropriation', copy: [['currency', 'currency']] } },
      fields: { unit: ['text', 128, true], currency: ['currency'], amount: ['posamount'] },
      chain: { scope: 'appropriationRef', prev: 'prevAllotmentRef', total: 'allottedTotal', amount: 'amount', cap: ['appropriation', 'amount'] },
    },
    commitment: {
      role: 'officer', id: 'commitmentId', signer: 'officerKeyId', time: 'committedAt',
      links: { allotment: { field: 'allotmentRef', type: 'allotment', copy: [['currency', 'currency']] } },
      fields: { supplierRef: ['party'], documentDigest: ['digest', 0, false, 'document'], currency: ['currency'], amount: ['posamount'] },
      chain: { scope: 'allotmentRef', prev: 'prevCommitmentRef', total: 'committedTotal', amount: 'amount', cap: ['allotment', 'amount'] },
    },
    receipt: {
      role: 'receiver', id: 'receiptId', signer: 'receiverKeyId', time: 'receivedAt',
      links: { commitment: { field: 'commitmentRef', type: 'commitment' } },
      fields: { documentDigest: ['digest', 0, false, 'document'] },
    },
    invoice: {
      role: 'intake', id: 'invoiceId', signer: 'intakeKeyId', time: 'receivedAt',
      links: {
        commitment: { field: 'commitmentRef', type: 'commitment', copy: [['currency', 'currency']], max: [['amount', 'amount']] },
        receipt: { field: 'receiptRef', type: 'receipt', match: [['commitmentRef', 'commitmentRef']] },
      },
      fields: { invoiceNumber: ['text', 64, true], invoiceDigest: ['digest', 0, false, 'document'], currency: ['currency'], amount: ['posamount'] },
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
        if (!inv) return [];
        const norm = (v) => v.normalize('NFKC').toLowerCase().replace(/[^\p{L}\p{N}]/gu, '');
        const number = norm(inv.statement.invoiceNumber);
        const payers = h.ctx.roles.treasury;
        const intake = h.ctx.roles.intake;
        const own = h.F.refOf(p);
        const twice = [...h.pool.values()].some((r) => {
          if (r.type !== 'payment' || h.F.refOf(r) === own || r.statement.commitmentRef !== p.statement.commitmentRef) return false;
          if (!payers || !payers.has(r.signerId)) return false;
          const other = h.pool.get(r.statement.invoiceRef);
          if (!other || other.type !== 'invoice' || h.F.refOf(other) === h.F.refOf(inv) || !intake || !intake.has(other.signerId)) return false;
          return other.statement.invoiceDigest === inv.statement.invoiceDigest || norm(other.statement.invoiceNumber) === number;
        });
        return [['invoice paid once', !twice, twice ? 'another supplied payment of this commitment pays a different invoice record with the same invoice number or the same invoice document' : 'no other supplied payment of this commitment pays the same invoice number or invoice document']];
      },
    },
  },
});
