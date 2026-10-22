// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

export type RecordType = 'appropriation' | 'allotment' | 'commitment' | 'receipt' | 'invoice' | 'payment';
export type Role = 'ministry' | 'budget' | 'officer' | 'receiver' | 'intake' | 'treasury';

export interface Envelope {
  format: 'qspend/2';
  type: RecordType;
  algorithm: 'ML-DSA-65';
  signer: { id: string; publicKey: string };
  statement: Record<string, unknown>;
  signature: string;
  anchor?: unknown;
}

export interface SeriesLedger {
  read(name: string): Promise<string | null>;
  compareAndSwap(name: string, expected: string | null, next: string): Promise<boolean>;
}

export interface KeyDescription {
  format: 'qspend-key/1';
  algorithm: 'ML-DSA-65';
  id: string;
  publicKey: string;
}

export type KeyRef = string | Uint8Array | KeyDescription;

export interface AppropriationOptions {
  key: Uint8Array;
  budgetRef: string;
  line: string;
  period: string;
  currency: string;
  amount: string;
  validUntil: string;
  approvedAt?: string;
  note?: string;
}

export interface AllotmentOptions {
  key: Uint8Array;
  appropriation: Envelope;
  unit: string;
  currency?: string;
  amount: string;
  previous?: Envelope;
  first?: boolean;
  ledger: string | SeriesLedger | false;
  allottedAt?: string;
  note?: string;
}

export interface CommitmentOptions {
  key: Uint8Array;
  allotment: Envelope;
  supplierRef?: string;
  partyScheme?: string;
  documentDigest?: string;
  document?: Uint8Array;
  awardRef?: string;
  currency?: string;
  amount: string;
  supplier: string;
  partySecret: Uint8Array;
  previous?: Envelope;
  first?: boolean;
  ledger: string | SeriesLedger | false;
  committedAt?: string;
  note?: string;
}

export interface ReceiptOptions {
  key: Uint8Array;
  commitment: Envelope;
  documentDigest?: string;
  document?: Uint8Array;
  receivedAt?: string;
  note?: string;
}

export interface InvoiceOptions {
  key: Uint8Array;
  commitment: Envelope;
  receipt: Envelope;
  invoiceNumber: string;
  invoiceDigest?: string;
  document?: Uint8Array;
  currency?: string;
  amount: string;
  receivedAt?: string;
  note?: string;
}

export interface PaymentOptions {
  key: Uint8Array;
  commitment: Envelope;
  invoice: Envelope;
  currency?: string;
  amount?: string;
  previous?: Envelope;
  first?: boolean;
  ledger: string | SeriesLedger | false;
  paidAt?: string;
  note?: string;
}

export type KeyStatus = { revoked: false } | { revoked: true; revokedAt: number };

export interface VerifyOptions {
  type: RecordType;
  ministryKeys?: KeyRef[];
  budgetKeys?: KeyRef[];
  officerKeys?: KeyRef[];
  receiverKeys?: KeyRef[];
  intakeKeys?: KeyRef[];
  treasuryKeys?: KeyRef[];
  awardRef?: string;
  records?: Envelope[];
  allSupplied?: boolean;
  party?: { field: string; identity: string; salt: Uint8Array };
  documentDigest?: string;
  document?: Uint8Array;
  invoiceDigest?: string;
  requireAnchor?: boolean;
  at?: string;
  maxAnchorDelay?: number;
  maxAnchorLookups?: number;
  deadlineMs?: number;
  keyStatus?: (keyId: string) => KeyStatus | Promise<KeyStatus>;
  keyStatusTimeoutMs?: number;
  rpc?: string | string[];
  client?: unknown;
  clients?: Array<string | unknown>;
  trustSingleEndpoint?: boolean;
  trustCustomEndpoints?: boolean;
  allowLoopback?: boolean;
  endpointAllowList?: string[];
  expectedSender?: string | string[];
  contract?: string;
  trustCustomContract?: boolean;
}

export interface VerifyCheck {
  name: string;
  ok: boolean;
  detail: string;
  transport: boolean;
  indeterminate: boolean;
}

export interface VerifyResult {
  valid: boolean;
  status: 'valid' | 'invalid' | 'indeterminate';
  type: RecordType | null;
  checks: VerifyCheck[];
  endpoints: string[];
  officialEndpoints: boolean | null;
  notices: string[];
  facts: Record<string, unknown>;
  [field: string]: unknown;
}

export interface AnchorOptions {
  seed: Uint8Array;
  index: number;
  network?: 'testnet';
  rpc?: string | string[];
  client?: unknown;
  clients?: Array<string | unknown>;
  trustSingleEndpoint?: boolean;
  allowLoopback?: boolean;
  endpointAllowList?: string[];
  meter?: number;
  maxFee?: string | number;
  timeoutMs?: number;
  onPending?: (pending: unknown) => void | Promise<void>;
}

export function generateKey(): Uint8Array;
export function publicKey(key: Uint8Array): Uint8Array;
export function keyId(key: Uint8Array): string;
export function describeKey(key: Uint8Array): KeyDescription;
export function commitParty(identity: string, options?: { salt?: Uint8Array; secret?: Uint8Array; scope?: string }): { salt: Uint8Array; ref: string };
export function appropriation(options: AppropriationOptions): Envelope;
export function allotment(options: AllotmentOptions & { ledger: string | SeriesLedger }): Promise<Envelope>;
export function allotment(options: AllotmentOptions & { ledger: false }): Envelope;
export function commitment(options: CommitmentOptions & { ledger: string | SeriesLedger }): Promise<Envelope>;
export function commitment(options: CommitmentOptions & { ledger: false }): Envelope;
export function receipt(options: ReceiptOptions): Envelope;
export function invoice(options: InvoiceOptions): Envelope;
export function payment(options: PaymentOptions & { ledger: string | SeriesLedger }): Promise<Envelope>;
export function payment(options: PaymentOptions & { ledger: false }): Envelope;
export function create(type: RecordType, options: Record<string, unknown>): Envelope | Promise<Envelope>;
export function folderLedger(folder: string): SeriesLedger;
export function ledgerLatest(ledger: string | SeriesLedger, type: RecordType, seriesRef: string): Promise<Envelope | null>;
export function anchor(envelopes: Envelope | Envelope[], options: AnchorOptions): Promise<Envelope[]>;
export function complete(envelopes: Envelope | Envelope[], pending: unknown, options?: { rpc?: string | string[]; client?: unknown; clients?: Array<string | unknown>; trustSingleEndpoint?: boolean; allowLoopback?: boolean; endpointAllowList?: string[]; timeoutMs?: number }): Promise<Envelope[]>;
export function verify(envelope: unknown, options: VerifyOptions): Promise<VerifyResult>;
export function refOf(envelope: Envelope): string;
export function anchorDigest(envelope: Envelope): string;
export const FORMAT: 'qspend/2';
export const ALGORITHM: 'ML-DSA-65';
export const KIND: 1102;
export const TYPES: readonly RecordType[];
export const ROLES: readonly Role[];
