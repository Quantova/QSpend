// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const C = require('./lib/core');
const { verify } = require('./lib/verify');
const F = require('./lib/format');

const api = {
  generateKey: C.generateKey,
  publicKey: C.publicKey,
  keyId: C.keyId,
  describeKey: C.describeKey,
  commitParty: C.commitParty,
  create: C.create,
  anchor: C.anchor,
  complete: C.complete,
  verify,
  refOf: (envelope) => F.refOf(C.signedEnvelope(envelope, F.parse(envelope).type, 'the envelope')),
  anchorDigest: (envelope) => F.anchorDigest(C.signedEnvelope(envelope, F.parse(envelope).type, 'the envelope')).toString('hex'),
  FORMAT: F.FORMAT,
  ALGORITHM: F.ALGORITHM,
  KIND: F.KIND,
  TYPES: F.TYPES,
  ROLES: Object.freeze(Object.keys(F.SPEC.roles)),
};
for (const type of F.TYPES) api[type] = (options) => C.create(type, options);
if (F.SPEC.extras) Object.assign(api, F.SPEC.extras({ F, C }));

module.exports = api;
