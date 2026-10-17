# QSpend

QSpend is a post quantum public spending integrity layer for governments. It seals each stage of public expenditure at the moment it occurs, from the appropriation voted by the legislature to the allotment, the commitment, the confirmation of receipt, the invoice and the payment, and links each stage to the stage that authorised it. Supreme audit institutions, parliaments and courts can later prove that no payment was made without authority, above its commitment or twice, without relying on the systems of the body that made it. Every record is signed with the Module Lattice Digital Signature Algorithm, parameter set 65, as standardised in FIPS 204, and can carry a Qstamp time proof recorded on the Quantova network under the QSpend record kind.

QSpend is part of QGov, the government branch of the Qstamp family.

## What QSpend is

Misused public funds hide in records that can be adjusted after the event. A payment with no valid commitment behind it, a payment split or repeated to avoid approval limits, an allotment that silently exceeds its appropriation, or a budget line rewritten once the money has gone. Each depends on a record that its custodian can quietly change.

QSpend removes that possibility. The finance ministry seals each appropriation when it is approved. The budget office seals each allotment against its appropriation, carrying the running total allotted. An authorising officer seals each commitment against its allotment, carrying the running total committed. A receiving officer confirms delivery under a separate key, the invoice intake seals each invoice against its commitment and its confirmation of receipt, and the treasury seals each payment against its invoice, carrying its position and the running total paid on the commitment. A verifier can then confirm the whole chain from appropriation to payment without trusting any of the bodies involved or Quantova Inc.

QSpend is standalone. It runs on the systems of the government, holds keys locally and uses the Quantova network only as a neutral public ledger for time proofs.

## What it detects

1. A record altered, replaced, inserted or backdated after it was sealed.
2. Allotments that together exceed their appropriation, commitments that together exceed their allotment, and payments that together exceed their commitment.
3. An invoice above its commitment, or an invoice whose confirmation of receipt belongs to another commitment.
4. A payment that differs from its invoice in amount or currency, a payment repeated against the same invoice, or a payment of a second invoice record that carries the same invoice number in the same commitment.
5. A record signed by a key that is not trusted for its role, or two linked records signed by the same key.
6. A record dated before the record it relies on.
7. Two different records in the same position of a series, once the records held for the series are supplied.
8. A record anchored long after the time it states, which is twenty four hours by default, is not accepted as proof of that time.

## Who uses it

1. Finance ministries and treasuries that want every payment of public money to be provable to auditors, parliaments and courts.
2. Spending departments and agencies that commit and receive public funds.
3. Supreme audit institutions, anti corruption agencies and parliamentary committees that review public expenditure.

## How a government integrates QSpend

1. Issue keys by role. The government creates separate ML-DSA-65 keys for the finance ministry, the budget office, authorising officers, receiving officers, invoice intake and the treasury, and publishes six lists of trusted keys. A key may appear in only one list, and QSpend refuses to sign a record with the key that signed a record it relies on.

2. Name suppliers privately. The commitParty function turns a supplier identifier into a salted commitment. Only the commitment enters a commitment record. The government keeps the identifier and the salt and can prove the link to a court without publishing either.

3. Seal the budget. The finance ministry calls appropriation for each budget line. The budget office calls allotment for each release of funds, naming the previous allotment on the same appropriation or declaring it the first.

4. Seal commitments, receipts and invoices. An authorising officer calls commitment against an allotment, with the fingerprint of the purchase order or contract. A receiving officer calls receipt against the commitment. Invoice intake calls invoice against the commitment and the receipt.

5. Seal payments. The treasury calls payment against the commitment and the invoice, naming the previous payment on the same commitment or declaring it the first. QSpend refuses to sign a payment that differs from its invoice, that repeats the invoice of the previous payment or that would take the payments above the commitment.

6. Anchor promptly. A single service with a funded Quantova account anchors new records in batches under the QSpend record kind, and each record receives its own receipt.

7. Verify on demand. Auditors and courts verify any record against the six lists of trusted keys and the records the government holds, with the verify command, the library or the independent procedure below.

## What is published and what stays private

Budget documents, contracts, invoices, supplier identities and bank details stay with the government. Records hold only SHA3 fingerprints of documents, salted commitments to suppliers and the key identifiers of officials.

When a record is anchored, only a 32 byte Qstamp commitment reaches the chain. It is derived from a salted fingerprint of the signed record and cannot be reversed into any field of the record.

## Cryptographic construction

1. Keys. Keys are 32 byte seeds from which ML-DSA-65 key pairs are derived by the key generation procedure of FIPS 204. A key identifier is the SHA3 hash with a 256 bit output of the ASCII label quantova/qspend/key/1, the byte 0x00 and the 1952 byte public key.

2. Party commitments. A supplier is named by the SHA3-256 hash of the ASCII label quantova/qspend/party/1, the byte 0x00, a random 32 byte salt and the identifier in Unicode normal form C. When the authority supplies its own 32 byte secret and the reference of the record that defines the series, the salt is instead the SHA3-256 hash of the ASCII label quantova/qspend/party-salt/1, the byte 0x00, the secret, the 32 byte reference and the identifier in Unicode normal form C, so the same party always receives the same commitment in that series.

3. Statements. Each statement is a canonical binary encoding that begins with the ASCII bytes QSPN and the version byte 1, followed by the statement type and its fields in a fixed order. Every field is an unsigned 16 bit big endian length followed by its bytes. Identifiers, key identifiers, references and digests are encoded as raw bytes, an absent reference is an empty field, sequence numbers are unsigned 64 bit big endian integers, and text is UTF-8 in Unicode normal form C, so every statement has exactly one encoding. Amounts are whole numbers of minor units with no leading zeros, and a currency is three capital letters, which QSpend checks for form only, so the integrating system should use ISO 4217 codes.

4. Signatures. Statements are signed with ML-DSA-65 in its hedged form under the FIPS 204 context string quantova/qspend/1, which separates QSpend signatures from every other SDK of the family and from every other use of the algorithm.

5. References. A record is referenced by the SHA3 hash of the label quantova/qspend/ref/1, the byte 0x00, the encoded statement and its signature. Each record names the records it relies on by these references, so it relies on one exact signed record that existed before it was signed.

6. Series. Allotments on one appropriation, commitments on one allotment and payments on one commitment each form a series. Every record of a series carries its position from one, the reference of the previous record of the series, which is empty only for the first, and the running total including itself.

7. Anchor. To anchor a record, QSpend stamps the SHA3 hash of the label quantova/qspend/anchor/1, the byte 0x00, the encoded statement and its signature as a Qstamp record of kind 1102.

## Record types

| Type | Signed by | Relies on | Series |
|---|---|---|---|
| appropriation | finance ministry key | none | none |
| allotment | budget office key | appropriation | per appropriation, capped by its amount |
| commitment | authorising officer key | allotment | per allotment, capped by its amount |
| receipt | receiving officer key | commitment | none |
| invoice | invoice intake key | commitment and receipt | none |
| payment | treasury officer key | commitment and invoice | per commitment, capped by its amount, one payment per invoice |

## Rules applied by verification

1. The expected record type is required, so a record of one type can never be presented as another, and options that do not apply to that type are refused.
2. The record is well formed and signed by the key it names, and that key is trusted for the role of its type. The six lists of trusted keys must not share a key.
3. Every record the record relies on, and every earlier record of each series involved, is taken from the records supplied and verified in turn by the same rules, back to the appropriation.
4. Each linked record is exactly the one referenced, of the expected type, signed by a different key, and dated no later than the record that relies on it.
5. Copied and matched fields agree, such as the currency of a commitment and its allotment, and an invoice does not exceed its commitment.
6. Each record of a series continues the previous record in position, running total and currency, the running total does not exceed its cap, and a payment does not repeat the invoice of an earlier payment in its series.
7. Any two different supplied records in the same position of a series involved make the result invalid.
8. A record in a series is valid only when the verifier declares that every record it holds for the series involved was supplied. Without that declaration the result is indeterminate, and with it a missing record makes the result invalid.
9. When documents are supplied, their fingerprints match the signed fingerprints, and when a supplier identity and salt are supplied, they match the commitment.
10. Each anchor is verified under the QSpend record kind with a SHA3 digest, and the stated time is not later than the anchor time, allowing five minutes. An anchor more than twenty four hours after the stated time, unless another limit is given, or later than a given verification time, does not prove the stated time and makes the result indeterminate.

A result is valid only when the trusted keys are given, every record relied on is supplied, the records held for each series are declared complete, and every record is anchored. When any of these is missing the result is indeterminate rather than valid. A record verified with anchoring not required proves only who signed it and what was signed, and its stated time is the claim of its signer.

## Trust model of this release

This release anchors on the live Quantova network Q-test-net-1. The signing module is compiled from the Quantova Q-Crypto library, which follows FIPS 204 and FIPS 202 and has been tested against the NIST vectors. It has not been validated under FIPS 140-3. Anchor times are confirmed by the endpoints a verifier queries and are accepted only when at least two endpoints run by different operators agree. Verification names the endpoints it consulted and says whether they are the official endpoints of the network, and a verifier who needs independence from any single operator should query several independent endpoints.

A sealed record proves who signed it, what was signed and when it was anchored. Each check is made from the records a verifier is given, so two records in the same position of a series are detected only when both are supplied, and auditors should obtain every record the government holds for the series they examine. A supplier commitment is the same in every record that uses the same salt, so records about one supplier can be linked by anyone who sees them, and anyone who obtains the salt can test guesses of the identifier, so salts must be protected like the identifiers themselves. Verifiers must keep the keys of retired officials in the trusted lists for as long as records they signed are verified. Payments are limited by their commitment, but two invoices may cite the same confirmation of receipt and two appropriations may be sealed for the same budget line, so the invoice intake and the finance ministry must prevent duplicates within their own procedures. A sealed record does not prove that a purchase represented value for money or that a payment was lawful, which remains the work of auditors and courts, and it does not detect spending that was never recorded.

## Installation

```
npm install @quantovainc/qspend
```

QSpend requires Node 20 or later.

## Command line use

```
qspend keygen ministry.key
qspend keygen budget.key
qspend keygen officer.key
qspend keygen receiver.key
qspend keygen intake.key
qspend keygen treasury.key
qspend key ministry.key > ministry.pub.json
qspend key budget.key > budget.pub.json
qspend key officer.key > officer.pub.json
qspend key receiver.key > receiver.pub.json
qspend key intake.key > intake.pub.json
qspend key treasury.key > treasury.pub.json
qspend commit-party --identity-file supplier.txt --random-salt --salt-out supplier.salt

qspend appropriation --key ministry.key --budget-ref "Appropriation Act 2026 section 4" --line "Road maintenance" --period 2026 --currency EUR --amount 100000000 --out appropriation.json
qspend allotment --key budget.key --appropriation appropriation.json --unit "Roads directorate" --amount 60000000 --first --out allotment.json
qspend commitment --key officer.key --allotment allotment.json --supplier-ref <commitment> --document order.pdf --amount 2500000 --first --out commitment.json
qspend receipt --key receiver.key --commitment commitment.json --document delivery.pdf --out receipt.json
qspend invoice --key intake.key --commitment commitment.json --receipt receipt.json --invoice-number "INV 0042" --document invoice.pdf --amount 2500000 --out invoice.json
qspend payment --key treasury.key --commitment commitment.json --invoice invoice.json --first --out payment.json
qspend anchor appropriation.json allotment.json commitment.json receipt.json invoice.json payment.json --seed-file account.key

qspend verify payment.json --type payment --ministry ministry.pub.json --budget budget.pub.json --officer officer.pub.json --receiver receiver.pub.json --intake intake.pub.json --treasury treasury.pub.json --record appropriation.json --record allotment.json --record commitment.json --record receipt.json --record invoice.json --all-supplied
```

The file account.key holds the 32 byte seed of a funded Quantova account, as 64 hexadecimal characters, which pays for anchoring. It is separate from the signing keys of officials.

If anchoring is interrupted after its transaction may have been sent, a pending stamp is kept beside each envelope and the envelopes are not anchored again. Finish with qspend complete, giving the same envelopes in the same order and the pending stamp.

The command exits with status 0 when the result is valid, 1 when it is invalid, refused or the evidence is malformed, 2 when it cannot be decided, and 64 for usage errors. Key and salt files must be readable only by their owner and are never followed through symbolic links.

## Independent verification procedure

1. Decode each public key and signature from base64 and confirm their lengths are 1952 and 3309 bytes.
2. Compute each key identifier from the label quantova/qspend/key/1, the byte 0x00 and the public key, and compare it with the signer identifier and the signing party named in the statement.
3. Encode each statement as described above and verify its signature with ML-DSA-65 under the context string quantova/qspend/1, following FIPS 204.
4. Compute the reference of each linked record and of each earlier record of each series, confirm each is the one named, and apply the rules of verification listed above.
5. Compute the anchor value of each record and verify its receipt by the procedure published with Qstamp under record kind 1102.

## Network

The live Quantova network is named Q-test-net-1 with genesis hash ca91e093bb8de33e90db52d7c89876597d14760703793ea7211929e73e613062. Anchors are recorded by the official Qstamp contract on that network. The public endpoint is https://rpc-testnet.quantova.org. Chain data is accepted only when at least two endpoints run by different operators agree. Give them with the rpc or clients option, or with --rpc once for each on the command line. The option trustSingleEndpoint, or --trust-single-endpoint, relies on one endpoint, which can then invent an anchor alone.

## Licence

QSpend is created and owned by Quantova Inc. It is licensed under the Apache License 2.0 or the MIT licence, at your option. The full texts are in the files LICENSE-APACHE and LICENSE-MIT, and the notice is in NOTICE.
