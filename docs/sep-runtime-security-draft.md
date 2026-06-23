## runtime-security extension (profile)

### Identity and placement

The `runtime-security` object is an extension body carried under the
`extensions` member of an audit event record, keyed `"runtime-security"`,
composing with other extension bodies (e.g. `caller-governance`) without
interaction. It summarizes a runtime policy disposition for the event.

### Fields

The `runtime-security` object contains the following members. All values
defined here MUST be JSON strings. The object MUST NOT contain numeric,
boolean, null, array, or nested-object values for the fields defined by this
profile. (This keeps the extension body within the base record's string-only
canonicalization and outside any number-canonicalization concerns.)

| Field | Required | Type | Definition |
|---|---|---|---|
| `drift_status` | REQUIRED | string enum | The runtime's evidentiary state regarding tool-surface drift for this event. |
| `severity` | REQUIRED | string enum | The severity the runtime assigned to the disposition. |
| `quarantine_decision` | REQUIRED | string enum | The disposition the runtime applied. |
| `policy_id` | REQUIRED | string | Identifier of the policy that produced this disposition. |
| `evidence_hash` | OPTIONAL | string | A cryptographic commitment to an out-of-band evidence record. |

#### `drift_status`

`drift_status` MUST be one of the following closed set of string values:

- `none` — no drift relative to the approved tool surface was evidenced.
- `observed` — a change relative to the approved surface was evidenced, without
  a determination that it is policy-relevant.
- `confirmed` — a policy-relevant change relative to the approved surface was
  evidenced.

A consumer that does not recognize a `drift_status` value MUST treat the field
as if absent (no claim made) rather than inferring a default.

> `observed` is used in preference to "suspected": it asserts what the runtime
> has evidence for, without asserting intent. *(Non-normative.)*

#### `severity`

`severity` MUST be one of the following closed set of string values, in
non-decreasing order of severity:

- `info`
- `low`
- `medium`
- `high`

`severity` carries the runtime's categorical assessment only. Numeric scores,
if any, are out of scope for this extension and MUST NOT be carried in the
canonical extension body.

#### `quarantine_decision`

`quarantine_decision` MUST be one of the following closed set of string values:

- `release` — the event was permitted to proceed.
- `hold` — the event was held pending review.
- `quarantine` — the event was quarantined.

#### `policy_id`

`policy_id` MUST be a string identifying the policy that produced the
disposition. It MUST be of the form `<scope>/<name>@<revision>`, where:

- `<scope>` is an emitter-qualified namespace (for example a reverse-DNS name,
  a URN, or a registered prefix) sufficient to disambiguate the policy across
  emitters;
- `<name>` identifies the policy within that scope;
- `<revision>` identifies the revision of that policy.

`policy_id` is vendor-neutral: it names a policy, not a product, an engine, or a
detection method. *(Example from the conformance fixture:
`example.org/runtime-drift@3`.)*

#### `evidence_hash`

When present, `evidence_hash` MUST be a cryptographic digest, expressed as
`<algorithm>:<hex>` (for example `sha256:<hex>`), committing to an out-of-band
evidence record that supports this disposition.

`evidence_hash` is an opaque commitment only. This profile:

- MUST NOT be interpreted as carrying or inlining the evidence itself;
- does NOT prescribe the structure, schema, or content of the referenced
  evidence record;
- does NOT require the referenced evidence to be produced by any particular
  detection method.

The base record commits to `evidence_hash` as opaque bytes and does not verify
the referenced evidence. A consumer wishing to rely on the evidence MUST resolve
and verify it out of band, against whatever schema the producer of that evidence
publishes.

> The extension body is a compact, interoperable summary of a disposition;
> `evidence_hash` optionally commits to a fuller, producer-defined supporting
> record. The mapping between the summary fields here and the contents of any
> referenced evidence record is producer-defined; this profile does not define a
> mandatory correspondence between them. *(Non-normative.)*

### Binding to the base outcome

The `runtime-security` disposition is decision evidence that informs the base
record's `outcome`; it is not an independent or competing outcome field. The
base `outcome` MUST reflect the actual enforcement result.

For the dispositions covered by this profile:

- A `confirmed` drift with `quarantine_decision: quarantine` that results in the
  event being held pending review corresponds to base `outcome: deferred`, as in
  the conformance fixture.
- A disposition that results in the event being terminally blocked corresponds
  to base `outcome: denied`.

This profile does not define base-outcome bindings for dispositions beyond those
stated above; other combinations follow the base record's outcome semantics.

> Rationale: this prevents a record whose base `outcome` is `allowed` from
> simultaneously carrying a `runtime-security` disposition of `quarantine`. The
> extension explains *why*; the base `outcome` states *what happened*.
> *(Non-normative.)*