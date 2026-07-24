# Detection Quality Evidence v1

Detection Quality Evidence gives an operator a reproducible view of how the
current Interlock revision handles a small, versioned corpus of synthetic MCP
drift, no-drift, inconclusive, and known-gap cases. It runs entirely offline and
reuses the production surface-drift classifier, metadata normalizer, observation
normalizer, and effective-permission evaluator.

This evidence is **corpus-bound** and **synthetic**. It is **not a production
false-positive rate** and is **not representative of all MCP deployments**.

## Generate the report

From the repository root, choose an output directory:

```bash
python scripts/generate_detection_quality_evidence.py --output-dir ./artifacts/detection-quality
```

The command writes these explicit paths under that directory:

- `detection-quality-evidence.v1.json` — machine-readable, strictly typed report;
- `detection-quality-evidence.v1.md` — readable report with case and test links.

If `--output-dir` is omitted, the command creates a new operating-system
temporary directory and prints both absolute output paths. It makes no network
calls and uses no production telemetry, live customer data, or live upstream
server.

The command exits nonzero when the corpus is invalid, case IDs collide, a case
has no ground-truth label, a reviewed expected Interlock decision changes, a
required metric denominator is zero, or defined high-risk sensitive-content or
unsafe-path patterns are found. This is a fail-closed sanitization boundary, not
proof that arbitrary free-form strings are non-sensitive.

## Metric semantics

The operational positive class for these confusion counts is an Interlock
`deny` or `quarantine` decision. `allow` and `monitor` are nonpositive;
`inconclusive` and `unsupported` are unscored. This definition is included here
so a monitor result is not silently reinterpreted as a high-confidence drift
detection.

- **Confirmed true positive:** labeled drift with `deny` or `quarantine`.
- **Confirmed false positive:** labeled no-drift control with `deny` or
  `quarantine`.
- **Confirmed true negative:** labeled no-drift control with `allow` or
  `monitor`.
- **Confirmed false negative / known miss:** labeled drift without `deny` or
  `quarantine`.
- **Inconclusive:** timeout, rate limit, upstream error, or another observation
  that cannot establish drift or no drift. These cases never enter precision,
  recall, or false-positive calculations.
- **Unsupported or unscored:** explicitly labeled cases outside the evaluated
  detector boundary. These also never enter confusion counts.

Corpus-bound precision is `TP / (TP + FP)`. Corpus-bound recall is
`TP / (TP + FN)`. The corpus-bound false-positive rate is `FP / (FP + TN)` and
uses only labeled no-drift controls. Each report includes the numerator and
denominator; the evidence command refuses to publish a required ratio with a
zero denominator.

## Add a sanitized operator case

Edit the versioned corpus at
`evidence/detection_quality/v1/corpus.json`. Each case must contain:

- a stable `case_id` and category;
- a supported existing `detector_path`;
- sanitized baseline and observed inputs/outcomes;
- an expected ground-truth label and reviewed expected Interlock decision;
- a rationale;
- a repository test reference and link when the case represents a documented
  blind spot.

### Evidence references must be stable

Every unresolved blind spot carries two things:

- `source_ref` — a **stable test identifier**, `path/to/test_file.py::test_name`;
- `source_url` — a plain public GitHub **file** URL, with no `#L` line anchor.

Line-number anchors are rejected by the loader. A `#L120` anchor silently slides
onto an unrelated statement the moment the referenced file is reformatted, so it
always appears to resolve while pointing at the wrong code. A test identifier
survives reformatting, and the focused suite parses each referenced file and
asserts the named test function actually exists — a check a line number cannot
support. Reference the test by name; do not reintroduce line anchors.

Use synthetic names, schemas, status codes, and outcome shapes only. Do not add
tool arguments, authorization headers, API keys, raw request/response bodies,
customer identifiers, or live captures. Adding a case changes the corpus hash;
it does not change product detection logic.

The loader recursively rejects secret-like keys and common credential forms,
Bearer and API-key values, JWT-like values, PEM private-key markers, cookie
values, `file://` URIs, Windows paths, UNC paths, and POSIX absolute paths.

Path detection is context-aware rather than anchored to the start of a string,
so ordinary prefixes do not evade it. All of these are rejected:

```text
C:\Customers\Acme\case.json      capture=C:\Customers\Acme\case.json
src:C:\Customers\Acme\case.json  fromC:\Customers\Acme\case.json
\\fileserver\share\case.json     src=\\fileserver\share\case.json
//fileserver/share/case.json     src=//fileserver/share/case.json
/secrets                         capture=/customerdata
C:Customers                      capture=C:folder/file
/etc/passwd                      capture=/etc/passwd
path:/var/lib/interlock/x.db     dump>/var/lib/secrets.db
seefile/etc/passwd               u=file:///etc/shadow
```

Complete `http://` and `https://` URLs are parsed and validated as URLs, so a
URL path component is not mistaken for a filesystem path. The exception is
narrow and applies to the **path component only**:

- **Allowed** — the path segment of a public web URL:
  `https://github.com/org/repo/blob/main/tests/test_x.py`,
  `https://example.com/etc/passwd`, and ordinary fragments such as `#L120`.
- **Rejected** — unsafe data carried in a **query or fragment value**. Before a
  URL is set aside, its query and fragment are recursively percent-decoded to a
  bounded depth and scanned with the same credential and filesystem-path rules
  used for free text. These all fail:

```text
https://example.com/?capture=/etc/passwd
https://example.com/?capture=C:%5CCustomers%5CAcme%5Ccase.json
https://example.com/?capture=%2Fvar%2Flib%2Fcustomer.db
https://example.com/?capture=%252Fvar%252Flib%252Fcustomer.db
https://example.com/?capture=%25252Fsecrets
https://example.com/#capture=%25252FC%253ACustomers
https://example.com/?next=file%3A%2F%2F%2Fetc%2Fshadow
https://example.com/?token=Bearer%20abc123def456
https://example.com/ok#access_token=eyJh.eyJz.dozj
https://example.com/ok#/etc/passwd
```

URLs carrying `user:pass@` userinfo are rejected. A string is not exempted
merely because it contains `https://`: each URL token is validated on its own
and only that token is set aside, so
`https://github.com/... see capture=/etc/passwd` is still rejected, an
incomplete fragment such as `https://` is not treated as a URL at all, and a
Windows or UNC path glued onto a URL is scanned rather than absorbed into it.
`file://` is forbidden everywhere and is never treated as a strippable URL.
The same validation applies to the dedicated `source_url` field.

These are defined high-risk patterns; they do not prove arbitrary text is safe.

The report records the exact Git commit. If tracked files differ from `HEAD`, it
also records `dirty_diff_sha256`, a SHA-256 digest of the complete tracked diff
without embedding that diff. Untracked files are intentionally not represented
unless they are deliberately included in the tracked diff.

Run the focused integrity suite after any corpus change:

```bash
python -m pytest tests/test_detection_quality_evidence.py -q
```

## What this does not prove

The report does not measure production traffic, prevalence, customer-specific
policy quality, all MCP schemas, all server behaviors, or end-to-end production
readiness. A passing report proves only that the named synthetic corpus produced
its reviewed expected decisions at the recorded Interlock revision. Unresolved
blind spots remain visible as case IDs linked to their adversarial test or
strict `xfail`; they are not converted into passing detections.
