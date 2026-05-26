# Interlock Compliance Posture

Interlock is pre-certification. Interlock does not currently claim SOC 2, ISO 27001, HIPAA, GDPR certification, or a signed Data Processing Addendum as its own product/company compliance program.

This page exists so buyers can understand what is available for a design-partner review without confusing infrastructure vendor attestations with Interlock's own certifications.

## Interlock Status

| Item | Current status |
|---|---|
| Interlock DPA | Not yet available. Can be prepared during legal/security review for pilots. |
| Transfer Impact Assessment | Not yet available as an Interlock document. Vendor TIAs may be used where applicable. |
| SOC 2 Type 2 | Not certified yet. Future target if enterprise demand validates it. |
| ISO 27001 | Not certified yet. Future target if enterprise demand validates it. |
| HIPAA | Not HIPAA-ready as a product claim. Requires a dedicated HIPAA deployment review, BAA chain, logging, retention, and customer configuration. |
| Standard Security Questionnaire | Draftable from existing security, architecture, production-readiness, and threat-model docs. |

## Available Today For Security Review

Interlock can provide these artifacts for a controlled pilot or design-partner review:

- security architecture overview
- threat model
- data flow diagram
- subprocessors and infrastructure provider list
- production hardening guide
- secret rotation runbook
- retention policy controls
- admin audit evidence
- CI/build verification summary
- MCP gateway and RBAC control descriptions

## Vendor Compliance References

If deployed on managed infrastructure, vendor compliance documents can support procurement review. These are vendor attestations, not Interlock certifications.

| Vendor | Relevant documents / status | Notes |
|---|---|---|
| Supabase | SOC 2 Type 2, ISO 27001, DPA, TIA, HIPAA add-on depending on plan and configuration | Used for Postgres/Auth in the current pilot path. Access to reports may depend on Supabase plan. |
| Vercel | DPA, SOC 2 Type 2, ISO 27001, HIPAA support depending on plan and configuration | Candidate for dashboard hosting. |
| Render | SOC 2 Type 2, ISO 27001, GDPR/DPA depending on plan and configuration | Candidate for backend hosting. |

Reference links:

- Supabase Security: https://supabase.com/docs/guides/security
- Supabase SOC 2: https://supabase.com/docs/guides/security/soc-2-compliance
- Supabase HIPAA: https://supabase.com/docs/guides/security/hipaa-compliance
- Supabase DPA: https://supabase.com/downloads/docs/Supabase%2BDPA%2B260317.pdf
- Supabase TIA: https://supabase.com/downloads/docs/Supabase%2BTIA%2B250314.pdf
- Vercel Compliance: https://vercel.com/docs/security/compliance
- Vercel DPA: https://vercel.com/legal/dpa
- Render Compliance: https://render.com/docs/certifications-compliance

## Buyer-Facing Language

Use this wording in outreach or diligence:

```text
Interlock is currently pre-certification. For pilots, we can provide architecture, threat model, production hardening, retention, secret rotation, and audit evidence. Infrastructure vendor compliance documents are available from Supabase/Vercel/Render depending on the selected deployment path and plan. Interlock does not currently claim SOC 2, ISO 27001, HIPAA, or GDPR certification as its own product.
```

Avoid this wording:

```text
Interlock is SOC 2 compliant.
Interlock is ISO 27001 certified.
Interlock is HIPAA compliant.
Interlock is GDPR certified.
```

Those claims require a formal Interlock compliance program, legal review, and in some cases third-party audits or signed agreements.
