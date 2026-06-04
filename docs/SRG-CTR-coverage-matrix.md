# DISA Container Platform SRG (V2R4) — coverage matrix

The deferred inherited-vs-asserted matrix (sparc-validate#9 / #166). It answers
two questions:

1. **Why does this profile assert ~34 controls when SRG-CTR has 188 rules?**
2. **For the rules we call "AWS-inherited" — do we actually have evidence?**

## Model

The DISA Container Platform SRG models the container platform as one product
spanning **registry → runtime → orchestrator → keystore**, plus the general SRG
inheritance families (audit, identity, crypto, host OS). On **Fargate** the
runtime/orchestrator/host layers are AWS-managed, so the 188 rules split:

| Disposition | ~Count | How it's covered |
|---|---|---|
| **Asserted** (customer-configurable projection) | ~53 → **34 controls** | EF-1…EF-8 + EF-10 automated checks (deduped across SRG-CTR + CIS-Compute + FSBP, which overlap heavily) |
| **Inherited** (AWS-managed platform layers) | ~135 | **EF-9** `document_attestation(:leveraged)` against AWS's FedRAMP/DoD authorization — *freshness-checked evidence*, not prose |

So 34 ≠ incomplete — it's the boundary-responsibility subset. What changed in
#166: the ~135 inherited are no longer *trusted in prose*; **EF-9** surfaces the
AWS authorization as first-class HDF evidence, and **EF-10** pulls the
configurable items that had been mis-filed as "inherited" back into asserted.

> Granularity note: this matrix is **domain-level**, mapped to the SRG's
> component model + CCIs. A per-SV-ID (188-row) mapping requires the SRG-CTR
> V2R4 XCCDF source; tracked as a refinement. The dispositions below are
> authoritative at the domain level.

## Domain → disposition

| SRG-CTR domain | Disposition | Controls |
|---|---|---|
| Image creation / registry / provenance | **Asserted** | EF-1.1–1.7 (digest pin, trusted registry, ECR scan-on-push, tag immutability, finding severity) + EF-10.4 (base-image currency → boundary attestation) |
| Container hardening (runtime config the consumer sets) | **Asserted** | EF-2.1–2.10 (privileged, non-root, read-only fs, drop caps, no priv-esc, cpu/mem, ulimits, healthcheck, privileged ports) |
| Secrets handling | **Asserted** | EF-3.1–3.2 (no plaintext env, SM/SSM refs) |
| Platform identity — *consumer use* | **Asserted** | EF-4.1–4.4 (task≠exec role, no wildcard, no embedded creds) |
| Network exposure | **Asserted** | EF-5.1–5.5 (awsvpc, no public IP, private subnets, SG no 0.0.0.0/0) |
| Isolation / runtime posture | **Asserted** | EF-6.1–6.5 (host-net/PID, platform version, ephemeral-storage CMK) |
| Remote access (ECS Exec) | **Asserted** | EF-7.1–7.2 (disabled/audited) |
| Logging / monitoring — *consumer config* | **Asserted** | EF-8.1–8.5 + EF-10.1 (GuardDuty Runtime Monitoring) + EF-10.2 (account-level Container Insights) |
| Runtime/image determinism | **Asserted** | EF-10.3 (runtimePlatform pinned) |
| **Host OS / kernel** | **Inherited** | **EF-9.1** (`:leveraged` evidence) |
| **Container runtime engine** | **Inherited** | **EF-9.2** |
| **Orchestrator control plane** | **Inherited** | **EF-9.3** |
| **Platform identity store (IAM/STS control plane)** | **Inherited** | **EF-9.4** |
| **Platform audit infrastructure** | **Inherited** | **EF-9.5** |
| **FIPS-validated crypto modules** | **Inherited** | **EF-9.6** |

## Evidence model for inherited (EF-9)

Each EF-9 control resolves `attestation_uri(:leveraged, 'aws-fargate-fedramp')`
(override: `inherited_evidence_uri`) and asserts the AWS authorization manifest
**exists + is current**. Unconfigured → **Skip** (never a vacuous pass). So
"AWS implemented it" becomes a freshness-checked artifact in HDF, backed by the
consumer's pull of AWS's FedRAMP High / DoD SRG / SOC 2 evidence.

## Gaps closed (EF-10) — previously mis-filed as inherited

| Control | What it verifies | Mechanism |
|---|---|---|
| EF-10.1 | GuardDuty Runtime Monitoring covers ECS/Fargate | `aws_guardduty_ecs_coverage` (escape-hatch; `exec_validated:false`) |
| EF-10.2 | Account-level Container Insights default | `aws_ecs_account_settings` (`ListAccountSettings`) |
| EF-10.3 | Task defs pin `runtimePlatform` | `aws_ecs_task_definition_full#runtime_platform_pinned?` |
| EF-10.4 | Base-image OS-package currency / EOL | boundary `document_attestation` (image-build/SBOM record; EF-1.7 gives detective coverage) |
