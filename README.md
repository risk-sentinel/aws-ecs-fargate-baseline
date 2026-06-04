# aws-ecs-fargate-baseline

Custom Tier-2 InSpec baseline for **Amazon ECS on AWS Fargate**.

No CIS Benchmark or DISA STIG exists for ECS/Fargate. This profile is
authored from first principles and anchored, per control, to:

1. **NIST SP 800-53 r5** (primary).
2. **AWS Foundational Security Best Practices** — `ECS.*` (with their
   published 800-53 r5 mappings).
3. **AWS ECS best-practices guide** (security-tasks-containers,
   security-iam, container-considerations).
4. **NIST SP 800-190** Application Container Security Guide.
5. **DISA Container Platform SRG (SRG-CTR V2R4)** — DoD-authoritative CCIs.

CCI-backed task-definition rules from **CIS AWS Compute v1.1.0** (§3 /
§11.1) are re-expressed here (`cis_source` tag) so the profile stands
alone as a complete Fargate baseline even though those controls also run
in `cis-aws-compute`.

## Deep checks (beyond presence)

| Control | Deep check |
|---|---|
| EF-1.1 | image references pinned by `@sha256` digest |
| EF-1.3/1.4/1.7 | ECR repo scan-on-push, tag-immutability, scan-finding severity counts |
| EF-2.4/2.5 | parse `linuxParameters.capabilities` drop-ALL / add-allowlist / escalation |
| EF-3.2 | `secrets[].valueFrom` are Secrets Manager / SSM ARNs |
| EF-4.2/4.3 | parse task & execution role inline + attached policy **documents** for wildcards |
| EF-5.4 | resolve subnet **route tables** — fail if default route to an IGW |
| EF-5.5 | resolve **security-group ingress** — fail on 0.0.0.0/0 |
| EF-7.1 | `enableExecuteCommand` false unless service is allowlisted |

## Shared-responsibility (Fargate)

The DISA Container Platform SRG models registry + runtime + orchestrator +
keystore as one product. In Fargate that product is **AWS-managed**, so
~135 of the SRG's 188 rules are **inherited** via AWS's FedRAMP/DoD
authorization (host OS, container runtime, control plane, identity store,
audit infrastructure, FIPS crypto modules). This profile asserts the
**customer-configurable projection**: task definitions, services,
clusters, IAM task/execution roles, network configuration, and the ECR
repositories backing task images.

The inherited layers are **no longer trusted in prose** — the **EF-9** family
surfaces AWS's FedRAMP/DoD authorization as freshness-checked HDF evidence
(`document_attestation(:leveraged)`), and the **EF-10** family pulls the
configurable items that had been mis-filed as "inherited" (GuardDuty Runtime
Monitoring, account-level Container Insights, `runtimePlatform`, base-image
currency) back into asserted. The full inherited-vs-asserted mapping is in
[`docs/SRG-CTR-coverage-matrix.md`](docs/SRG-CTR-coverage-matrix.md)
(risk-sentinel/sparc-validate#166).

## Scope

Only **Fargate** task definitions are evaluated (requiresCompatibilities
includes FARGATE). EC2-launch-type task defs and host-level concerns are
out of scope (they belong to cis-aws-compute / host-OS profiles).

## Controls (34)

`EF-1.x` image supply chain · `EF-2.x` per-container hardening ·
`EF-3.x` secrets wiring · `EF-4.x` IAM roles · `EF-5.x` network ·
`EF-6.x` runtime/isolation · `EF-7.x` ECS Exec · `EF-8.x` logging /
cluster / resilience.

## Inputs

| Input | Default | Purpose |
|---|---|---|
| `aws_partition` | `aws` | Target partition. |
| `trusted_image_registries` | `[]` | Allowed registry prefixes (EF-1.2, fails closed when empty). |
| `ecs_exec_allowed_services` | `[]` | Services permitted to enable ECS Exec (EF-7.1). |
| `required_tag_keys` | `[]` | Governance tag keys (EF-8.4). |
| `require_image_digest_pinning` | `true` | Require `@sha256` image pinning (EF-1.1). |
| `max_image_finding_severity` | `HIGH` | Highest tolerated ECR scan severity (EF-1.7). |
| `allowed_added_capabilities` | `[NET_BIND_SERVICE]` | Permitted added Linux caps (EF-2.4). |
| `scan_regions` | `[]` | Region allowlist; empty = current region. |

## Running

```bash
cinc-auditor vendor . --overwrite
cinc-auditor exec . -t aws:// --input aws_partition=aws --reporter cli json:hdf.json
```

The SPARC overlay lives in `risk-sentinel/sparc-validate` under
`overlays/aws-ecs-fargate-baseline`.

## Custom resources

- `aws_ecs_task_definition_full` — deep per-container introspection
  (capabilities, ulimits, healthCheck, secrets, repositoryCredentials,
  cpu/memory, ports) beyond the cis-aws-compute version.
- `aws_ecs_service_full` — network config (subnets/SGs),
  `enableExecuteCommand`, circuit breaker.
- `aws_iam_role_policy_analysis` — fetches + parses role policy documents
  for wildcard grants.
- `iam_policy_statement` — pure-Ruby policy-statement parser (ported from
  cis-aws-foundations #72).
