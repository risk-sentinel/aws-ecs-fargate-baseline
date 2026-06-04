# encoding: UTF-8
#
# EF-9 — AWS-inherited SRG-CTR domains, surfaced as first-class evidence.
#
# The DISA Container Platform SRG (188 rules) models the whole container product
# (host OS, runtime engine, orchestrator control plane, platform identity store,
# audit infrastructure, FIPS crypto). On Fargate those layers are AWS-managed —
# ~135 SRG rules are inherited via AWS's FedRAMP/DoD authorization. Previously
# that inheritance was asserted in README prose only (trusted, not evidenced).
#
# These controls convert that trust into HDF evidence (sparc-validate#154,#166):
# each AWS-managed SRG domain is checked for EXISTENCE + FRESHNESS of the AWS
# authorization artifact (FedRAMP/DoD package, pulled into the consumer's
# leveraged-systems store) via document_attestation against the :leveraged class.
# Unconfigured -> Skip (no vacuous pass). See docs/SRG-CTR-coverage-matrix.md.
#
# NOTE: control IDs must be string literals (InSpec's static control-ID AST
# collector calls .value on the id node) — hence explicit blocks, not a loop.

control "EF-9.1" do
  title "Fargate host OS / kernel hardening (AWS-managed)"
  desc  "The Fargate microVM host OS, kernel hardening, and patching are AWS-managed "\
        "and inherited via AWS's FedRAMP/DoD authorization. The consumer cannot "\
        "configure or query the host; evidence is the AWS authorization package."
  tag severity: "medium"
  tag nist: ["CM-6 b", "SI-2 c"]
  tag cci: ["CCI-000366", "CCI-002605"]
  tag local_number: "EF-9.1"
  tag srg_source: "DISA Container Platform SRG V2R4 (host/runtime domain, AWS-inherited)"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "inherited"
  tag inherited_from: "aws-shared-responsibility"
  tag attestation_references: ["AWS FedRAMP High", "AWS FedRAMP Moderate", "AWS DoD SRG IL4/IL5", "AWS SOC 2 Type II"]
  tag exec_validated: false
  impact 0.5

  uri = input("inherited_evidence_uri", value: "")
  uri = attestation_uri(:leveraged, "aws-fargate-fedramp", ext: "json") if uri.to_s.empty?
  max_age_days = input("leveraged_evidence_max_age_days", value: 365)

  if uri.to_s.empty?
    describe "EF-9.1 AWS-inherited host-OS evidence (no leveraged source configured)" do
      skip "inherited-from-aws: Fargate host OS/kernel is AWS-managed. Set leveraged_evidence_base / inherited_evidence_uri to AWS's pulled FedRAMP/DoD authorization manifest, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "EF-9.1 AWS authorization evidence (#{uri})" do
      it("is reachable") { expect(doc.connection_error).to be_nil, "evidence unreachable: #{doc.connection_error}" }
      it("exists") { expect(doc.exists?).to eq(true) }
      it("is current within #{max_age_days} days") { expect(doc.current?).to eq(true) }
    end
  end
end

control "EF-9.2" do
  title "Container runtime engine integrity (AWS-managed)"
  desc  "The container runtime engine on Fargate is AWS-managed; runtime isolation "\
        "and integrity are inherited via AWS authorization (SRG-CTR runtime domain)."
  tag severity: "medium"
  tag nist: ["SC-39", "SI-7"]
  tag cci: ["CCI-001084", "CCI-002696"]
  tag local_number: "EF-9.2"
  tag srg_source: "DISA Container Platform SRG V2R4 (runtime domain, AWS-inherited)"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "inherited"
  tag inherited_from: "aws-shared-responsibility"
  tag attestation_references: ["AWS FedRAMP High", "AWS DoD SRG IL4/IL5", "AWS SOC 2 Type II"]
  tag exec_validated: false
  impact 0.5

  uri = input("inherited_evidence_uri", value: "")
  uri = attestation_uri(:leveraged, "aws-fargate-fedramp", ext: "json") if uri.to_s.empty?
  max_age_days = input("leveraged_evidence_max_age_days", value: 365)

  if uri.to_s.empty?
    describe "EF-9.2 AWS-inherited runtime-engine evidence (no leveraged source configured)" do
      skip "inherited-from-aws: container runtime engine is AWS-managed on Fargate. Set leveraged_evidence_base / inherited_evidence_uri, or `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "EF-9.2 AWS authorization evidence (#{uri})" do
      it("is reachable") { expect(doc.connection_error).to be_nil, "evidence unreachable: #{doc.connection_error}" }
      it("exists") { expect(doc.exists?).to eq(true) }
      it("is current within #{max_age_days} days") { expect(doc.current?).to eq(true) }
    end
  end
end

control "EF-9.3" do
  title "ECS / Fargate orchestrator control plane (AWS-managed)"
  desc  "The ECS control plane (scheduling, API, state) is AWS-managed and inherited "\
        "via AWS authorization (SRG-CTR orchestrator domain)."
  tag severity: "medium"
  tag nist: ["AC-3", "CM-5"]
  tag cci: ["CCI-000213", "CCI-001813"]
  tag local_number: "EF-9.3"
  tag srg_source: "DISA Container Platform SRG V2R4 (orchestrator domain, AWS-inherited)"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "inherited"
  tag inherited_from: "aws-shared-responsibility"
  tag attestation_references: ["AWS FedRAMP High", "AWS DoD SRG IL4/IL5", "AWS SOC 2 Type II"]
  tag exec_validated: false
  impact 0.5

  uri = input("inherited_evidence_uri", value: "")
  uri = attestation_uri(:leveraged, "aws-fargate-fedramp", ext: "json") if uri.to_s.empty?
  max_age_days = input("leveraged_evidence_max_age_days", value: 365)

  if uri.to_s.empty?
    describe "EF-9.3 AWS-inherited control-plane evidence (no leveraged source configured)" do
      skip "inherited-from-aws: ECS/Fargate control plane is AWS-managed. Set leveraged_evidence_base / inherited_evidence_uri, or `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "EF-9.3 AWS authorization evidence (#{uri})" do
      it("is reachable") { expect(doc.connection_error).to be_nil, "evidence unreachable: #{doc.connection_error}" }
      it("exists") { expect(doc.exists?).to eq(true) }
      it("is current within #{max_age_days} days") { expect(doc.current?).to eq(true) }
    end
  end
end

control "EF-9.4" do
  title "Platform identity store (AWS IAM/STS control plane) (AWS-managed)"
  desc  "The platform identity store / token service backing task and execution "\
        "roles is AWS-managed and inherited (SRG-CTR keystore/identity domain). The "\
        "consumer's USE of it (role scoping) is asserted by EF-4."
  tag severity: "medium"
  tag nist: ["IA-2", "IA-5"]
  tag cci: ["CCI-000764", "CCI-000196"]
  tag local_number: "EF-9.4"
  tag srg_source: "DISA Container Platform SRG V2R4 (keystore/identity domain, AWS-inherited)"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "inherited"
  tag inherited_from: "aws-shared-responsibility"
  tag attestation_references: ["AWS FedRAMP High", "AWS DoD SRG IL4/IL5", "AWS SOC 2 Type II"]
  tag exec_validated: false
  impact 0.5

  uri = input("inherited_evidence_uri", value: "")
  uri = attestation_uri(:leveraged, "aws-fargate-fedramp", ext: "json") if uri.to_s.empty?
  max_age_days = input("leveraged_evidence_max_age_days", value: 365)

  if uri.to_s.empty?
    describe "EF-9.4 AWS-inherited identity-store evidence (no leveraged source configured)" do
      skip "inherited-from-aws: platform identity store (IAM/STS control plane) is AWS-managed. Set leveraged_evidence_base / inherited_evidence_uri, or `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "EF-9.4 AWS authorization evidence (#{uri})" do
      it("is reachable") { expect(doc.connection_error).to be_nil, "evidence unreachable: #{doc.connection_error}" }
      it("exists") { expect(doc.exists?).to eq(true) }
      it("is current within #{max_age_days} days") { expect(doc.current?).to eq(true) }
    end
  end
end

control "EF-9.5" do
  title "Platform audit infrastructure (AWS-managed)"
  desc  "The control-plane audit infrastructure (API/control-plane logging) is "\
        "AWS-managed and inherited (SRG-CTR audit domain). The consumer's task-level "\
        "logging is asserted by EF-8."
  tag severity: "medium"
  tag nist: ["AU-2", "AU-12"]
  tag cci: ["CCI-000169", "CCI-000172"]
  tag local_number: "EF-9.5"
  tag srg_source: "DISA Container Platform SRG V2R4 (audit domain, AWS-inherited)"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "inherited"
  tag inherited_from: "aws-shared-responsibility"
  tag attestation_references: ["AWS FedRAMP High", "AWS DoD SRG IL4/IL5", "AWS SOC 2 Type II"]
  tag exec_validated: false
  impact 0.5

  uri = input("inherited_evidence_uri", value: "")
  uri = attestation_uri(:leveraged, "aws-fargate-fedramp", ext: "json") if uri.to_s.empty?
  max_age_days = input("leveraged_evidence_max_age_days", value: 365)

  if uri.to_s.empty?
    describe "EF-9.5 AWS-inherited audit-infrastructure evidence (no leveraged source configured)" do
      skip "inherited-from-aws: control-plane audit infrastructure is AWS-managed. Set leveraged_evidence_base / inherited_evidence_uri, or `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "EF-9.5 AWS authorization evidence (#{uri})" do
      it("is reachable") { expect(doc.connection_error).to be_nil, "evidence unreachable: #{doc.connection_error}" }
      it("exists") { expect(doc.exists?).to eq(true) }
      it("is current within #{max_age_days} days") { expect(doc.current?).to eq(true) }
    end
  end
end

control "EF-9.6" do
  title "FIPS-validated cryptographic modules (AWS-provided)"
  desc  "The cryptographic modules underpinning Fargate / AWS service endpoints are "\
        "FIPS-validated by AWS and inherited (SRG-CTR crypto domain)."
  tag severity: "medium"
  tag nist: ["SC-13", "IA-7"]
  tag cci: ["CCI-002450", "CCI-000803"]
  tag local_number: "EF-9.6"
  tag srg_source: "DISA Container Platform SRG V2R4 (crypto domain, AWS-inherited)"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "inherited"
  tag inherited_from: "aws-shared-responsibility"
  tag attestation_references: ["AWS FedRAMP High", "AWS DoD SRG IL4/IL5", "AWS SOC 2 Type II"]
  tag exec_validated: false
  impact 0.5

  uri = input("inherited_evidence_uri", value: "")
  uri = attestation_uri(:leveraged, "aws-fargate-fedramp", ext: "json") if uri.to_s.empty?
  max_age_days = input("leveraged_evidence_max_age_days", value: 365)

  if uri.to_s.empty?
    describe "EF-9.6 AWS-inherited FIPS-crypto evidence (no leveraged source configured)" do
      skip "inherited-from-aws: FIPS-validated crypto modules are AWS-provided. Set leveraged_evidence_base / inherited_evidence_uri, or `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "EF-9.6 AWS authorization evidence (#{uri})" do
      it("is reachable") { expect(doc.connection_error).to be_nil, "evidence unreachable: #{doc.connection_error}" }
      it("exists") { expect(doc.exists?).to eq(true) }
      it("is current within #{max_age_days} days") { expect(doc.current?).to eq(true) }
    end
  end
end
