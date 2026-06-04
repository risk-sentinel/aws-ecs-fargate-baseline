# encoding: UTF-8
#
# EF-10 — coverage gaps: customer-configurable Fargate controls that the SRG
# shared-responsibility matrix previously folded into "AWS-inherited" but which
# are in fact consumer-configurable AND API-verifiable (sparc-validate#166).
#
# exec_validated: false — the GuardDuty (v2 features API) and ECS-account-setting
# accessors are not yet exec-verified against a live account; see the resource
# headers. Validate against a real deployment before relying on a FAIL.

control "EF-10.1" do
  title "GuardDuty Runtime Monitoring must cover ECS/Fargate"
  desc  "GuardDuty Runtime Monitoring provides runtime threat detection for "\
        "Fargate tasks. It is consumer-configurable (not AWS-inherited) and must "\
        "be enabled where ECS is in use (SI-4 / AU-6)."
  tag severity:              "medium"
  tag nist:                  ["SI-4 a", "SI-4 (2)"]
  tag cci:                   ["CCI-001253", "CCI-002661"]
  tag local_number:          "EF-10.1"
  tag srg_source:            "DISA Container Platform SRG V2R4 (runtime monitoring)"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"
  tag exec_validated:        false

  clusters = ecs_cluster_arns
  impact 0.5
  impact 0.0 if clusters.empty?
  only_if("No ECS clusters in scope") { !clusters.empty? }

  describe aws_guardduty_ecs_coverage do
    it { should be_runtime_monitoring_enabled }
  end
end

control "EF-10.2" do
  title "ECS account-level Container Insights default must be enabled"
  desc  "The account-wide containerInsights default (ecs:ListAccountSettings) "\
        "ensures new clusters get monitoring even if a per-cluster setting is "\
        "missed (AU-6(3)/CA-7). Consumer-configurable, not AWS-inherited."
  tag severity:              "low"
  tag nist:                  ["AU-6 (3)", "CA-7"]
  tag cci:                   ["CCI-000130"]
  tag local_number:          "EF-10.2"
  tag srg_source:            "DISA Container Platform SRG V2R4 (orchestrator config)"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"
  tag exec_validated:        false

  clusters = ecs_cluster_arns
  impact 0.3
  impact 0.0 if clusters.empty?
  only_if("No ECS clusters in scope") { !clusters.empty? }

  describe "ECS account setting containerInsights" do
    subject { aws_ecs_account_settings.value_for("containerInsights") }
    it { should cmp "enabled" }
  end
end

control "EF-10.3" do
  title "Fargate task definitions must pin runtimePlatform"
  desc  "operatingSystemFamily + cpuArchitecture must be explicitly set so the "\
        "runtime/image expectation is deterministic across deploys (CM-6 b). "\
        "Consumer-configurable on the task definition."
  tag severity:              "low"
  tag nist:                  ["CM-6 b"]
  tag cci:                   ["CCI-000366"]
  tag local_number:          "EF-10.3"
  tag srg_source:            "DISA Container Platform SRG V2R4 (image/runtime config)"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"
  tag exec_validated:        false

  task_defs = fargate_task_definition_arns
  impact 0.3
  impact 0.0 if task_defs.empty?
  only_if("No Fargate task definitions in scope") { !task_defs.empty? }

  task_defs.each do |arn|
    describe "runtimePlatform pinned for #{arn.split('/').last}" do
      subject { aws_ecs_task_definition_full(task_definition: arn).runtime_platform_pinned? }
      it { should eq true }
    end
  end
end

control "EF-10.4" do
  title "Task base images must be current (no EOL / out-of-cadence base image)"
  desc  "Base-image OS-package currency / EOL is an image-build-pipeline concern "\
        "not assertable from the running task definition (the image digest does "\
        "not carry an EOL date). Converted to Pass-with-evidence against the "\
        "boundary's image-build / SBOM-currency record (SI-2). EF-1.7 (scan "\
        "findings) provides detective coverage of known-vulnerable packages."
  tag severity:              "medium"
  tag nist:                  ["SI-2 c"]
  tag cci:                   ["CCI-002605"]
  tag local_number:          "EF-10.4"
  tag srg_source:            "DISA Container Platform SRG V2R4 (image currency)"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "alternative"
  tag attestation_category:  "policy"
  tag exec_validated:        false

  impact 0.5

  uri = input("c_ef_10_4_attestation_uri", value: "")
  uri = attestation_uri(:boundary, "EF-10.4") if uri.to_s.empty?
  max_age_days = input("attestation_max_age_days", value: 365)

  if uri.to_s.empty?
    describe "EF-10.4 base-image currency attestation" do
      skip "attestation-required: base-image EOL / OS-package currency is an "\
           "image-build-pipeline concern. Set boundary_docs_base / "\
           "c_ef_10_4_attestation_uri to the image-build / SBOM-currency record, "\
           "or supply a CMS-pattern attestation via `saf attest apply`. EF-1.7 "\
           "gives detective coverage of known-vulnerable packages."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "EF-10.4 base-image currency attestation (#{uri})" do
      it("is reachable") { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it("exists") { expect(doc.exists?).to eq(true) }
      it("is current within #{max_age_days} days") { expect(doc.current?).to eq(true) }
    end
  end
end
