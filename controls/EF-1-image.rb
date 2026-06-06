# encoding: UTF-8
#
# EF-1.x — Image supply chain (1:n images per task definition).
# NIST CM-2(2)/CM-8/CM-7/SI-7/RA-5; SRG-CTR; FSBP; 800-190 §4.1.

control "EF-1.1" do
  title "Container images must be pinned by digest (not a mutable tag)"
  desc "Images referenced by mutable tag (or :latest) can change underneath a "\
       "deployment. Pin by @sha256 digest for immutable, verifiable provenance."
  tag severity:              "medium"
  tag nist:                  ["CM-2 (2)", "CM-8 a 1"]
  tag cci:                   ["CCI-000366"]
  tag local_number:          "EF-1.1"
  tag srg:                   "SRG-APP-000131-CTR-000285"
  tag nist_800_190:          "4.1"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  require_pin = input("require_image_digest_pinning")
  tds = fargate_task_definition_arns
  applicable = require_pin && !tds.empty?
  impact 0.5
  impact 0.0 unless applicable
  only_if("digest pinning not required or no Fargate task defs") { applicable }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "Unpinned images in #{td.family}:#{td.revision}" do
      subject { td.unpinned_image_containers }
      it { should be_empty }
    end
  end
end

control "EF-1.2" do
  title "Container images must come from trusted registries"
  desc "Only images from approved registries (private ECR or vetted sources) "\
       "may be deployed. Fails closed when trusted_image_registries is empty."
  tag severity:              "high"
  tag nist:                  ["CM-7 a", "SI-7 a"]
  tag cci:                   ["CCI-000381", "CCI-000865"]
  tag local_number:          "EF-1.2"
  tag srg:                   "SRG-APP-000141-CTR-000320"
  tag fsbp:                  "n/a"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  trusted = input("trusted_image_registries")
  tds = fargate_task_definition_arns
  impact 0.7
  impact 0.0 if tds.empty?
  only_if("No Fargate task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "Untrusted images in #{td.family}:#{td.revision}" do
      subject { td.untrusted_image_containers(trusted) }
      it { should be_empty }
    end
  end
end

control "EF-1.3" do
  title "ECR repositories backing task images must have scan-on-push enabled"
  desc "Image vulnerability scanning must run automatically on push so newly "\
       "introduced CVEs are detected (RA-5)."
  tag severity:              "medium"
  tag nist:                  ["RA-5 a"]
  tag cci:                   ["CCI-001312", "CCI-002605"]
  tag local_number:          "EF-1.3"
  tag srg:                   "SRG-APP-000456-CTR-001125"
  tag fsbp:                  "ECR.1"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  repos = ecr_repos_in_scope
  impact 0.5
  impact 0.0 if repos.empty?
  only_if("No in-account ECR repositories backing Fargate task images") { !repos.empty? }

  repos.each do |repo|
    describe aws_ecr_repository(repository_name: repo) do
      its("image_scanning_configuration") { should_not be_nil }
      its("scan_on_push") { should eq true }
    end
  end
end

control "EF-1.4" do
  title "ECR repositories must enforce image tag immutability"
  desc "Immutable tags prevent an existing tag from being overwritten with a "\
       "different image, preserving supply-chain integrity (CM-5(6)/SI-7)."
  tag severity:              "medium"
  tag nist:                  ["CM-5 (6)", "SI-7 a"]
  tag cci:                   ["CCI-001749"]
  tag local_number:          "EF-1.4"
  tag srg:                   "SRG-APP-000131-CTR-000285"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  repos = ecr_repos_in_scope
  impact 0.5
  impact 0.0 if repos.empty?
  only_if("No in-account ECR repositories in scope") { !repos.empty? }

  repos.each do |repo|
    describe aws_ecr_repository(repository_name: repo) do
      its("image_tag_mutability") { should eq "IMMUTABLE" }
    end
  end
end

control "EF-1.7" do
  title "Task images must not carry findings above the tolerated severity"
  desc "Images with unremediated findings at or above max_image_finding_severity "\
       "must not be deployed (RA-5/SI-2). Requires ECR scan results to exist "\
       "(see EF-1.3)."
  tag severity:              "high"
  tag nist:                  ["RA-5 a", "SI-2 a"]
  tag cci:                   ["CCI-001312"]
  tag local_number:          "EF-1.7"
  tag srg:                   "SRG-APP-000414-CTR-001010"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  rank = %w[INFORMATIONAL LOW MEDIUM HIGH CRITICAL]
  ceiling = input("max_image_finding_severity").to_s.upcase
  ceiling_idx = rank.index(ceiling) || rank.index("HIGH")
  disallowed = rank[(ceiling_idx + 1)..] || []

  images = task_image_refs
  impact 0.7
  impact 0.0 if images.empty? || disallowed.empty?
  only_if("No resolvable ECR images, or ceiling already at CRITICAL") { !images.empty? && !disallowed.empty? }

  images.each do |ref|
    next unless ref[:repo] && ref[:digest]

    img = aws_ecr_image(repository_name: ref[:repo], image_digest: ref[:digest])
    counts = (img.image_scan_findings && img.image_scan_findings[:finding_severity_counts]) || {}
    over = disallowed.sum { |sev| counts[sev.to_sym].to_i + counts[sev].to_i }
    describe "Disallowed-severity findings (#{disallowed.join('/')}) for #{ref[:repo]}@#{ref[:digest][0, 16]}" do
      subject { over }
      it { should eq 0 }
    end
  end
end

control "EF-1.5" do
  title "Task images must be cryptographically signed"
  desc "Container images must carry a verifiable signature (e.g., cosign/notation) so "\
       "their provenance and integrity can be attested before deployment (CM-5(6)/SI-7). "\
       "Evaluated for digest-pinned task images; tag-only references are caught by EF-1.1."
  tag severity:              "high"
  tag nist:                  ["CM-5 (6)", "SI-7 a"]
  tag cci:                   ["CCI-003992"]
  tag local_number:          "EF-1.5"
  tag srg:                   "SRG-APP-000131-CTR-000285"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  images = task_image_refs
  impact 0.7
  impact 0.0 if images.empty?
  only_if("No resolvable ECR task images") { !images.empty? }

  images.each do |ref|
    next unless ref[:repo] && ref[:digest]
    describe aws_ecr_image(repository_name: ref[:repo], image_digest: ref[:digest]) do
      it { should be_signed }
    end
  end
end

control "EF-1.6" do
  title "Task images must have an attached SBOM"
  desc "Each container image must carry a Software Bill of Materials (SPDX/CycloneDX) as "\
       "an OCI referrer, so its components are inventoried for vulnerability and "\
       "supply-chain analysis (SI-7/RA-5). Evaluated for digest-pinned task images."
  tag severity:              "medium"
  tag nist:                  ["SI-7 a", "RA-5 a"]
  tag cci:                   ["CCI-003992"]
  tag local_number:          "EF-1.6"
  tag srg:                   "SRG-APP-000131-CTR-000285"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  images = task_image_refs
  impact 0.5
  impact 0.0 if images.empty?
  only_if("No resolvable ECR task images") { !images.empty? }

  images.each do |ref|
    next unless ref[:repo] && ref[:digest]
    describe aws_ecr_image(repository_name: ref[:repo], image_digest: ref[:digest]) do
      it { should have_sbom }
    end
  end
end
