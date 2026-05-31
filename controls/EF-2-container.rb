# encoding: UTF-8
#
# EF-2.x — Per-container hardening (each of n containers in a task def).
# NIST AC-6/CM-7/SC-6/SI-13; SRG-CTR; CIS AWS Compute §3 (re-expressed).

control "EF-2.1" do
  title "Containers must not run privileged"
  desc "A privileged container has near-host-level access, defeating container "\
       "isolation. No container definition may set privileged=true."
  tag severity:              "high"
  tag nist:                  ["AC-6"]
  tag cci:                   ["CCI-000056", "CCI-002113"]
  tag local_number:          "EF-2.1"
  tag srg:                   "SRG-APP-000243-CTR-000595"
  tag fsbp:                  "ECS.4"
  tag cis_source:            "CIS AWS Compute v1.1.0 C-3.4"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  tds = fargate_task_definition_arns
  impact 0.7
  impact 0.0 if tds.empty?
  only_if("No Fargate task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "Privileged containers in #{td.family}:#{td.revision}" do
      subject { td.privileged_container_names }
      it { should be_empty }
    end
  end
end

control "EF-2.2" do
  title "Containers must run as a non-root user"
  desc "Each container definition must set a non-root user. Running as root "\
       "(or leaving user unset) increases container-escape blast radius."
  tag severity:              "medium"
  tag nist:                  ["AC-6"]
  tag cci:                   ["CCI-001499"]
  tag local_number:          "EF-2.2"
  tag srg:                   "SRG-APP-000133-CTR-000290"
  tag fsbp:                  "ECS.20"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  tds = fargate_task_definition_arns
  impact 0.5
  impact 0.0 if tds.empty?
  only_if("No Fargate task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "Root-user containers in #{td.family}:#{td.revision}" do
      subject { td.root_user_container_names }
      it { should be_empty }
    end
  end
end

control "EF-2.3" do
  title "Containers must use a read-only root filesystem"
  desc "readonlyRootFilesystem=true prevents tampering with the container "\
       "filesystem at runtime (AC-6/CM-7)."
  tag severity:              "medium"
  tag nist:                  ["AC-6", "CM-7 a"]
  tag cci:                   ["CCI-000364", "CCI-002110"]
  tag local_number:          "EF-2.3"
  tag srg:                   "SRG-APP-000133-CTR-000295"
  tag fsbp:                  "ECS.5"
  tag cis_source:            "CIS AWS Compute v1.1.0 C-3.5"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  tds = fargate_task_definition_arns
  impact 0.5
  impact 0.0 if tds.empty?
  only_if("No Fargate task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "Writable-root-fs containers in #{td.family}:#{td.revision}" do
      subject { td.non_readonly_root_fs_container_names }
      it { should be_empty }
    end
  end
end

control "EF-2.4" do
  title "Containers must drop ALL Linux capabilities and add only an allowlist"
  desc "linuxParameters.capabilities.drop must include ALL; any added "\
       "capability must be in allowed_added_capabilities (least privilege)."
  tag severity:              "medium"
  tag nist:                  ["AC-6", "CM-7 a"]
  tag cci:                   ["CCI-002233"]
  tag local_number:          "EF-2.4"
  tag srg:                   "SRG-APP-000342-CTR-000775"
  tag nist_800_190:          "4.5.3"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  allowed = input("allowed_added_capabilities")
  tds = fargate_task_definition_arns
  impact 0.5
  impact 0.0 if tds.empty?
  only_if("No Fargate task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "Containers not dropping ALL caps in #{td.family}:#{td.revision}" do
      subject { td.containers_without_dropped_all_caps }
      it { should be_empty }
    end
    describe "Containers adding disallowed caps in #{td.family}:#{td.revision}" do
      subject { td.containers_with_disallowed_added_caps(allowed) }
      it { should be_empty }
    end
  end
end

control "EF-2.5" do
  title "Containers must not request privilege-escalating capabilities"
  desc "Containers must not add SYS_ADMIN/SYS_PTRACE/ALL, which enable "\
       "privilege escalation and host introspection (AC-6)."
  tag severity:              "high"
  tag nist:                  ["AC-6"]
  tag cci:                   ["CCI-002233"]
  tag local_number:          "EF-2.5"
  tag srg:                   "SRG-APP-000342-CTR-000775"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  tds = fargate_task_definition_arns
  impact 0.7
  impact 0.0 if tds.empty?
  only_if("No Fargate task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "Privilege-escalating containers in #{td.family}:#{td.revision}" do
      subject { td.containers_with_no_new_privileges_disabled }
      it { should be_empty }
    end
  end
end

control "EF-2.6" do
  title "Containers must declare CPU and memory limits"
  desc "Per-container cpu and memory (or memoryReservation) bound resource use, "\
       "limiting the blast radius of a noisy/compromised container (SC-6)."
  tag severity:              "low"
  tag nist:                  ["SC-6"]
  tag cci:                   ["CCI-002385"]
  tag local_number:          "EF-2.6"
  tag srg:                   "SRG-APP-000435-CTR-001070"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  tds = fargate_task_definition_arns
  impact 0.3
  impact 0.0 if tds.empty?
  only_if("No Fargate task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "Containers missing cpu/memory limits in #{td.family}:#{td.revision}" do
      subject { td.containers_without_cpu_memory_limits }
      it { should be_empty }
    end
  end
end

control "EF-2.7" do
  title "Containers should set ulimits"
  desc "ulimits (e.g. nofile) bound per-process resource consumption (SC-6)."
  tag severity:              "low"
  tag nist:                  ["SC-6"]
  tag cci:                   ["CCI-002385"]
  tag local_number:          "EF-2.7"
  tag srg:                   "SRG-APP-000435-CTR-001070"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  tds = fargate_task_definition_arns
  impact 0.3
  impact 0.0 if tds.empty?
  only_if("No Fargate task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "Containers without ulimits in #{td.family}:#{td.revision}" do
      subject { td.containers_without_ulimits }
      it { should be_empty }
    end
  end
end

control "EF-2.8" do
  title "Containers must define a health check"
  desc "A healthCheck lets ECS detect and replace unhealthy tasks, supporting "\
       "availability (SI-13/CP-10)."
  tag severity:              "low"
  tag nist:                  ["SI-13"]
  tag cci:                   ["CCI-002385"]
  tag local_number:          "EF-2.8"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  tds = fargate_task_definition_arns
  impact 0.3
  impact 0.0 if tds.empty?
  only_if("No Fargate task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "Containers without health checks in #{td.family}:#{td.revision}" do
      subject { td.containers_without_healthcheck }
      it { should be_empty }
    end
  end
end

control "EF-2.10" do
  title "Containers must not bind privileged ports (<1024)"
  desc "Container ports below 1024 require elevated privilege historically and "\
       "are disallowed by SRG-CTR; bind unprivileged ports instead (CM-7)."
  tag severity:              "low"
  tag nist:                  ["CM-7 a"]
  tag cci:                   ["CCI-000382"]
  tag local_number:          "EF-2.10"
  tag srg:                   "SRG-APP-000142-CTR-000330"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  tds = fargate_task_definition_arns
  impact 0.3
  impact 0.0 if tds.empty?
  only_if("No Fargate task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "Containers binding privileged ports in #{td.family}:#{td.revision}" do
      subject { td.containers_with_privileged_ports }
      it { should be_empty }
    end
  end
end
