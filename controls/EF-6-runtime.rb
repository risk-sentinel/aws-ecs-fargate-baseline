# encoding: UTF-8
#
# EF-6.x — Runtime / isolation. NIST AC-6/CM-7/SC-39/SI-2/SC-8/SC-28.
# CIS AWS Compute C-3.1/3.3/3.8/11.1 re-expressed; SRG-CTR isolation.

control "EF-6.1" do
  title "Host-network task definitions must not allow privileged/root containers"
  desc "If a task definition uses host network mode, no container may be "\
       "privileged or run as root (defense in depth; Fargate forbids host "\
       "mode but the assertion keeps the profile portable)."
  tag severity:              "high"
  tag nist:                  ["AC-6"]
  tag cci:                   ["CCI-000056", "CCI-002113"]
  tag local_number:          "EF-6.1"
  tag srg:                   "SRG-APP-000243-CTR-000595"
  tag cis_source:            "CIS AWS Compute v1.1.0 C-3.1"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  tds = fargate_task_definition_arns.select { |a| aws_ecs_task_definition_full(task_definition: a).host_network? }
  impact 0.7
  impact 0.0 if tds.empty?
  only_if("No host-network task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "Host-network privileged/root containers in #{td.family}:#{td.revision}" do
      subject { (td.privileged_container_names + td.root_user_container_names).uniq }
      it { should be_empty }
    end
  end
end

control "EF-6.2" do
  title "Task definitions must not share the host PID namespace"
  desc "pidMode must not be 'host'; sharing the host PID namespace breaks "\
       "process isolation (CM-7/SC-39)."
  tag severity:              "medium"
  tag nist:                  ["CM-7 a", "SC-39"]
  tag cci:                   ["CCI-000364", "CCI-002110"]
  tag local_number:          "EF-6.2"
  tag srg:                   "SRG-APP-000431-CTR-001065"
  tag fsbp:                  "ECS.3"
  tag cis_source:            "CIS AWS Compute v1.1.0 C-3.3"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  tds = fargate_task_definition_arns
  impact 0.5
  impact 0.0 if tds.empty?
  only_if("No Fargate task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "pidMode for #{td.family}:#{td.revision}" do
      subject { td.pid_mode }
      it { should_not eq "host" }
    end
  end
end

control "EF-6.3" do
  title "Fargate services must run the latest platform version"
  desc "platform_version should be LATEST so security patches apply "\
       "automatically (SI-2). A pinned numeric version drifts behind."
  tag severity:              "medium"
  tag nist:                  ["SI-2 a"]
  tag cci:                   ["CCI-000865"]
  tag local_number:          "EF-6.3"
  tag srg:                   "SRG-APP-000456-CTR-001125"
  tag fsbp:                  "ECS.10"
  tag cis_source:            "CIS AWS Compute v1.1.0 C-3.8"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  keys = ecs_service_keys
  impact 0.5
  impact 0.0 if keys.empty?
  only_if("No ECS services in scope") { !keys.empty? }

  keys.each do |k|
    svc = aws_ecs_service_full(cluster: k[:cluster], service: k[:service])
    next unless svc.fargate?

    describe "Platform version for service #{svc.service_name}" do
      subject { svc.platform_version }
      it { should eq "LATEST" }
    end
  end
end

control "EF-6.5" do
  title "Clusters must encrypt Fargate ephemeral storage with a CMK"
  desc "Fargate ephemeral storage should be encrypted with a customer-managed "\
       "KMS key via the cluster's managed storage configuration (SC-28)."
  tag severity:              "medium"
  tag nist:                  ["SC-28"]
  tag cci:                   ["CCI-000051", "CCI-001199"]
  tag local_number:          "EF-6.5"
  tag cis_source:            "CIS AWS Compute v1.1.0 C-11.1"
  tag srg:                   "SRG-APP-000429-CTR-001060"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  clusters = ecs_cluster_arns
  impact 0.5
  impact 0.0 if clusters.empty?
  only_if("No ECS clusters in scope") { !clusters.empty? }

  clusters.each do |c|
    describe "Fargate ephemeral storage CMK for cluster #{c.split('/').last}" do
      subject { aws_ecs_cluster_full(cluster: c).fargate_ephemeral_storage_cmk_configured? }
      it { should eq true }
    end
  end
end

control "EF-6.6" do
  title "Task EFS volumes must enable in-transit encryption"
  desc "Any task definition that mounts an Amazon EFS volume must set "\
       "efsVolumeConfiguration.transitEncryption to ENABLED, so the NFS traffic "\
       "between the task and EFS is TLS-protected (SC-8 / SC-8(1)). This is the "\
       "task's east-west storage transit, distinct from the north-south ALB/proxy "\
       "TLS covered by EF-11/EF-12. Scoped to task defs that declare EFS volumes."
  tag severity:              "high"
  tag nist:                  ["SC-8", "SC-8 (1)", "SC-28"]
  tag cci:                   ["CCI-002418", "CCI-002421"]
  tag local_number:          "EF-6.6"
  tag srg:                   "SRG-APP-000439-CTR-001080"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  arns        = fargate_task_definition_arns
  efs_tds     = arns.select { |a| aws_ecs_task_definition_full(task_definition: a).efs_volumes? }
  impact 0.7
  impact 0.0 if efs_tds.empty?
  only_if("No Fargate task definitions mount an EFS volume") { !efs_tds.empty? }

  efs_tds.each do |arn|
    td       = aws_ecs_task_definition_full(task_definition: arn)
    offenders = td.efs_volumes_without_transit_encryption
    describe "Task #{td.family} EFS volumes with transit encryption ENABLED" do
      subject { offenders }
      it { should be_empty }
    end
  end
end
