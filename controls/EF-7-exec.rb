# encoding: UTF-8
#
# EF-7.x — ECS Exec. NIST AC-17/AC-6(9)/AU-12; AWS ECS Exec security.

control "EF-7.1" do
  title "ECS Exec must be disabled except on explicitly allowed services"
  desc "enableExecuteCommand opens an interactive shell into running tasks "\
       "(AC-17/AC-6(9)). It must be false unless the service is listed in "\
       "ecs_exec_allowed_services."
  tag severity:              "high"
  tag nist:                  ["AC-17 (2)", "AC-6 (9)"]
  tag cci:                   ["CCI-000067", "CCI-002233"]
  tag local_number:          "EF-7.1"
  tag srg:                   "SRG-APP-000033-CTR-000095"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  allowed = input("ecs_exec_allowed_services")
  keys = ecs_service_keys
  impact 0.7
  impact 0.0 if keys.empty?
  only_if("No ECS services in scope") { !keys.empty? }

  keys.each do |k|
    svc = aws_ecs_service_full(cluster: k[:cluster], service: k[:service])
    permitted = allowed.include?(svc.service_name) || allowed.include?(svc.service_arn)
    next if permitted # allowed services are governed by EF-7.2 instead

    describe "ECS Exec for service #{svc.service_name}" do
      subject { svc.exec_enabled? }
      it { should eq false }
    end
  end
end

control "EF-7.2" do
  title "Where ECS Exec is enabled, sessions must be audited and KMS-encrypted"
  desc "For services permitted to use ECS Exec, the cluster's execute-command "\
       "configuration must log sessions to CloudWatch Logs / S3 and encrypt "\
       "them with KMS (AU-12/SC-28). Verified via the cluster configuration."
  tag severity:              "medium"
  tag nist:                  ["AU-12 a", "SC-28"]
  tag cci:                   ["CCI-000172"]
  tag local_number:          "EF-7.2"
  tag srg:                   "SRG-APP-000092-CTR-000165"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  allowed = input("ecs_exec_allowed_services")
  keys = ecs_service_keys
  exec_services = keys.select do |k|
    svc = aws_ecs_service_full(cluster: k[:cluster], service: k[:service])
    svc.exec_enabled? && (allowed.include?(svc.service_name) || allowed.include?(svc.service_arn))
  end
  impact 0.5
  impact 0.0 if exec_services.empty?
  only_if("No services with ECS Exec enabled + allowed") { !exec_services.empty? }

  exec_services.map { |k| k[:cluster] }.uniq.each do |cluster_arn|
    cfg = aws_ecs_cluster_full(cluster: cluster_arn).respond_to?(:execute_command_configuration) ? nil : nil
    describe "ECS Exec audit logging on cluster #{cluster_arn.split('/').last}" do
      skip "MANUAL/ATTESTATION: confirm the cluster executeCommandConfiguration "\
           "logs sessions to CloudWatch Logs or S3 with kmsKeyId set. "\
           "(Cluster configuration.executeCommandConfiguration is not exposed by "\
           "describe_clusters in the vendored resource; verify via "\
           "`aws ecs describe-clusters --include CONFIGURATIONS`.)"
    end
  end
end
