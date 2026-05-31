# encoding: UTF-8
#
# EF-8.x — Logging / monitoring / cluster / resilience.
# NIST AU-2/AU-12/AU-6(3)/CM-8/SI-13/CP-10; CIS AWS Compute C-3.7/3.9/3.10-12.

control "EF-8.1" do
  title "Every container must declare a log configuration"
  desc "logConfiguration must be set on each container so task output is "\
       "captured for audit (AU-2/AU-12)."
  tag severity:              "medium"
  tag nist:                  ["AU-2 a", "AU-12 a"]
  tag cci:                   ["CCI-000011", "CCI-000123"]
  tag local_number:          "EF-8.1"
  tag srg:                   "SRG-APP-000510-CTR-001330"
  tag fsbp:                  "ECS.9"
  tag cis_source:            "CIS AWS Compute v1.1.0 C-3.7"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  tds = fargate_task_definition_arns
  impact 0.5
  impact 0.0 if tds.empty?
  only_if("No Fargate task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "Containers missing logging in #{td.family}:#{td.revision}" do
      subject { td.containers_missing_logging }
      it { should be_empty }
    end
  end
end

control "EF-8.3" do
  title "Clusters must enable Container Insights"
  desc "Container Insights collects metrics/logs needed for monitoring and "\
       "incident response (AU-6(3)/CA-7)."
  tag severity:              "medium"
  tag nist:                  ["AU-6 (3)"]
  tag cci:                   ["CCI-000130", "CCI-000766"]
  tag local_number:          "EF-8.3"
  tag fsbp:                  "ECS.12"
  tag cis_source:            "CIS AWS Compute v1.1.0 C-3.9"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  clusters = ecs_cluster_arns
  impact 0.5
  impact 0.0 if clusters.empty?
  only_if("No ECS clusters in scope") { !clusters.empty? }

  clusters.each do |c|
    describe "Container Insights for cluster #{c.split('/').last}" do
      subject { aws_ecs_cluster_full(cluster: c).container_insights_enabled? }
      it { should eq true }
    end
  end
end

control "EF-8.4" do
  title "Services, clusters, and task definitions must carry required tags"
  desc "Required governance tags (required_tag_keys) must be present for "\
       "inventory and ABAC (CM-8). Empty input = require at least one tag."
  tag severity:              "low"
  tag nist:                  ["CM-8 a 1"]
  tag cci:                   ["CCI-000389"]
  tag local_number:          "EF-8.4"
  tag fsbp:                  "ECS.13/14/15"
  tag cis_source:            "CIS AWS Compute v1.1.0 C-3.10/3.11/3.12"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  required = input("required_tag_keys")
  keys = ecs_service_keys
  clusters = ecs_cluster_arns
  tds = fargate_task_definition_arns
  applicable = !(keys.empty? && clusters.empty? && tds.empty?)
  impact 0.3
  impact 0.0 unless applicable
  only_if("No ECS resources in scope") { applicable }

  check = lambda do |label, present_keys|
    describe "Tags for #{label}" do
      subject { present_keys }
      if required.empty?
        it("must have at least one tag") { expect(present_keys).not_to be_empty }
      else
        it("must include #{required.join(', ')}") { expect(present_keys).to include(*required) }
      end
    end
  end

  clusters.each { |c| check.call("cluster #{c.split('/').last}", aws_ecs_cluster_full(cluster: c).tag_keys) }
  keys.each do |k|
    svc = aws_ecs_service_full(cluster: k[:cluster], service: k[:service])
    check.call("service #{svc.service_name}", svc.tag_keys)
  end
  tds.each do |a|
    td = aws_ecs_task_definition_full(task_definition: a)
    check.call("task def #{td.family}:#{td.revision}", td.tag_keys)
  end
end

control "EF-8.5" do
  title "Services should enable the deployment circuit breaker"
  desc "The deployment circuit breaker auto-rolls-back failed deployments, "\
       "supporting availability (SI-13/CP-10)."
  tag severity:              "low"
  tag nist:                  ["SI-13"]
  tag cci:                   ["CCI-002385"]
  tag local_number:          "EF-8.5"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  keys = ecs_service_keys
  impact 0.3
  impact 0.0 if keys.empty?
  only_if("No ECS services in scope") { !keys.empty? }

  keys.each do |k|
    svc = aws_ecs_service_full(cluster: k[:cluster], service: k[:service])
    next unless svc.fargate?

    describe "Deployment circuit breaker for service #{svc.service_name}" do
      subject { svc.circuit_breaker_enabled? }
      it { should eq true }
    end
  end
end
