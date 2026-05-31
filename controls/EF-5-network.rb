# encoding: UTF-8
#
# EF-5.x — Network. NIST SC-7; SRG-CTR SRG-APP-000039 (segmentation);
# CIS AWS Compute C-3.2. Deep checks resolve route tables + SG rules.

control "EF-5.1" do
  title "Task definitions must use awsvpc network mode"
  desc "Fargate requires awsvpc; asserting it here keeps task-level network "\
       "isolation explicit and portable to non-Fargate consumers (SC-7)."
  tag severity:              "medium"
  tag nist:                  ["SC-7 a"]
  tag cci:                   ["CCI-001097"]
  tag local_number:          "EF-5.1"
  tag srg:                   "SRG-APP-000039-CTR-000110"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  tds = fargate_task_definition_arns
  impact 0.5
  impact 0.0 if tds.empty?
  only_if("No Fargate task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "Network mode for #{td.family}:#{td.revision}" do
      subject { td.network_mode }
      it { should eq "awsvpc" }
    end
  end
end

control "EF-5.2" do
  title "Services must not auto-assign public IPs"
  desc "assignPublicIp must be DISABLED so tasks are not directly reachable "\
       "from the internet (SC-7)."
  tag severity:              "high"
  tag nist:                  ["SC-7 a", "AC-3"]
  tag cci:                   ["CCI-000051", "CCI-000213"]
  tag local_number:          "EF-5.2"
  tag srg:                   "SRG-APP-000039-CTR-000110"
  tag fsbp:                  "ECS.2"
  tag cis_source:            "CIS AWS Compute v1.1.0 C-3.2"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  keys = ecs_service_keys
  impact 0.7
  impact 0.0 if keys.empty?
  only_if("No ECS services in scope") { !keys.empty? }

  keys.each do |k|
    svc = aws_ecs_service_full(cluster: k[:cluster], service: k[:service])
    next unless svc.fargate?

    describe "assignPublicIp for service #{svc.service_name}" do
      subject { svc.assign_public_ip }
      it { should eq "DISABLED" }
    end
  end
end

control "EF-5.4" do
  title "Service tasks must run in private subnets"
  desc "Each subnet a Fargate service launches into must be private (no default "\
       "route to an internet gateway), keeping tasks off the public internet "\
       "(SC-7). Deep check resolves the subnet route tables."
  tag severity:              "high"
  tag nist:                  ["SC-7 a"]
  tag cci:                   ["CCI-001097"]
  tag local_number:          "EF-5.4"
  tag srg:                   "SRG-APP-000039-CTR-000110"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  keys = ecs_service_keys
  impact 0.7
  impact 0.0 if keys.empty?
  only_if("No ECS services in scope") { !keys.empty? }

  keys.each do |k|
    svc = aws_ecs_service_full(cluster: k[:cluster], service: k[:service])
    next unless svc.fargate?

    svc.subnets.each do |subnet_id|
      describe "Subnet #{subnet_id} (service #{svc.service_name}) routing" do
        subject { aws_subnet_routing(subnet_id: subnet_id) }
        it "must not have a default route to an internet gateway" do
          expect(aws_subnet_routing(subnet_id: subnet_id).internet_gateway_route?).to eq(false)
        end
      end
    end
  end
end

control "EF-5.5" do
  title "Service security groups must not allow 0.0.0.0/0 ingress"
  desc "The security groups attached to a Fargate service must not permit "\
       "unrestricted inbound access from the internet (SC-7(3)). Deep check "\
       "resolves each SG's ingress rules."
  tag severity:              "high"
  tag nist:                  ["SC-7 a"]
  tag cci:                   ["CCI-001097"]
  tag local_number:          "EF-5.5"
  tag srg:                   "SRG-APP-000142-CTR-000325"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  keys = ecs_service_keys
  impact 0.7
  impact 0.0 if keys.empty?
  only_if("No ECS services in scope") { !keys.empty? }

  keys.each do |k|
    svc = aws_ecs_service_full(cluster: k[:cluster], service: k[:service])
    next unless svc.fargate?

    svc.security_groups.each do |sg_id|
      describe "Security group #{sg_id} (service #{svc.service_name})" do
        subject { aws_security_group(group_id: sg_id) }
        it { should_not allow_in(ipv4_range: "0.0.0.0/0") }
      end
    end
  end
end
