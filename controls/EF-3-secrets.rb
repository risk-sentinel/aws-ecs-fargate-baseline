# encoding: UTF-8
#
# EF-3.x — Secrets wiring (n secrets per container).
# NIST CM-2/IA-5/SC-28/AC-3; SRG-CTR; CIS AWS Compute C-3.6; cross-profile
# with aws-secrets-baseline (the secret store itself is hardened there).

control "EF-3.1" do
  title "Secrets must not be passed as plaintext environment variables"
  desc "Secret-shaped values in container environment[] are visible in the "\
       "task definition. Use the secrets[] block with Secrets Manager / SSM "\
       "instead (CM-2/IA-5)."
  tag severity:              "high"
  tag nist:                  ["IA-5 (1) (e)", "CM-6 b"]
  tag cci:                   ["CCI-000389", "CCI-001045", "CCI-001315"]
  tag local_number:          "EF-3.1"
  tag srg:                   "SRG-APP-000038-CTR-000105"
  tag fsbp:                  "ECS.8"
  tag cis_source:            "CIS AWS Compute v1.1.0 C-3.6"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  tds = fargate_task_definition_arns
  impact 0.7
  impact 0.0 if tds.empty?
  only_if("No Fargate task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "Secret-shaped env vars in #{td.family}:#{td.revision}" do
      subject { td.containers_with_secret_shaped_env }
      it { should be_empty }
    end
  end
end

control "EF-3.2" do
  title "Injected secrets must reference Secrets Manager / SSM ARNs"
  desc "Every secrets[].valueFrom must be an ARN (Secrets Manager or SSM "\
       "Parameter Store), not an inline/plaintext value (IA-5(7)/SC-28)."
  tag severity:              "high"
  tag nist:                  ["IA-5 (7)", "SC-28"]
  tag cci:                   ["CCI-001368"]
  tag local_number:          "EF-3.2"
  tag srg:                   "SRG-APP-000038-CTR-000105"
  tag nist_800_190:          "3.4"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  tds = fargate_task_definition_arns
  impact 0.7
  impact 0.0 if tds.empty?
  only_if("No Fargate task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "Non-ARN secret references in #{td.family}:#{td.revision}" do
      subject { td.containers_with_non_arn_secrets }
      it { should be_empty }
    end
  end
end
