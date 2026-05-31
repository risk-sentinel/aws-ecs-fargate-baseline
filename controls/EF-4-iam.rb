# encoding: UTF-8
#
# EF-4.x — IAM task / execution roles. NIST AC-5/AC-6; SRG-CTR; 800-190 §4.5.
# Deep checks parse the role policy documents (aws_iam_role_policy_analysis).

control "EF-4.1" do
  title "Task role must be distinct from the execution role"
  desc "The execution role (image pull, log push, secret fetch) and the task "\
       "role (application AWS permissions) must be separate so the application "\
       "does not inherit infrastructure permissions (AC-5/AC-6, 800-190 §4.5)."
  tag severity:              "medium"
  tag nist:                  ["AC-5", "AC-6"]
  tag cci:                   ["CCI-002233"]
  tag local_number:          "EF-4.1"
  tag srg:                   "SRG-APP-000342-CTR-000775"
  tag nist_800_190:          "4.5"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  tds = fargate_task_definition_arns
  impact 0.5
  impact 0.0 if tds.empty?
  only_if("No Fargate task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "Role separation for #{td.family}:#{td.revision}" do
      it "must define a task role distinct from the execution role" do
        expect(td.task_role_arn).not_to be_nil
        expect(td.execution_role_arn).not_to be_nil
        expect(td.task_role_arn).not_to eq(td.execution_role_arn)
      end
    end
  end
end

control "EF-4.2" do
  title "Task role must not grant wildcard action on wildcard resource"
  desc "The task role's policies must not contain Allow statements pairing a "\
       "wildcard Action with a wildcard Resource (over-broad grant, AC-6). "\
       "Deep check parses inline + attached managed policy documents."
  tag severity:              "high"
  tag nist:                  ["AC-6"]
  tag cci:                   ["CCI-000366"]
  tag local_number:          "EF-4.2"
  tag srg:                   "SRG-APP-000033-CTR-000095"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  tds = fargate_task_definition_arns
  role_arns = tds.map { |a| aws_ecs_task_definition_full(task_definition: a).task_role_arn }.compact.uniq
  impact 0.7
  impact 0.0 if role_arns.empty?
  only_if("No task roles in scope") { !role_arns.empty? }

  role_arns.each do |role_arn|
    describe "Task role #{role_name_from_arn(role_arn)}" do
      subject { aws_iam_role_policy_analysis(role_arn: role_arn).wildcard_statements }
      it { should be_empty }
    end
  end
end

control "EF-4.3" do
  title "Execution role must not grant wildcard actions"
  desc "The execution role should be scoped to specific ECR / Secrets Manager / "\
       "CloudWatch Logs actions and resources; it must not grant any wildcard "\
       "Action (AC-6). Deep check parses the role's policy documents."
  tag severity:              "high"
  tag nist:                  ["AC-6"]
  tag cci:                   ["CCI-000366"]
  tag local_number:          "EF-4.3"
  tag srg:                   "SRG-APP-000033-CTR-000095"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  tds = fargate_task_definition_arns
  role_arns = tds.map { |a| aws_ecs_task_definition_full(task_definition: a).execution_role_arn }.compact.uniq
  impact 0.7
  impact 0.0 if role_arns.empty?
  only_if("No execution roles in scope") { !role_arns.empty? }

  role_arns.each do |role_arn|
    describe "Execution role #{role_name_from_arn(role_arn)}" do
      subject { aws_iam_role_policy_analysis(role_arn: role_arn).wildcard_action_statements }
      it { should be_empty }
    end
  end
end

control "EF-4.4" do
  title "Task definitions must not embed long-lived AWS credentials"
  desc "Static AWS access keys must never be passed via environment variables; "\
       "use the task role for AWS access instead (IA-5/AC-6)."
  tag severity:              "high"
  tag nist:                  ["IA-5 (1) (e)", "AC-6"]
  tag cci:                   ["CCI-000389"]
  tag local_number:          "EF-4.4"
  tag fsbp:                  "ECS.8"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  aws_key_pattern = /\AAWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN)\z|ECS_ENGINE_AUTH_DATA/
  tds = fargate_task_definition_arns
  impact 0.7
  impact 0.0 if tds.empty?
  only_if("No Fargate task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    offenders = []
    td.container_definitions.each do |c|
      Array(c[:environment]).each do |e|
        offenders << "#{c[:name]}:#{e[:name]}" if e[:name].to_s =~ aws_key_pattern
      end
    end
    describe "Embedded AWS credentials in #{td.family}:#{td.revision}" do
      subject { offenders }
      it { should be_empty }
    end
  end
end
