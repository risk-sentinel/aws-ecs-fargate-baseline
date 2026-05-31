# Full-view ECS service resource — wraps `describe_services` with
# `include: ['TAGS']`. Extends the cis-aws-compute version with the
# network-config detail and resilience/exec fields the Fargate baseline
# needs: awsvpc subnets + security groups, enableExecuteCommand,
# deployment circuit breaker, and min-healthy-percent.
#
# Instantiation:
#   aws_ecs_service_full(cluster: 'prod-sparc', service: 'api')

class AwsEcsServiceFull < AwsResourceBase
  name "aws_ecs_service_full"
  desc "ECS service with tags, network-config, exec, and resilience fields."

  example "
    describe aws_ecs_service_full(cluster: 'prod-sparc', service: 'api') do
      its('platform_version') { should eq 'LATEST' }
      its('assign_public_ip') { should eq 'DISABLED' }
    end
  "

  attr_reader :service_arn, :service_name, :cluster_arn,
              :launch_type, :platform_version, :assign_public_ip,
              :subnets, :security_groups,
              :enable_execute_command,
              :circuit_breaker_enable, :circuit_breaker_rollback,
              :minimum_healthy_percent, :task_definition,
              :tags, :tag_keys

  def initialize(opts = {})
    super(opts)
    validate_parameters(required: %i[cluster service])
    @display_name = opts[:service]

    catch_aws_errors do
      resp = @aws.ecs_client.describe_services(
        cluster:  opts[:cluster],
        services: [opts[:service]],
        include:  ["TAGS"],
      )
      s = resp.services.first
      return if s.nil?

      @service_arn      = s.service_arn
      @service_name     = s.service_name
      @cluster_arn      = s.cluster_arn
      @launch_type      = s.launch_type
      @platform_version = s.platform_version
      @task_definition  = s.task_definition
      @enable_execute_command = s.enable_execute_command

      awsvpc = s.network_configuration&.awsvpc_configuration
      @assign_public_ip = awsvpc&.assign_public_ip
      @subnets          = Array(awsvpc&.subnets)
      @security_groups  = Array(awsvpc&.security_groups)

      dc  = s.deployment_configuration
      cb  = dc&.deployment_circuit_breaker
      @circuit_breaker_enable   = cb&.enable
      @circuit_breaker_rollback = cb&.rollback
      @minimum_healthy_percent  = dc&.minimum_healthy_percent

      @tags     = (s.tags || []).map { |t| { key: t.key, value: t.value } }
      @tag_keys = @tags.map { |t| t[:key] }
    end
  end

  def exists?
    !@service_arn.nil?
  end

  def fargate?
    @launch_type == "FARGATE"
  end

  def exec_enabled?
    @enable_execute_command == true
  end

  def circuit_breaker_enabled?
    @circuit_breaker_enable == true
  end

  def resource_id
    @service_arn || @display_name
  end

  def to_s
    "AWS ECS service (full) #{@display_name}"
  end
end
