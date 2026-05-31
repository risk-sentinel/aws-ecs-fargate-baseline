# Full-view ECS task definition resource. Extends the cis-aws-compute
# version with deeper per-container introspection needed for the Fargate
# baseline's composition-level checks (1:n container definitions).
#
# Beyond the original (privileged/root/readonly-fs/logging/env/image/
# network+pid), this exposes per-container: linuxParameters.capabilities
# (drop/add), ulimits, healthCheck, secrets[].valueFrom, repositoryCredentials,
# cpu/memory, portMappings; plus task-level task_role_arn / execution_role_arn
# and requiresCompatibilities.
#
# Instantiation:
#   aws_ecs_task_definition_full(task_definition: 'arn:aws:ecs:...:...')

class AwsEcsTaskDefinitionFull < AwsResourceBase
  name "aws_ecs_task_definition_full"
  desc "ECS task definition with tags + deep container-definition introspection."

  example "
    describe aws_ecs_task_definition_full(task_definition: 'sparc-api:42') do
      its('privileged_container_names')          { should be_empty }
      its('containers_without_dropped_all_caps') { should be_empty }
    end
  "

  attr_reader :task_definition_arn, :family, :revision,
              :network_mode, :pid_mode,
              :requires_compatibilities,
              :task_role_arn, :execution_role_arn,
              :container_names, :container_images, :container_definitions,
              :tags, :tag_keys

  def initialize(opts = {})
    opts = { task_definition: opts } if opts.is_a?(String)
    super(opts)
    validate_parameters(required: [:task_definition])
    @display_name = opts[:task_definition]

    catch_aws_errors do
      resp = @aws.ecs_client.describe_task_definition(
        task_definition: opts[:task_definition],
        include:         ["TAGS"],
      )
      td = resp.task_definition
      return if td.nil?

      @task_definition_arn      = td.task_definition_arn
      @family                   = td.family
      @revision                 = td.revision
      @network_mode             = td.network_mode
      @pid_mode                 = td.pid_mode
      @requires_compatibilities = Array(td.requires_compatibilities)
      @task_role_arn            = td.task_role_arn
      @execution_role_arn       = td.execution_role_arn
      @container_definitions    = (td.container_definitions || []).map(&:to_h)

      @container_names  = @container_definitions.map { |c| c[:name] }
      @container_images = @container_definitions.map { |c| c[:image] }

      @tags     = (resp.tags || []).map { |t| { key: t.key, value: t.value } }
      @tag_keys = @tags.map { |t| t[:key] }
    end
  end

  def exists?
    !@task_definition_arn.nil?
  end

  def fargate?
    @requires_compatibilities.include?("FARGATE")
  end

  def host_network?
    @network_mode == "host"
  end

  # --- B. per-container hardening (existing) ---------------------------

  def privileged_container_names
    select_names { |c| c[:privileged] == true }
  end

  def root_user_container_names
    select_names do |c|
      u = c[:user].to_s.strip
      u.empty? || u == "root" || u == "0" || u.start_with?("root:") || u.start_with?("0:")
    end
  end

  def non_readonly_root_fs_container_names
    select_names { |c| c[:readonly_root_filesystem] != true }
  end

  def containers_missing_logging
    select_names do |c|
      log = c[:log_configuration]
      !(log && log[:log_driver] && !log[:log_driver].to_s.empty?)
    end
  end

  SECRET_SHAPED_KEY_PATTERN = /password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key/i.freeze

  def containers_with_secret_shaped_env
    offenders = []
    @container_definitions.each do |c|
      bad = Array(c[:environment]).select { |e| e[:name].to_s =~ SECRET_SHAPED_KEY_PATTERN }
      offenders.concat(bad.map { |e| "#{c[:name]}:#{e[:name]}" })
    end
    offenders
  end

  def untrusted_image_containers(trusted_registry_prefixes)
    prefixes = Array(trusted_registry_prefixes)
    return container_names.map { |n| "#{n}:(no trusted registries configured)" } if prefixes.empty?
    @container_definitions.reject do |c|
      prefixes.any? { |p| c[:image].to_s.start_with?(p) }
    end.map { |c| "#{c[:name]}:#{c[:image]}" }
  end

  # --- A. image supply chain (new) ------------------------------------

  # Image references not pinned by @sha256:... digest.
  def unpinned_image_containers
    @container_definitions.reject { |c| c[:image].to_s.include?("@sha256:") }
                          .map { |c| "#{c[:name]}:#{c[:image]}" }
  end

  # Containers pulling from a private registry without repositoryCredentials
  # backed by Secrets Manager (inline creds or none).
  def containers_with_inline_repo_credentials
    select_names do |c|
      rc = c[:repository_credentials]
      rc && rc[:credentials_parameter] && !rc[:credentials_parameter].to_s.start_with?("arn:")
    end
  end

  # --- B. deep per-container hardening (new) --------------------------

  # Containers that do not drop ALL Linux capabilities.
  def containers_without_dropped_all_caps
    select_names do |c|
      caps = c.dig(:linux_parameters, :capabilities)
      drop = Array(caps && caps[:drop]).map { |x| x.to_s.upcase }
      !drop.include?("ALL")
    end
  end

  # Containers adding capabilities beyond the allowed list.
  def containers_with_disallowed_added_caps(allowed)
    allow = Array(allowed).map { |x| x.to_s.upcase }
    offenders = []
    @container_definitions.each do |c|
      caps = c.dig(:linux_parameters, :capabilities)
      add = Array(caps && caps[:add]).map { |x| x.to_s.upcase }
      bad = add - allow
      offenders << "#{c[:name]}:#{bad.join(',')}" unless bad.empty?
    end
    offenders
  end

  # Containers granting escalated privileges (add_capabilities SYS_ADMIN, etc.)
  def containers_with_no_new_privileges_disabled
    # ECS exposes this only via linuxParameters; absence is acceptable
    # (default is no-new-privileges for Fargate). Flag explicit add of
    # dangerous caps as the observable proxy.
    select_names do |c|
      caps = c.dig(:linux_parameters, :capabilities)
      add = Array(caps && caps[:add]).map { |x| x.to_s.upcase }
      (add & %w[SYS_ADMIN SYS_PTRACE ALL]).any?
    end
  end

  def containers_without_cpu_memory_limits
    select_names do |c|
      cpu = c[:cpu].to_i
      mem = (c[:memory] || c[:memory_reservation]).to_i
      cpu <= 0 || mem <= 0
    end
  end

  def containers_without_ulimits
    select_names { |c| Array(c[:ulimits]).empty? }
  end

  def containers_without_healthcheck
    select_names do |c|
      hc = c[:health_check]
      !(hc && Array(hc[:command]).any?)
    end
  end

  # Containers binding privileged ports (<1024) on the container side.
  def containers_with_privileged_ports
    offenders = []
    @container_definitions.each do |c|
      Array(c[:port_mappings]).each do |pm|
        port = pm[:container_port].to_i
        offenders << "#{c[:name]}:#{port}" if port.positive? && port < 1024
      end
    end
    offenders
  end

  # --- C. secrets wiring (new) ---------------------------------------

  # secrets[].valueFrom that are not Secrets Manager / SSM Parameter ARNs.
  def containers_with_non_arn_secrets
    offenders = []
    @container_definitions.each do |c|
      Array(c[:secrets]).each do |s|
        vf = s[:value_from].to_s
        offenders << "#{c[:name]}:#{s[:name]}" unless vf.start_with?("arn:")
      end
    end
    offenders
  end

  def secret_value_from_arns
    @container_definitions.flat_map { |c| Array(c[:secrets]).map { |s| s[:value_from].to_s } }
                          .reject(&:empty?)
  end

  def resource_id
    @task_definition_arn || @display_name
  end

  def to_s
    "AWS ECS task definition (full) #{@display_name}"
  end

  private

  def select_names(&block)
    @container_definitions.select(&block).map { |c| c[:name] }
  end
end
