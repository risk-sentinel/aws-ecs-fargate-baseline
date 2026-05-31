# Full-view ECS cluster resource — wraps `describe_clusters` with
# `include: [CONFIGURATIONS, SETTINGS, TAGS]` so controls can inspect
# fields the vendored `aws_ecs_cluster` doesn't expose:
#
#   - container_insights (CIS 3.9)
#   - fargate_ephemeral_storage_kms_key_id (CIS 11.1)
#   - execute_command_configuration logging + KMS (EF-7.2)
#   - tag_keys (CIS 3.11)
#
# Instantiation: `aws_ecs_cluster_full(cluster: 'prod-sparc')` (name or ARN).

class AwsEcsClusterFull < AwsResourceBase
  name "aws_ecs_cluster_full"
  desc "ECS cluster with configuration, settings, and tags included."

  example "
    describe aws_ecs_cluster_full(cluster: 'prod-sparc') do
      its('container_insights') { should eq 'enabled' }
      its('fargate_ephemeral_storage_kms_key_id') { should_not be_nil }
    end
  "

  attr_reader :cluster_arn, :cluster_name, :status,
              :container_insights, :fargate_ephemeral_storage_kms_key_id,
              :exec_logging, :exec_kms_key_id,
              :exec_cw_log_group, :exec_s3_bucket,
              :tags, :tag_keys

  def initialize(opts = {})
    opts = { cluster: opts } if opts.is_a?(String)
    super(opts)
    validate_parameters(required: [:cluster])
    @display_name = opts[:cluster]

    catch_aws_errors do
      resp = @aws.ecs_client.describe_clusters(
        clusters: [opts[:cluster]],
        include:  %w[CONFIGURATIONS SETTINGS TAGS],
      )
      c = resp.clusters.first
      return if c.nil?

      @cluster_arn  = c.cluster_arn
      @cluster_name = c.cluster_name
      @status       = c.status

      ci_setting = (c.settings || []).find { |s| s.name == "containerInsights" }
      @container_insights = ci_setting&.value

      msc = c.configuration&.managed_storage_configuration
      @fargate_ephemeral_storage_kms_key_id = msc&.fargate_ephemeral_storage_kms_key_id

      ecc = c.configuration&.execute_command_configuration
      @exec_logging    = ecc&.logging   # NONE | DEFAULT | OVERRIDE
      @exec_kms_key_id = ecc&.kms_key_id
      lc = ecc&.log_configuration
      @exec_cw_log_group = lc&.cloud_watch_log_group_name
      @exec_s3_bucket    = lc&.s3_bucket_name

      @tags     = (c.tags || []).map { |t| { key: t.key, value: t.value } }
      @tag_keys = @tags.map { |t| t[:key] }
    end
  end

  def exists?
    !@cluster_arn.nil?
  end

  def container_insights_enabled?
    %w[enabled enhanced].include?(@container_insights)
  end

  def fargate_ephemeral_storage_cmk_configured?
    !@fargate_ephemeral_storage_kms_key_id.nil? && !@fargate_ephemeral_storage_kms_key_id.empty?
  end

  # ECS Exec sessions are audited when the cluster's executeCommandConfiguration
  # ships logs to CloudWatch Logs or S3 (logging=OVERRIDE with a destination).
  # logging=DEFAULT sends only to the awslogs driver if the task defines one,
  # which is not a guaranteed audit destination, so we require OVERRIDE.
  def exec_logging_configured?
    @exec_logging == "OVERRIDE" &&
      (!@exec_cw_log_group.to_s.empty? || !@exec_s3_bucket.to_s.empty?)
  end

  def exec_kms_configured?
    !@exec_kms_key_id.to_s.empty?
  end

  def resource_id
    @cluster_arn || @display_name
  end

  def to_s
    "AWS ECS cluster (full) #{@display_name}"
  end
end
