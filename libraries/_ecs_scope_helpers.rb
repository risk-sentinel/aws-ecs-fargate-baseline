# encoding: UTF-8
#
# Helpers mixed into the InSpec control-eval context so controls stay terse.
#
#   fargate_task_definition_arns  -> latest-ACTIVE task defs that require FARGATE
#   ecs_service_keys              -> [{cluster:, service:}, ...]
#   ecs_cluster_arns              -> [<cluster-arn>, ...]
#   role_name_from_arn(arn)       -> trailing role name
#
# Scope is limited to Fargate: a task definition is in scope only when its
# requiresCompatibilities includes FARGATE. EC2-launch-type task defs and
# their host-level concerns are out of scope for a Fargate baseline (those
# belong to cis-aws-compute / host-OS profiles).
module EcsScopeHelpers
  def ecs_cluster_arns
    @ecs_cluster_arns ||= aws_ecs_inventory.cluster_arns
  rescue StandardError
    []
  end

  def ecs_service_keys
    @ecs_service_keys ||= aws_ecs_inventory.service_keys
  rescue StandardError
    []
  end

  def fargate_task_definition_arns
    @fargate_task_definition_arns ||= begin
      aws_ecs_inventory.latest_active_task_definition_arns.select do |arn|
        aws_ecs_task_definition_full(task_definition: arn).fargate?
      end
    rescue StandardError
      []
    end
  end

  def role_name_from_arn(arn)
    arn.to_s.split("/").last
  end

  # Image references across all Fargate task defs, parsed into
  # {repo:, digest:, registry:, raw:} where the image is an in-account ECR URI:
  #   <acct>.dkr.ecr.<region>.amazonaws.com/<repo>[@sha256:<digest>|:tag]
  # Non-ECR or unparseable images yield repo:/digest: nil.
  def task_image_refs
    @task_image_refs ||= begin
      refs = []
      fargate_task_definition_arns.each do |arn|
        aws_ecs_task_definition_full(task_definition: arn).container_images.each do |img|
          refs << parse_ecr_image(img)
        end
      end
      refs.uniq { |r| r[:raw] }
    rescue StandardError
      []
    end
  end

  # Distinct in-account ECR repository names backing Fargate task images.
  def ecr_repos_in_scope
    @ecr_repos_in_scope ||= task_image_refs.map { |r| r[:repo] }.compact.uniq
  end

  def parse_ecr_image(img)
    s = img.to_s
    out = { raw: s, repo: nil, digest: nil, registry: nil }
    # ECR registry host: <acct>.dkr.ecr.<region>.amazonaws.com(.cn)
    if s =~ %r{\A(\d+\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com(?:\.cn)?)/(.+)\z}
      out[:registry] = Regexp.last_match(1)
      remainder = Regexp.last_match(2)
      if remainder.include?("@sha256:")
        repo, digest = remainder.split("@", 2)
        out[:repo] = repo
        out[:digest] = digest
      else
        out[:repo] = remainder.split(":", 2).first
      end
    end
    out
  end
end

Inspec::Rule.include(EcsScopeHelpers)
