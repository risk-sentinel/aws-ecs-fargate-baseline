# ECS inventory helper — returns flat iterables suited for control
# describes:
#
#   aws_ecs_inventory.cluster_arns
#     => [<cluster-arn>, ...]
#
#   aws_ecs_inventory.service_keys
#     => [{cluster: <cluster-arn>, service: <service-arn>}, ...]
#
#   aws_ecs_inventory.latest_active_task_definition_arns
#     => [<arn>, ...]  # one per family, highest revision, status=ACTIVE
#
# Why not vendored `aws_ecs_task_definitions`: it lists every revision
# of every family, which inflates iteration cost and flags old revisions
# that are no longer deployable. CIS intent is "latest active revision",
# which is what this helper returns.

class AwsEcsInventory < AwsResourceBase
  name "aws_ecs_inventory"
  desc "ECS inventory: clusters, services, latest-ACTIVE task definitions."

  example "
    describe aws_ecs_inventory do
      its('cluster_arns') { should_not be_empty }
    end
  "

  attr_reader :cluster_arns

  def initialize(opts = {})
    super(opts)
    validate_parameters
    @cluster_arns = fetch_cluster_arns
  end

  def fetch_cluster_arns
    arns = []
    token = nil
    loop do
      resp = nil
      catch_aws_errors do
        args = {}
        args[:next_token] = token if token
        resp = @aws.ecs_client.list_clusters(args)
      end
      break unless resp
      arns.concat(resp.cluster_arns)
      token = resp.next_token
      break unless token
    end
    arns
  end

  def service_keys
    @service_keys ||= @cluster_arns.flat_map do |cluster_arn|
      arns = []
      token = nil
      loop do
        resp = nil
        catch_aws_errors do
          args = { cluster: cluster_arn }
          args[:next_token] = token if token
          resp = @aws.ecs_client.list_services(args)
        end
        break unless resp
        arns.concat(resp.service_arns)
        token = resp.next_token
        break unless token
      end
      arns.map { |s| { cluster: cluster_arn, service: s } }
    end
  end

  def latest_active_task_definition_arns
    @latest_active_task_definition_arns ||= begin
      families = []
      token = nil
      loop do
        resp = nil
        catch_aws_errors do
          args = { status: "ACTIVE" }
          args[:next_token] = token if token
          resp = @aws.ecs_client.list_task_definition_families(args)
        end
        break unless resp
        families.concat(resp.families)
        token = resp.next_token
        break unless token
      end
      families.map do |family|
        resp = nil
        catch_aws_errors do
          resp = @aws.ecs_client.list_task_definitions(
            family_prefix: family,
            status:        "ACTIVE",
            sort:          "DESC",
            max_results:   1,
          )
        end
        resp&.task_definition_arns&.first
      end.compact
    end
  end

  def to_s
    "AWS ECS inventory (clusters=#{@cluster_arns.size})"
  end
end
