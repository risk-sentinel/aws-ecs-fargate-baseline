# encoding: UTF-8
require "aws_backend"

# aws_elbv2_inventory — enumerates Application Load Balancers (ELBv2) with their
# scheme and the FSBP-relevant load-balancer attributes (drop-invalid-headers,
# access logging, deletion protection).
#
# Why custom: the stock `aws_elbs` resource uses the CLASSIC `elb_client` and so
# does not see ALBs at all, and the stock `aws_elasticloadbalancingv2_listeners`
# resource needs a `load_balancer_arn` up front — so something has to enumerate
# the ALBs to drive it. This resource fills that gap using the enumerated
# `elb_client_v2` (the ELBv2 API), filtered to `type == "application"`.
class AwsElbv2Inventory < AwsResourceBase
  name "aws_elbv2_inventory"
  desc "Application Load Balancers (ELBv2) with scheme + FSBP attributes."
  example <<~EX
    describe aws_elbv2_inventory.internet_facing do
      it { should_not be_empty }
    end
  EX

  attr_reader :load_balancers

  def initialize(opts = {})
    super(opts)
    validate_parameters(allow: %i(aws_region aws_endpoint))
    @load_balancers = []

    catch_aws_errors do
      @aws.elb_client_v2.describe_load_balancers.each do |page|
        page.load_balancers.each do |lb|
          next unless lb.type == "application"

          attrs = {}
          catch_aws_errors do
            @aws.elb_client_v2
                .describe_load_balancer_attributes(load_balancer_arn: lb.load_balancer_arn)
                .attributes.each { |a| attrs[a.key] = a.value }
          end

          @load_balancers << {
            arn:                  lb.load_balancer_arn,
            name:                 lb.load_balancer_name,
            scheme:               lb.scheme,
            drop_invalid_headers: attrs["routing.http.drop_invalid_header_fields.enabled"] == "true",
            access_logs_enabled:  attrs["access_logs.s3.enabled"] == "true",
            deletion_protection:  attrs["deletion_protection.enabled"] == "true",
          }
        end
      end
    end
  end

  # internet-facing ALBs — the ones that terminate client TLS at the edge.
  def internet_facing
    @load_balancers.select { |lb| lb[:scheme] == "internet-facing" }
  end

  def arns
    @load_balancers.map { |lb| lb[:arn] }
  end

  def to_s
    "ELBv2 Inventory (#{@load_balancers.size} application LBs)"
  end
end
