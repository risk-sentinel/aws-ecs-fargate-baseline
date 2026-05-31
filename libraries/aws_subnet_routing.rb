require "aws_backend"

# aws_subnet_routing — resolves the EFFECTIVE route table for a subnet and
# answers whether it has a default route (0.0.0.0/0 or ::/0) to an internet
# gateway. AWS uses the subnet's explicitly associated route table if one
# exists, otherwise the VPC main route table. The vendored aws_route_table
# only takes route_table_id and does no subnet->table resolution, which is
# what EF-5.4 (private-subnet check) needs. Uses the enumerated ec2_client.
class AwsSubnetRouting < AwsResourceBase
  name "aws_subnet_routing"
  desc "Effective route table + internet-egress posture for a subnet."
  example <<~EX
    describe aws_subnet_routing(subnet_id: 'subnet-123') do
      it { should_not have_internet_gateway_route }
    end
  EX

  attr_reader :subnet_id, :vpc_id, :route_table_id, :routes

  def initialize(opts = {})
    opts = { subnet_id: opts } if opts.is_a?(String)
    super(opts)
    validate_parameters(required: %i(subnet_id))
    @subnet_id = opts[:subnet_id]
    @routes = []
    @exists = false

    catch_aws_errors do
      resolve_vpc
      resolve_route_table
    end
  end

  def exists?
    @exists
  end

  # True if the effective route table sends 0.0.0.0/0 (or ::/0) to an
  # internet gateway — i.e. the subnet is public.
  def internet_gateway_route?
    @routes.any? do |r|
      default = ["0.0.0.0/0", "::/0"].include?(r[:destination].to_s)
      default && r[:gateway_id].to_s.start_with?("igw-")
    end
  end

  def to_s
    "Subnet routing #{@subnet_id}"
  end

  private

  def resolve_vpc
    resp = @aws.ec2_client.describe_subnets(subnet_ids: [@subnet_id])
    subnet = resp.subnets.first
    return if subnet.nil?
    @vpc_id = subnet.vpc_id
    @exists = true
  end

  def resolve_route_table
    return if @vpc_id.nil?

    explicit = @aws.ec2_client.describe_route_tables(
      filters: [{ name: "association.subnet-id", values: [@subnet_id] }],
    ).route_tables.first

    table = explicit || main_route_table
    return if table.nil?

    @route_table_id = table.route_table_id
    @routes = table.routes.map do |r|
      {
        destination: r.destination_cidr_block || r.destination_ipv_6_cidr_block,
        gateway_id:  r.gateway_id,
        nat_gateway_id: r.nat_gateway_id,
      }
    end
  end

  def main_route_table
    @aws.ec2_client.describe_route_tables(
      filters: [
        { name: "vpc-id", values: [@vpc_id] },
        { name: "association.main", values: ["true"] },
      ],
    ).route_tables.first
  end
end
