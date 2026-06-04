# encoding: UTF-8
#
# aws_ecs_account_settings — effective ECS account-level settings
# (ecs:ListAccountSettings, effective_settings: true). Lets EF-10.2 assert
# account-wide defaults the per-cluster controls can't see, e.g.
# containerInsights default-on, awsvpcTrunking, tag-resource propagation.
#
#   describe aws_ecs_account_settings do
#     its('value_for("containerInsights")') { should cmp 'enabled' }
#   end
#
# On an AWS API error the resource is marked failed by catch_aws_errors (InSpec
# surfaces it); @settings stays empty so value_for returns nil.

class AwsEcsAccountSettings < AwsResourceBase
  name "aws_ecs_account_settings"
  desc "Effective ECS account-level settings (ListAccountSettings)."
  example "
    describe aws_ecs_account_settings do
      its('value_for(\"containerInsights\")') { should cmp 'enabled' }
    end
  "

  attr_reader :settings

  def initialize(opts = {})
    super(opts)
    @settings = {}
    catch_aws_errors do
      next_token = nil
      loop do
        resp = @aws.ecs_client.list_account_settings(effective_settings: true, next_token: next_token)
        Array(resp.settings).each { |s| @settings[s.name.to_s] = s.value }
        next_token = resp.next_token
        break if next_token.nil? || next_token.to_s.empty?
      end
    end
  end

  # Effective value of a named account setting, or nil if unset/unreachable.
  def value_for(name)
    @settings[name.to_s]
  end

  def to_s
    "ECS Account Settings"
  end
end
