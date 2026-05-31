require "aws_backend"

# aws_iam_role_policy_analysis — fetches the actual inline + attached
# managed policy DOCUMENTS for an IAM role and flattens them through the
# IamPolicyStatement parser so controls can detect wildcard action/resource
# grants. The stock aws_iam_role exposes only policy NAMES/ARNs, not the
# documents, which is insufficient for least-privilege deep checks
# (EF-4.2 task role no-wildcard, EF-4.3 execution role scoped).
#
# Identity-policy statements have no Principal (the role IS the principal),
# so "public" heuristics don't apply; we look for wildcard Action AND
# wildcard Resource (the classic over-broad grant).
class AwsIamRolePolicyAnalysis < AwsResourceBase
  name "aws_iam_role_policy_analysis"
  desc "Inline + attached managed policy documents for an IAM role, parsed for wildcards."
  example <<~EX
    describe aws_iam_role_policy_analysis(role_arn: arn) do
      its('wildcard_statements') { should be_empty }
    end
  EX

  attr_reader :role_name, :role_arn, :statements, :access_error

  def initialize(opts = {})
    opts = { role_arn: opts } if opts.is_a?(String)
    super(opts)
    validate_parameters(required: %i(role_arn))
    @role_arn  = opts[:role_arn]
    @role_name = @role_arn.to_s.split("/").last
    @statements = []
    @access_error = nil
    @exists = false

    catch_aws_errors do
      load_inline_policies
      load_attached_policies
    end
  end

  def exists?
    @exists
  end

  # Statements granting a wildcard Action together with a wildcard Resource.
  def wildcard_statements
    @statements.select do |s|
      IamPolicyStatement.allow?(s) &&
        IamPolicyStatement.action_is_wildcard?(s) &&
        wildcard_resource?(s)
    end
  end

  # Statements granting a wildcard Action (regardless of resource scope) —
  # used for the stricter execution-role check.
  def wildcard_action_statements
    @statements.select { |s| IamPolicyStatement.allow?(s) && IamPolicyStatement.action_is_wildcard?(s) }
  end

  def to_s
    "IAM role policy analysis #{@role_name}"
  end

  private

  def wildcard_resource?(statement)
    Array(statement[:raw]["Resource"] || statement[:raw][:Resource]).any? { |r| r.to_s == "*" }
  end

  def load_inline_policies
    names = @aws.iam_client.list_role_policies(role_name: @role_name).policy_names
    @exists = true
    names.each do |pn|
      doc = @aws.iam_client.get_role_policy(role_name: @role_name, policy_name: pn).policy_document
      # Inline policy documents are URL-encoded JSON.
      decoded = doc.is_a?(String) ? CGI.unescape(doc) : doc
      @statements.concat(IamPolicyStatement.parse(decoded))
    end
  rescue Aws::IAM::Errors::NoSuchEntity
    @access_error = "role not found: #{@role_name}"
  rescue Aws::IAM::Errors::AccessDenied => e
    @access_error = e.message
  end

  def load_attached_policies
    attached = @aws.iam_client.list_attached_role_policies(role_name: @role_name).attached_policies
    @exists = true
    attached.each do |ap|
      pol = @aws.iam_client.get_policy(policy_arn: ap.policy_arn).policy
      ver = @aws.iam_client.get_policy_version(policy_arn: ap.policy_arn, version_id: pol.default_version_id)
      doc = ver.policy_version.document
      decoded = doc.is_a?(String) ? CGI.unescape(doc) : doc
      @statements.concat(IamPolicyStatement.parse(decoded))
    end
  rescue Aws::IAM::Errors::AccessDenied => e
    @access_error ||= e.message
  end
end
