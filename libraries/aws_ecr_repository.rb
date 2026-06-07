# encoding: UTF-8
#
# aws_ecr_repository — scan + tag-mutability posture of an ECR repository backing a
# Fargate task image (EF-1.3 / EF-1.4). Workload-scoped: the controls iterate only the
# repos referenced by in-scope task definitions (ecr_repos_in_scope). Exposes exactly
# what EF-1 asserts.

class AwsEcrRepository < AwsResourceBase
  name "aws_ecr_repository"
  desc "ECR repository scan-on-push + image-tag-mutability posture."
  example "
    describe aws_ecr_repository(repository_name: 'app') do
      its('scan_on_push') { should eq true }
      its('image_tag_mutability') { should eq 'IMMUTABLE' }
    end
  "

  attr_reader :repository_name, :image_scanning_configuration, :scan_on_push, :image_tag_mutability

  def initialize(opts = {})
    opts = { repository_name: opts } if opts.is_a?(String)
    super(opts)
    validate_parameters(required: %i[repository_name])
    @repository_name = opts[:repository_name]
    @exists = false
    catch_aws_errors do
      repo = @aws.ecr_client.describe_repositories(repository_names: [@repository_name]).repositories.first
      next if repo.nil?
      @exists                       = true
      @image_scanning_configuration = repo.image_scanning_configuration
      @scan_on_push                 = repo.image_scanning_configuration&.scan_on_push
      @image_tag_mutability         = repo.image_tag_mutability
    end
  end

  def exists?
    @exists == true
  end

  def to_s
    "ECR Repository #{@repository_name}"
  end
end
