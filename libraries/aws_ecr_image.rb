# encoding: UTF-8
#
# aws_ecr_image — image scan findings for a specific ECR image (EF-1.7 CVE gate).
# Exposes image_scan_findings (a hash carrying :finding_severity_counts) as EF-1.7 reads
# it. A not-yet-scanned image (ScanNotFound) yields nil findings.

class AwsEcrImage < AwsResourceBase
  name "aws_ecr_image"
  desc "ECR image vulnerability scan findings (severity counts)."
  example "
    describe aws_ecr_image(repository_name: 'app', image_digest: 'sha256:...') do
      its('image_scan_findings') { should_not be_nil }
    end
  "

  attr_reader :repository_name, :image_digest, :image_scan_findings

  def initialize(opts = {})
    super(opts)
    validate_parameters(required: %i[repository_name image_digest])
    @repository_name = opts[:repository_name]
    @image_digest    = opts[:image_digest]
    @image_scan_findings = nil
    catch_aws_errors do
      resp = @aws.ecr_client.describe_image_scan_findings(
        repository_name: @repository_name,
        image_id: { image_digest: @image_digest },
      )
      @image_scan_findings = resp.image_scan_findings&.to_h
    rescue Aws::ECR::Errors::ScanNotFoundException, Aws::ECR::Errors::ImageNotFoundException
      @image_scan_findings = nil
    end
  end

  # True when the image carries a signature (cosign/notation) — DescribeImageSigningStatus
  # returns at least one signing status. Drives `should be_signed`.
  def signed?
    !Array(@aws.ecr_client.describe_image_signing_status(
      repository_name: @repository_name, image_id: { image_digest: @image_digest }
    ).signing_statuses).empty?
  rescue StandardError
    false
  end

  # True when the image has an SBOM referrer artifact (spdx / cyclonedx / in-toto).
  # Drives `should have_sbom`.
  def has_sbom?
    refs = []
    token = nil
    loop do
      resp = @aws.ecr_client.list_image_referrers(repository_name: @repository_name, subject_id: { image_digest: @image_digest }, next_token: token)
      refs.concat(Array(resp.referrers))
      token = resp.next_token
      break if token.nil? || token.to_s.empty?
    end
    refs.any? { |r| %i[artifact_media_type artifact_type media_type].any? { |m| r.respond_to?(m) && r.public_send(m).to_s =~ /spdx|cyclonedx|in-toto|\bsbom\b|bom/i } }
  rescue StandardError
    false
  end

  def to_s
    "ECR Image #{@repository_name}@#{@image_digest.to_s[0, 16]}"
  end
end
