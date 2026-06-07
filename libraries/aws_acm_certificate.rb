# encoding: UTF-8
#
# aws_acm_certificate — status + expiry of a single ACM certificate
# (acm:DescribeCertificate). Used by EF-11.7 to assert that the certificate bound
# to an ALB HTTPS/TLS listener is ISSUED and not about to expire.
#
#   describe aws_acm_certificate(certificate_arn: arn) do
#     it { should be_issued }
#     its('days_until_expiry') { should be > 30 }
#   end
#
# The scanner image must ship the aws-sdk-acm gem. When it is absent the resource
# reports `available? == false` (instead of erroring), so EF-11.7 skips with a
# clear "add aws-sdk-acm" message rather than failing the whole profile load.

class AwsAcmCertificate < AwsResourceBase
  name "aws_acm_certificate"
  desc "Status and expiry of a single ACM certificate."
  example "
    describe aws_acm_certificate(certificate_arn: arn) do
      it { should be_issued }
    end
  "

  attr_reader :certificate_arn, :status, :not_after, :not_before, :domain_name, :type

  def initialize(opts = {})
    opts = { certificate_arn: opts } if opts.is_a?(String)
    super(opts)
    validate_parameters(required: %i[certificate_arn])
    @certificate_arn = opts[:certificate_arn]
    @available = false
    @exists    = false

    begin
      require "aws-sdk-acm"
    rescue LoadError
      return # aws-sdk-acm not in the scanner image → available? == false
    end
    @available = true

    catch_aws_errors do
      cert = @aws.aws_client(Aws::ACM::Client).describe_certificate(certificate_arn: @certificate_arn).certificate
      next if cert.nil?

      @exists      = true
      @status      = cert.status
      @not_after   = cert.not_after
      @not_before  = cert.not_before
      @domain_name = cert.domain_name
      @type        = cert.type
    end
  end

  # The aws-sdk-acm gem was loadable in the scanner image.
  def available?
    @available == true
  end

  def exists?
    @exists == true
  end

  # ACM status == ISSUED (a usable, validated certificate). PENDING_VALIDATION,
  # EXPIRED, REVOKED, FAILED, INACTIVE, VALIDATION_TIMED_OUT all fail this.
  def issued?
    @status.to_s == "ISSUED"
  end

  def expired?
    !@not_after.nil? && @not_after < Time.now
  end

  # Whole days until NotAfter (negative once expired); nil if no expiry known.
  def days_until_expiry
    return nil if @not_after.nil?
    ((@not_after - Time.now) / 86_400).floor
  end

  def to_s
    "ACM Certificate #{@certificate_arn.to_s.split('/').last}"
  end
end
