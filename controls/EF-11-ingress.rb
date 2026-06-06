# encoding: UTF-8
#
# EF-11.x — Ingress / Application Load Balancer TLS.
#
# The Fargate service's internet ingress is an ALB that TERMINATES TLS. This is
# the boundary the cis-nginx `nginx_tls_termination: upstream` controls defer to
# (sparc-validate#172) — so it is validated here with REAL checks rather than a
# human attestation. A consumer whose NGINX terminates TLS instead sets
# `nginx_tls_termination: nginx` (validated in cis-nginx); both layers are
# checked where TLS actually lives (distributed-TLS design).
#
# Provenance: AWS FSBP ELB.* (the authoritative automatable source for ALB TLS)
# + NIST SC-8 / SC-13 / AU-2 / CP-* . No DISA STIG exists for AWS ALB; CIS AWS
# Compute §10 is Elastic Beanstalk (N/A for Fargate + ALB).

control "EF-11.1" do
  title "Internet-facing ALBs must offer a TLS (HTTPS) listener"
  desc "An internet-facing Application Load Balancer that terminates client "\
       "traffic must encrypt data in transit via an HTTPS/TLS listener "\
       "(SC-8). An HTTP-only internet-facing ALB exposes plaintext to the "\
       "internet."
  tag severity:              "high"
  tag nist:                  ["SC-8", "SC-8 (1)"]
  tag cci:                   ["CCI-002418", "CCI-002421"]
  tag local_number:          "EF-11.1"
  tag srg:                   "SRG-APP-000439-CTR-001070"
  tag fsbp:                  "ELB.2"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  albs = aws_elbv2_inventory.internet_facing
  impact 0.8
  impact 0.0 if albs.empty?
  only_if("No internet-facing Application Load Balancers in scope") { !albs.empty? }

  albs.each do |lb|
    protocols = aws_elasticloadbalancingv2_listeners(load_balancer_arn: lb[:arn]).protocols
    describe "Internet-facing ALB #{lb[:name]} — has an HTTPS/TLS listener" do
      subject { protocols.any? { |p| %w(HTTPS TLS).include?(p.to_s) } }
      it { should eq true }
    end
  end
end

control "EF-11.2" do
  title "ALB HTTPS listeners must use a strong TLS security policy"
  desc "Each HTTPS/TLS listener must use a predefined SSL policy that enforces "\
       "TLS 1.2 or higher (SC-13). Legacy policies (TLS 1.0/1.1, the 2015/2016 "\
       "sets) permit deprecated protocols. The approved set is the "\
       "`alb_strong_ssl_policies` input."
  tag severity:              "high"
  tag nist:                  ["SC-13", "SC-8 (1)"]
  tag cci:                   ["CCI-002450", "CCI-002421"]
  tag local_number:          "EF-11.2"
  tag srg:                   "SRG-APP-000439-CTR-001070"
  tag fsbp:                  "ELB.17"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  albs     = aws_elbv2_inventory.internet_facing
  approved = input("alb_strong_ssl_policies")
  impact 0.8
  impact 0.0 if albs.empty?
  only_if("No internet-facing Application Load Balancers in scope") { !albs.empty? }

  albs.each do |lb|
    lst = aws_elasticloadbalancingv2_listeners(load_balancer_arn: lb[:arn])
    lst.protocols.zip(lst.ssl_policies, lst.ports).each do |proto, policy, port|
      next unless %w(HTTPS TLS).include?(proto.to_s)
      describe "ALB #{lb[:name]} HTTPS listener :#{port} SSL policy" do
        subject { policy }
        it { should be_in approved }
      end
    end
  end
end

control "EF-11.3" do
  title "ALB HTTP listeners must redirect to HTTPS"
  desc "Any plaintext HTTP listener on an internet-facing ALB must redirect to "\
       "HTTPS (default action type=redirect, protocol HTTPS) so clients are "\
       "moved onto TLS rather than served over plaintext (SC-8 / FSBP ELB.1)."
  tag severity:              "medium"
  tag nist:                  ["SC-8", "AC-17 (2)"]
  tag cci:                   ["CCI-002418"]
  tag local_number:          "EF-11.3"
  tag srg:                   "SRG-APP-000439-CTR-001070"
  tag fsbp:                  "ELB.1"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  albs = aws_elbv2_inventory.internet_facing
  impact 0.5
  impact 0.0 if albs.empty?
  only_if("No internet-facing Application Load Balancers in scope") { !albs.empty? }

  albs.each do |lb|
    lst = aws_elasticloadbalancingv2_listeners(load_balancer_arn: lb[:arn])
    lst.protocols.zip(lst.default_actions, lst.ports).each do |proto, actions, port|
      next unless proto.to_s == "HTTP"
      redirects_https = Array(actions).any? do |a|
        type = a.respond_to?(:type) ? a.type : a[:type]
        rc   = a.respond_to?(:redirect_config) ? a.redirect_config : a[:redirect_config]
        proto2 = rc && (rc.respond_to?(:protocol) ? rc.protocol : rc[:protocol])
        type.to_s == "redirect" && proto2.to_s == "HTTPS"
      end
      describe "ALB #{lb[:name]} HTTP listener :#{port} redirects to HTTPS" do
        subject { redirects_https }
        it { should eq true }
      end
    end
  end
end

control "EF-11.4" do
  title "ALBs must drop invalid HTTP header fields"
  desc "routing.http.drop_invalid_header_fields.enabled must be true so the ALB "\
       "strips malformed headers before forwarding to the Fargate tasks "\
       "(request-smuggling / header-injection hardening — FSBP ELB.4 / SI-10)."
  tag severity:              "medium"
  tag nist:                  ["SI-10"]
  tag cci:                   ["CCI-001310"]
  tag local_number:          "EF-11.4"
  tag srg:                   "SRG-APP-000251-CTR-000600"
  tag fsbp:                  "ELB.4"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  albs = aws_elbv2_inventory.internet_facing
  impact 0.4
  impact 0.0 if albs.empty?
  only_if("No internet-facing Application Load Balancers in scope") { !albs.empty? }

  albs.each do |lb|
    describe "ALB #{lb[:name]} drop_invalid_header_fields" do
      subject { lb[:drop_invalid_headers] }
      it { should eq true }
    end
  end
end

control "EF-11.5" do
  title "ALBs must have access logging enabled"
  desc "access_logs.s3.enabled must be true so ingress request records are "\
       "captured for audit + incident response (AU-2 / FSBP ELB.5)."
  tag severity:              "medium"
  tag nist:                  ["AU-2 a", "AU-12 a"]
  tag cci:                   ["CCI-000130", "CCI-000169"]
  tag local_number:          "EF-11.5"
  tag srg:                   "SRG-APP-000092-CTR-000165"
  tag fsbp:                  "ELB.5"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  albs = aws_elbv2_inventory.internet_facing
  impact 0.4
  impact 0.0 if albs.empty?
  only_if("No internet-facing Application Load Balancers in scope") { !albs.empty? }

  albs.each do |lb|
    describe "ALB #{lb[:name]} access_logs enabled" do
      subject { lb[:access_logs_enabled] }
      it { should eq true }
    end
  end
end

control "EF-11.6" do
  title "ALBs must have deletion protection enabled"
  desc "deletion_protection.enabled must be true so the ingress LB cannot be "\
       "removed accidentally or maliciously, an availability safeguard "\
       "(CP-10 / FSBP ELB.6)."
  tag severity:              "low"
  tag nist:                  ["CP-10"]
  tag cci:                   ["CCI-000366"]
  tag local_number:          "EF-11.6"
  tag srg:                   "SRG-APP-000516-CTR-001325"
  tag fsbp:                  "ELB.6"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  albs = aws_elbv2_inventory.internet_facing
  impact 0.3
  impact 0.0 if albs.empty?
  only_if("No internet-facing Application Load Balancers in scope") { !albs.empty? }

  albs.each do |lb|
    describe "ALB #{lb[:name]} deletion_protection" do
      subject { lb[:deletion_protection] }
      it { should eq true }
    end
  end
end
