# encoding: UTF-8
#
# EF-12.x — Reverse-proxy TLS termination (distributed-TLS model).
#
# TLS for a Fargate workload terminates either at the ALB (EF-11) or at a
# reverse-proxy sidecar (nginx/envoy/...) inside the task — or both. The
# `tls_termination` input declares where, per the distributed-TLS design shared
# with cis-nginx (`nginx_tls_termination`). Each layer is validated where TLS
# actually lives:
#   - ALB termination .......... EF-11 (real ACM + SSL-policy checks here).
#   - Proxy termination ........ EF-12 (Fargate-layer readiness here) + the
#                                proxy's cipher/protocol config validated INSIDE
#                                the container by cis-nginx.
#
# From a task definition we can observe whether a reverse-proxy container is
# present and whether it has TLS key material wired (a secret, env, or mounted
# cert/key) — the signal that it terminates TLS. The in-container nginx.conf TLS
# directives are out of reach of the ECS API and belong to cis-nginx.
#
# Provenance: NIST SC-8 / SC-8(1) / SC-13. No DISA STIG exists for an AWS ALB or
# a Fargate sidecar; the Container Platform SRG's transport requirements
# (SRG-APP-000439-CTR-001070, ...-000035) anchor the intent.

control "EF-12.1" do
  title "Reverse-proxy TLS termination must be wired where declared"
  desc "When this workload terminates TLS at a reverse proxy rather than (or in "\
       "addition to) the ALB — `tls_termination` is 'proxy' or 'both' — a "\
       "reverse-proxy container (nginx/envoy/haproxy/traefik/apache) must be "\
       "present in the Fargate task definitions and have TLS key material wired "\
       "(a secret, env var, or mounted volume referencing a certificate/key). "\
       "Fail-closed: proxy termination is declared but no proxy holds TLS "\
       "material means TLS is not actually terminating where claimed. The "\
       "proxy's cipher/protocol configuration is validated inside the container "\
       "by cis-nginx (nginx_tls_termination). SC-8 / SC-8(1) / SC-13."
  tag severity:              "high"
  tag nist:                  ["SC-8", "SC-8 (1)", "SC-13"]
  tag cci:                   ["CCI-002418", "CCI-002421"]
  tag local_number:          "EF-12.1"
  tag srg:                   "SRG-APP-000439-CTR-001070"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  mode       = input("tls_termination", value: "alb").to_s.downcase
  applicable = %w(proxy both).include?(mode)
  proxies    = applicable ? proxy_containers : []

  impact 0.7
  impact 0.0 unless applicable
  only_if("tls_termination=#{mode}: TLS terminates at the ALB (validated by EF-11), not a proxy") { applicable }

  describe "Reverse-proxy container present for proxy TLS termination (tls_termination=#{mode})" do
    subject { proxies.map { |p| "#{p[:family]}/#{p[:name]}" } }
    it { should_not be_empty }
  end

  proxies.each do |p|
    has_tls = container_has_tls_material?(p[:def])
    describe "Proxy #{p[:family]}/#{p[:name]} (#{p[:image]}) has TLS key material wired" do
      subject { has_tls }
      it { should eq true }
    end
  end
end

control "EF-12.2" do
  title "Reverse-proxy / ingress container inventory (informational)"
  desc "Enumerates reverse-proxy / web-proxy containers (nginx, envoy, haproxy, "\
       "traefik, apache) across in-scope Fargate task definitions, so the "\
       "ingress topology is visible and each proxy's in-container TLS "\
       "configuration can be validated with cis-nginx. Informational — no "\
       "pass/fail (impact 0.0)."
  tag severity:              "none"
  tag nist:                  ["CM-8"]
  tag local_number:          "EF-12.2"
  tag srg:                   "SRG-APP-000439-CTR-001070"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  impact 0.0
  proxies = proxy_containers

  if proxies.empty?
    describe "Reverse-proxy containers detected in scope" do
      subject { proxies }
      it { should be_empty }
    end
  else
    proxies.each do |p|
      describe "Proxy container #{p[:family]}/#{p[:name]} — image (validate TLS config via cis-nginx)" do
        subject { p[:image] }
        it { should_not be_nil }
      end
    end
  end
end
