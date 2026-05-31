# Pure-Ruby parser for AWS resource-based policy documents. No SDK
# calls. Walks a policy document statement-by-statement and decides
# whether each statement grants unrestricted access via Principal: "*".
#
# Ported verbatim from risk-sentinel/cis-aws-foundations (CIS 2.21, #72).
# Each profile stands alone, so this is a focused copy rather than a
# cross-profile dependency.
#
# Coarse condition heuristic: a statement with a wildcard principal AND
# any non-empty Condition block is accepted (not judged public). Sharper
# per-service condition analysis is a tracked follow-up.
#
# Wildcard shapes covered: "*", { "AWS" => "*" }, { "Service" => "*" },
# { "Federated" => "*" }, { "CanonicalUser" => "*" }, plus arrays
# containing "*" in any of those slots.

require "json"

module IamPolicyStatement
  WILDCARD = "*".freeze
  WILDCARD_PRINCIPAL_KEYS = %w[AWS Service Federated CanonicalUser].freeze

  module_function

  # Parse a policy document. Accepts a JSON string or an already-decoded
  # Hash. Returns an array of normalized statement hashes; an unparseable
  # or empty input returns [].
  def parse(policy)
    doc = decode(policy)
    return [] unless doc.is_a?(Hash)
    statements = Array(doc["Statement"] || doc[:Statement])
    statements.map { |s| normalize(s) }.compact
  end

  def decode(policy)
    return policy if policy.is_a?(Hash)
    return nil if policy.nil?
    str = policy.to_s
    return nil if str.empty?
    JSON.parse(str)
  rescue JSON::ParserError
    nil
  end

  def normalize(statement)
    return nil unless statement.is_a?(Hash)
    {
      sid:       statement["Sid"] || statement[:Sid],
      effect:    (statement["Effect"] || statement[:Effect]).to_s,
      principal: statement["Principal"] || statement[:Principal],
      action:    statement["Action"] || statement[:Action],
      condition: statement["Condition"] || statement[:Condition],
      raw:       statement,
    }
  end

  def allow?(statement)
    statement[:effect] == "Allow"
  end

  def deny?(statement)
    statement[:effect] == "Deny"
  end

  # True if the Principal slot contains a wildcard "*" anywhere we check.
  def principal_is_wildcard?(statement)
    principal = statement[:principal]
    return true if principal == WILDCARD
    return false unless principal.is_a?(Hash)
    WILDCARD_PRINCIPAL_KEYS.any? do |key|
      val = principal[key] || principal[key.to_sym]
      next false if val.nil?
      Array(val).any? { |v| v.to_s == WILDCARD }
    end
  end

  def action_is_wildcard?(statement)
    Array(statement[:action]).any? { |a| a.to_s.include?(WILDCARD) }
  end

  # Coarse: any non-empty Condition block.
  def has_condition?(statement)
    cond = statement[:condition]
    cond.is_a?(Hash) && !cond.empty?
  end

  # True when this Deny statement blocks non-TLS access via
  # Condition Bool aws:SecureTransport=false.
  def denies_insecure_transport?(statement)
    return false unless deny?(statement)
    cond = statement[:condition]
    return false unless cond.is_a?(Hash)
    bool = cond["Bool"] || cond[:Bool] || {}
    val = bool["aws:SecureTransport"] || bool["aws:securetransport"]
    val.to_s.casecmp("false").zero?
  end

  # Allow + wildcard principal + no narrowing condition => effectively public.
  def effectively_public?(statement)
    allow?(statement) && principal_is_wildcard?(statement) && !has_condition?(statement)
  end

  def principal_label(statement)
    principal = statement[:principal]
    return WILDCARD if principal == WILDCARD
    return principal.to_json if principal.is_a?(Hash)
    principal.to_s
  end
end
