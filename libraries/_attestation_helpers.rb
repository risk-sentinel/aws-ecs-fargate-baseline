# encoding: UTF-8
#
# CANONICAL SOURCE — scaffolder-owned (sparc-validate#154).
#
# Synced into each profile's libraries/ by tools/attestation/sync.py alongside
# document_attestation.rb. Do NOT hand-edit per-profile copies — edit here and
# re-sync (ratified #154 §10.2).
#
# _attestation_helpers — resolves an (evidence-class, logical-name) pair to a
# full document URI, so controls reference a class + logical name and never a
# hard-coded location. The three evidence classes were ratified in #154 §10.1:
#
#   :leveraged  leveraged-SYSTEM authorizations the boundary inherits
#               (AWS FedRAMP, SOC 2, ISO). One doc <- many controls/profiles
#               (WORM). Base input: leveraged_evidence_base.
#               Maps to `inherited` controls.
#   :policy     policy-PROVIDER documents the boundary leverages (shared /
#               templated / parent-org policies) — a SEPARATE location from the
#               boundary's own docs. One doc <- many controls.
#               Base input: policy_provider_base.
#               Maps to `alternative` policy-category controls.
#   :boundary   the boundary system's OWN docs (Contingency Plan, DRP, IRP,
#               system-specific policies/procedures). One doc <- one/few
#               controls. Base input: boundary_docs_base.
#
# Provider is inferred downstream from the base's URI scheme (s3 / https /
# github / gitlab / file) by the document_attestation resource — the resolver
# only composes strings; it does not know or care which provider it is.
#
# Resolution contract (#154 §3 + ratified clarification):
#   attestation_uri(:boundary, 'C-2.1.3')
#     -> '' when boundary_docs_base is unset  (=> control SKIPs, stays
#        SAF-attestable; never a false Pass or Fail)
#     -> '<boundary_docs_base>/C-2.1.3.md' when the base is set
#
# Logical name (#154 §10.6): defaults to the control_id; pass an explicit name
# for shared/leveraged docs (e.g. 'aws-fedramp-moderate').
#
# Loaded into control bodies via `::Inspec::Rule.include` — bare
# `Inspec::Rule.include` raises uninitialized-constant NameError at exec under
# InSpec 7 (library files load in an anonymous-class context). See
# docs/dev/Vendored_Resource_Gaps.md §6.

module AttestationHelpers
  # Maps each evidence class to the profile input that holds its base location.
  CLASS_BASE_INPUT = {
    leveraged: "leveraged_evidence_base",
    policy:    "policy_provider_base",
    boundary:  "boundary_docs_base",
  }.freeze

  DEFAULT_EXT = "md".freeze

  # Compose the full document URI for an evidence class + logical name.
  #   klass        - :leveraged | :policy | :boundary
  #   logical_name - the document's logical name (default: the control_id)
  #   ext:         - file extension appended when logical_name has none
  # Returns '' when the class base input is unset/empty -> control SKIPs.
  def attestation_uri(klass, logical_name, ext: DEFAULT_EXT)
    base_input = CLASS_BASE_INPUT[klass]
    raise ArgumentError, "unknown evidence class #{klass.inspect} (expected #{CLASS_BASE_INPUT.keys.inspect})" if base_input.nil?

    base = input(base_input, value: "").to_s.strip
    return "" if base.empty?

    name = logical_name.to_s
    name = "#{name}.#{ext}" if ext && !name.empty? && !name.include?(".")
    "#{base.chomp('/')}/#{name}"
  end
end

::Inspec::Rule.include(AttestationHelpers)
