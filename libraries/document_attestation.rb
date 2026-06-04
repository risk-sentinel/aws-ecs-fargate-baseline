# encoding: UTF-8
#
# CANONICAL SOURCE — scaffolder-owned (sparc-validate#154).
#
# This is the single authoritative copy of the document_attestation resource.
# It is synced into each profile's libraries/ by tools/attestation/sync.py
# (or `scaffold.py sync-attestation <profile>`). Do NOT hand-edit the per-
# profile copies — edit here and re-sync, so the N copies never drift
# (ratified decision #154 §10.2: resource/helper sync is scaffolder-owned).
#
# document_attestation — source-agnostic "does this evidence document exist,
# and is it current?" accessor. Lifts policy / periodic-review controls from
# Skip-with-rationale to Pass-with-evidence based on the existence + freshness
# of an attestation (or leveraged-system evidence) document at a URI.
#
# Schemes:
#   s3://bucket/key         — primary; lazy-loads aws-sdk-s3 and uses the
#                             ambient AWS credential chain (the OIDC creds the
#                             exec job exports). Requires the caller's role to
#                             have s3:GetObject on the key AND kms:Decrypt on
#                             the bucket CMK (HeadObject on an SSE-KMS object
#                             needs it).
#   https://host/path       — HTTP HEAD; parses the Last-Modified header.
#   file:///path            — local file mtime. Bare paths are aliased to this.
#   github://owner/repo/path[@ref]
#                           — GitHub REST: last-commit-date touching the path
#                             (GET /repos/{o}/{r}/commits?path=&sha=). The
#                             commit date is a *better* freshness signal than
#                             an mtime — it is literally "when the policy last
#                             changed," with history.
#   gitlab://<enc-project>/path[@ref]
#                           — GitLab REST: last-commit-date touching the path
#                             (GET /projects/:id/repository/commits?path=&ref_name=).
#                             <enc-project> is the URL-encoded project id, i.e.
#                             "group%2Fsubgroup%2Frepo" (GitLab's own API
#                             convention for slash-encoded namespaces).
#
# Auth (git hosts): a fine-grained PAT with read access to repo contents.
# Resolution order: opts[:token] (e.g. control passes
# `token: input('attestation_github_token')`) -> ENV. The conventional env
# vars are ATTESTATION_GITHUB_TOKEN / ATTESTATION_GITLAB_TOKEN, set from a
# runner secret. A public repo needs no token. Tokens are never committed.
#
# Accessors:
#   exists?            -> Boolean
#   last_modified      -> Time | nil
#   current?(days=nil) -> Boolean   (existence-only when no window given)
#   connection_error   -> String | nil
#   attestation_json   -> Hash | nil  (parsed CMS-pattern JSON, lazy)
#
# A populated connection_error means the document could not be reached
# (missing IAM/KMS grant, network failure, bad token, malformed URI). Controls
# surface it as a FAIL rather than a vacuous pass. file:// and https:// need no
# AWS creds, so the resource is reusable by any consumer pointing at any
# evidence store.
#
# Design notes: docs/dev/Vendored_Resource_Gaps.md (document-as-evidence),
# sparc-validate#154 (evidence-class model + multi-provider rollout).

class DocumentAttestation < Inspec.resource(1)
  name "document_attestation"
  supports platform: "aws"
  desc "Existence + freshness of an evidence/attestation document at a URI (s3/https/file/github/gitlab)."
  example <<~EXAMPLE
    describe document_attestation('s3://my-bucket/attestations/C-2.1.3.json', max_age_days: 365) do
      it { should exist }
      it { should be_current }
    end

    describe document_attestation('github://acme/governance/policies/cp.md', token: input('attestation_github_token')) do
      it { should exist }
    end
  EXAMPLE

  attr_reader :uri, :scheme, :last_modified, :connection_error

  # Positional opts hash — NOT keyword args. InSpec routes resource args through
  # a *args splat, so under Ruby 3 `document_attestation(uri, max_age_days: 365)`
  # arrives as `.new(uri, {max_age_days: 365})` (two positional args). A keyword
  # signature rejects that with "wrong number of arguments (given 2, expected
  # 0..1)" at exec. Accept (uri, opts) and a single hash form.
  def initialize(uri = nil, opts = {})
    if uri.is_a?(Hash)
      opts = uri
      uri  = opts[:uri]
    end
    @uri              = uri.to_s
    @max_age_days     = opts[:max_age_days]
    @region           = opts[:region] || ENV["AWS_REGION"] || "us-east-1"
    @token            = opts[:token]
    @exists           = false
    @last_modified    = nil
    @connection_error = nil
    @raw_body         = nil
    @scheme           = nil

    if @uri.empty?
      @connection_error = "no document URI configured"
      return
    end
    fetch
  end

  def exists?
    @exists == true
  end

  # Existence-only when no window is given (any existing doc is "current");
  # otherwise the document must have been modified within the window.
  def current?(max_age_days = nil)
    days = max_age_days || @max_age_days
    return false unless @exists && @last_modified
    return true if days.nil?
    @last_modified > (Time.now - (days.to_i * 86_400))
  end

  def attestation_json
    return @attestation_json if defined?(@attestation_json)
    @attestation_json =
      begin
        require "json"
        body = fetch_body
        body ? JSON.parse(body) : nil
      rescue JSON::ParserError, StandardError
        nil
      end
  end

  def to_s
    "Document Attestation '#{@uri}'"
  end

  private

  def fetch
    case @uri
    when %r{\As3://}     then fetch_s3
    when %r{\Ahttps?://} then fetch_http
    when %r{\Agithub://} then fetch_github
    when %r{\Agitlab://} then fetch_gitlab
    when %r{\Afile://}   then fetch_file(@uri.sub(%r{\Afile://}, ""))
    else                      fetch_file(@uri) # bare-path alias
    end
  end

  def fetch_s3
    @scheme = "s3"
    m = @uri.match(%r{\As3://([^/]+)/(.+)\z})
    return (@connection_error = "malformed s3 URI: #{@uri}") unless m
    @s3_bucket, @s3_key = m[1], m[2]
    begin
      require "aws-sdk-s3"
      resp = s3_client.head_object(bucket: @s3_bucket, key: @s3_key)
      @exists        = true
      @last_modified = resp.last_modified
    rescue Aws::S3::Errors::NotFound, Aws::S3::Errors::NoSuchKey
      @exists = false
    rescue Aws::S3::Errors::Forbidden, Aws::S3::Errors::AccessDenied => e
      @connection_error = "S3 access denied for #{@uri} (#{e.class.name.split('::').last}) — " \
                          "check the role's s3:GetObject + kms:Decrypt on the bucket CMK."
    rescue StandardError => e
      @connection_error = "S3 head_object failed for #{@uri}: #{e.class}: #{e.message}"
    end
  end

  def fetch_http
    @scheme = "https"
    require "net/http"
    require "uri"
    require "time"
    parsed = URI.parse(@uri)
    resp = Net::HTTP.start(parsed.host, parsed.port, use_ssl: parsed.scheme == "https") do |http|
      http.head(parsed.request_uri)
    end
    if resp.is_a?(Net::HTTPSuccess)
      @exists = true
      lm = resp["last-modified"]
      @last_modified = lm ? Time.httpdate(lm) : nil
    elsif resp.is_a?(Net::HTTPNotFound)
      @exists = false
    else
      @connection_error = "HTTP #{resp.code} for #{@uri}"
    end
  rescue StandardError => e
    @connection_error = "HTTP HEAD failed for #{@uri}: #{e.class}: #{e.message}"
  end

  # github://owner/repo/path/to/doc.md[@ref]
  # Existence + freshness from the commit history of the path: a non-empty
  # commits list means the path exists; the newest commit's date is the
  # "last changed" timestamp (history-aware, better than an mtime).
  def fetch_github
    @scheme = "github"
    rest = @uri.sub(%r{\Agithub://}, "")
    rest, ref = split_ref(rest)
    m = rest.match(%r{\A([^/]+)/([^/]+)/(.+)\z})
    return (@connection_error = "malformed github URI (expect github://owner/repo/path[@ref]): #{@uri}") unless m
    owner, repo, path = m[1], m[2], m[3]
    query = "path=#{url_encode(path)}&per_page=1"
    query += "&sha=#{url_encode(ref)}" if ref
    api = "https://api.github.com/repos/#{owner}/#{repo}/commits?#{query}"
    headers = {
      "Accept"               => "application/vnd.github+json",
      "X-GitHub-Api-Version" => "2022-11-28",
      "User-Agent"           => "document_attestation",
    }
    tok = git_token("GITHUB")
    headers["Authorization"] = "Bearer #{tok}" if tok
    commits = git_host_commits(api, headers)
    return if @connection_error
    if commits.is_a?(Array) && !commits.empty?
      @exists = true
      date = commits.first.dig("commit", "committer", "date") ||
             commits.first.dig("commit", "author", "date")
      @last_modified = parse_git_time(date)
    else
      @exists = false
    end
  end

  # gitlab://<url-encoded-project>/path/to/doc.md[@ref]
  # <url-encoded-project> is the namespaced project id with slashes encoded as
  # %2F (GitLab API convention), e.g. gitlab://group%2Frepo/policies/cp.md
  def fetch_gitlab
    @scheme = "gitlab"
    rest = @uri.sub(%r{\Agitlab://}, "")
    rest, ref = split_ref(rest)
    m = rest.match(%r{\A([^/]+)/(.+)\z})
    return (@connection_error = "malformed gitlab URI (expect gitlab://<enc-project>/path[@ref]): #{@uri}") unless m
    project, path = m[1], m[2]
    query = "path=#{url_encode(path)}&per_page=1"
    query += "&ref_name=#{url_encode(ref)}" if ref
    api = "https://gitlab.com/api/v4/projects/#{project}/repository/commits?#{query}"
    headers = { "User-Agent" => "document_attestation" }
    tok = git_token("GITLAB")
    headers["PRIVATE-TOKEN"] = tok if tok
    commits = git_host_commits(api, headers)
    return if @connection_error
    if commits.is_a?(Array) && !commits.empty?
      @exists = true
      date = commits.first["committed_date"] || commits.first["created_at"]
      @last_modified = parse_git_time(date)
    else
      @exists = false
    end
  end

  def fetch_file(path)
    @scheme = "file"
    if File.exist?(path) && File.readable?(path)
      @exists        = true
      @last_modified = File.mtime(path)
    else
      @exists = false
    end
  rescue StandardError => e
    @connection_error = "file read failed for #{@uri}: #{e.class}: #{e.message}"
  end

  def fetch_body
    case @scheme
    when "s3"
      return nil unless @exists
      require "aws-sdk-s3"
      s3_client.get_object(bucket: @s3_bucket, key: @s3_key).body.read
    when "https"
      require "net/http"
      require "uri"
      Net::HTTP.get(URI.parse(@uri))
    when "file"
      path = @uri.sub(%r{\Afile://}, "")
      File.read(path) if File.exist?(path)
    end
    # github/gitlab: body fetch deliberately unsupported — these providers
    # answer existence + freshness only (commit metadata), not document bodies.
  rescue StandardError
    nil
  end

  # --- git-host shared helpers --------------------------------------------

  # Split a trailing "@ref" off a github://owner/repo/path@ref form. Returns
  # [rest_without_ref, ref_or_nil]. Only splits on the LAST '@' so paths
  # without a ref are returned unchanged.
  def split_ref(rest)
    idx = rest.rindex("@")
    return [rest, nil] if idx.nil?
    [rest[0...idx], rest[(idx + 1)..]]
  end

  def git_token(host)
    return @token if @token && !@token.to_s.empty?
    env = ENV["ATTESTATION_#{host}_TOKEN"]
    env && !env.empty? ? env : nil
  end

  def url_encode(str)
    require "erb"
    ERB::Util.url_encode(str.to_s)
  end

  def parse_git_time(str)
    return nil if str.nil?
    require "time"
    Time.parse(str)
  rescue StandardError
    nil
  end

  # GET a git-host commits endpoint, parse the JSON array. Sets
  # @connection_error (and returns nil) on any non-2xx / transport error.
  def git_host_commits(api, headers)
    require "net/http"
    require "uri"
    require "json"
    parsed = URI.parse(api)
    resp = Net::HTTP.start(parsed.host, parsed.port, use_ssl: true) do |http|
      req = Net::HTTP::Get.new(parsed.request_uri)
      headers.each { |k, v| req[k] = v }
      http.request(req)
    end
    if resp.is_a?(Net::HTTPSuccess)
      JSON.parse(resp.body)
    elsif resp.is_a?(Net::HTTPNotFound)
      [] # project/repo or path not found -> treated as "does not exist"
    elsif resp.is_a?(Net::HTTPUnauthorized) || resp.is_a?(Net::HTTPForbidden)
      @connection_error = "git-host auth failed (HTTP #{resp.code}) for #{@uri} — " \
                          "check the ATTESTATION_*_TOKEN scope (Contents: read)."
      nil
    else
      @connection_error = "git-host HTTP #{resp.code} for #{@uri}"
      nil
    end
  rescue StandardError => e
    @connection_error = "git-host request failed for #{@uri}: #{e.class}: #{e.message}"
    nil
  end

  def s3_client
    @s3_client ||= Aws::S3::Client.new(region: @region)
  end
end
