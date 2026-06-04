# encoding: UTF-8
#
# aws_guardduty_ecs_coverage — GuardDuty Runtime Monitoring coverage for ECS/
# Fargate. GuardDuty is NOT in inspec-aws's AwsConnection closed list, so this
# uses the public aws_client(klass) escape hatch (per memory
# feedback_inspec_aws_connection_closed_list).
#
#   describe aws_guardduty_ecs_coverage do
#     it { should be_detector_enabled }
#     it { should be_runtime_monitoring_enabled }
#   end
#
# CAVEAT (exec_validated: false): `detector_enabled?` rests on the stable
# list_detectors + get_detector.status == 'ENABLED' API. `runtime_monitoring_enabled?`
# inspects the get_detector `features` array for a RUNTIME_MONITORING feature in
# 'ENABLED' status — the exact v2 feature name / ECS-Fargate additional-config
# shape should be confirmed against a real GuardDuty configuration before relying
# on a FAIL from this accessor.

class AwsGuarddutyEcsCoverage < AwsResourceBase
  name "aws_guardduty_ecs_coverage"
  desc "GuardDuty Runtime Monitoring coverage (detector + RUNTIME_MONITORING feature)."
  example "
    describe aws_guardduty_ecs_coverage do
      it { should be_runtime_monitoring_enabled }
    end
  "

  def initialize(opts = {})
    super(opts)
    @detector_ids = []
    @enabled_detectors = []
    @runtime_feature_enabled = false
    catch_aws_errors do
      gd = @aws.aws_client(Aws::GuardDuty::Client)
      @detector_ids = Array(gd.list_detectors.detector_ids)
      @detector_ids.each do |id|
        d = gd.get_detector(detector_id: id)
        next unless d.status.to_s.casecmp("ENABLED").zero?
        @enabled_detectors << id
        feature = Array(d.features).find { |f| f.name.to_s.casecmp("RUNTIME_MONITORING").zero? }
        @runtime_feature_enabled = true if feature && feature.status.to_s.casecmp("ENABLED").zero?
      end
    end
  end

  def detector_enabled?
    !@enabled_detectors.empty?
  end

  def runtime_monitoring_enabled?
    detector_enabled? && @runtime_feature_enabled
  end

  def to_s
    "GuardDuty ECS Runtime-Monitoring coverage"
  end
end
