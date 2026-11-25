using System;

namespace V2SubAuto.Models
{
    public sealed record PipelineSnapshot
    {
        public bool IsRunning { get; init; }
        public string CurrentStage { get; init; } = "Idle";
        public string DetailMessage { get; init; } = "Ready";
        public double ProgressPercent { get; init; }

        public int FetchedCount { get; init; }
        public int AfterDedupCount { get; init; }
        public int AfterTcpingCount { get; init; }
        public int AfterRealDelayCount { get; init; }
        public int FinalSurvivingCount { get; init; }

        public DateTime? LastCompletedUtc { get; init; }
        public DateTime? NextScheduledUtc { get; init; }
    }
}
