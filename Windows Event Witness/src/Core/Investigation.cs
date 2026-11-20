using System.IO;
using System.Text.Json;

namespace WindowsEventWitness.Core;

public sealed record Finding(string Kind, string Priority, string Detail, string[] EvidenceIds);

public sealed record Comparison(string Category, string Activity, string Provider, int EventId, int Baseline, int Current)
{
    public int Delta => Current - Baseline;
}

public static class Investigation
{
    public static Finding[] Findings(EvidenceCase evidence, EvidenceLink[] links)
    {
        var findings = new List<Finding>();
        foreach (var record in evidence.Events)
        {
            var signal = Match(record);
            if (signal is { } match)
                findings.Add(new Finding(match.Kind, match.Priority, match.Detail, [record.Id]));
        }

        var rows = evidence.Events.ToDictionary(record => record.Id, StringComparer.Ordinal);
        var uncertain = links.Where(link => link.Certainty == "Uncertain" && rows.ContainsKey(link.ToId)).ToArray();
        if (uncertain.Length > 0)
        {
            findings.Add(new Finding("Process chain", "Context", $"{uncertain.Length:N0} linked events have an unverified process origin in this case.",
                uncertain.Select(link => link.ToId).Distinct().Take(8).ToArray()));
        }

        return findings.ToArray();
    }

    public static GeminiFinding ForReview(Finding finding, IReadOnlyDictionary<string, EvidenceEvent> rows, EvidenceLink[] links)
    {
        var evidence = new List<GeminiEvidence>();
        foreach (var id in finding.EvidenceIds)
        {
            if (!rows.TryGetValue(id, out var record))
                continue;

            var observation = finding.Kind switch
            {
                "Audit log cleared" => "Audit log clearing recorded",
                "Service installed" => "Service installation recorded",
                "Security configuration changed" => "Security configuration change recorded",
                "Detection reported" => "Security product detection recorded",
                "Process chain" when links.Any(link => link.ToId == id && link.Certainty == "Uncertain") => "Process origin could not be verified",
                "Process chain" => "Parent and child process identifiers align",
                _ => "Event recorded"
            };
            evidence.Add(new GeminiEvidence(id, record.Category, observation));
        }

        return new GeminiFinding(finding.Kind, finding.Priority, evidence.Count, evidence);
    }

    public static Comparison[] Compare(EvidenceCase baseline, EvidenceCase current)
    {
        var previous = Counts(baseline);
        var now = Counts(current);
        return previous.Keys.Union(now.Keys)
            .Select(key => new Comparison(key.Category, key.Activity, key.Provider, key.EventId, previous.GetValueOrDefault(key), now.GetValueOrDefault(key)))
            .Where(row => row.Delta != 0)
            .OrderByDescending(row => Math.Abs(row.Delta))
            .ThenBy(row => row.Category, StringComparer.Ordinal)
            .ThenBy(row => row.EventId)
            .ToArray();
    }

    private static Dictionary<(string Category, string Activity, string Provider, int EventId), int> Counts(EvidenceCase evidence) =>
        evidence.Events.GroupBy(record => (record.Category, record.Title, record.Provider, record.EventId))
            .ToDictionary(group => group.Key, group => group.Count());

    private static (string Kind, string Priority, string Detail)? Match(EvidenceEvent record)
    {
        if ((record.Provider == "Microsoft-Windows-Eventlog" && record.EventId == 104) ||
            (record.Provider == "Microsoft-Windows-Eventlog" && record.EventId == 1102))
            return ("Audit log cleared", "High", "An event provider recorded a log-clearing operation. Check who initiated it and whether it matches an approved change.");

        if ((record.Provider == "Service Control Manager" && record.EventId == 7045) ||
            (record.Provider == "Microsoft-Windows-Security-Auditing" && record.EventId == 4697))
            return ("Service installed", "Review", "Windows recorded a service installation. Compare its time and service details with approved software changes.");

        if ((record.Provider == "Microsoft-Windows-Security-Auditing" && record.EventId == 4719) ||
            (record.Provider == "Microsoft-Windows-Windows Defender" && record.EventId == 5007))
            return ("Security configuration changed", "Review", "Windows recorded a security configuration change. Check the original record and the expected policy.");

        if (record.Provider == "Microsoft-Windows-Windows Defender" && record.EventId == 1116)
            return ("Detection reported", "High", "Microsoft Defender reported a detection. Check its classification and subsequent remediation records.");

        return null;
    }
}

public sealed class UserSettings
{
    public bool WalkthroughComplete { get; set; }
    public bool AutoReview { get; set; }
    public string[] EnabledModels { get; set; } = [];

    public static UserSettings Load(string path)
    {
        try
        {
            if (File.Exists(path) && new FileInfo(path).Length <= 32768)
                return JsonSerializer.Deserialize<UserSettings>(File.ReadAllText(path)) ?? new UserSettings();
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException)
        {
            return new UserSettings();
        }

        return new UserSettings();
    }

    public void Save(string path)
    {
        var pending = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllText(pending, JsonSerializer.Serialize(this));
            File.Move(pending, path, true);
        }
        finally
        {
            if (File.Exists(pending))
                File.Delete(pending);
        }
    }
}
