using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading;
using System.Xml;
using System.Xml.Linq;

namespace WindowsEventWitness.Core;

public sealed record EvidenceCase(string Title, DateTimeOffset CapturedUtc, EvidenceEvent[] Events, ChannelCoverage[] Coverage);

public sealed record ChannelCoverage(string Source, string State, int Count, string Detail);

public sealed record EvidenceEvent(
    string Id,
    DateTimeOffset TimestampUtc,
    string Computer,
    string Channel,
    string Provider,
    int EventId,
    long? RecordId,
    string Category,
    string Title,
    string Summary,
    string? ProcessGuid,
    string? ParentProcessGuid,
    int? ProcessId,
    int? ParentProcessId,
    Dictionary<string, string> Fields,
    string RawXml);

public sealed record EvidenceLink(string FromId, string ToId, string Description, string Certainty);

public static class EvidenceCapture
{
    private const string SysmonChannel = "Microsoft-Windows-Sysmon/Operational";
    private const string DefenderChannel = "Microsoft-Windows-Windows Defender/Operational";
    internal const int MaxCaptureXmlCharacters = 20_000_000;
    private const int MaxChannelXmlCharacters = 6_000_000;

    public static IReadOnlyList<string> DefaultChannels { get; } = Array.AsReadOnly(new[]
    {
        "System", "Application", "Security", SysmonChannel, DefenderChannel
    });

    public static EvidenceCase CollectRecent(
        int hours = 24,
        int maxPerChannel = 1000,
        CancellationToken cancellationToken = default,
        IReadOnlyList<string>? channels = null)
    {
        if (hours is < 1 or > 720)
            throw new ArgumentOutOfRangeException(nameof(hours), "Choose a window between 1 and 720 hours.");
        if (maxPerChannel is < 1 or > 10_000)
            throw new ArgumentOutOfRangeException(nameof(maxPerChannel));

        string[] sources = (channels ?? DefaultChannels).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (sources.Length is < 1 or > 10 || sources.Any(string.IsNullOrWhiteSpace))
            throw new ArgumentException("Select between one and ten event channels.", nameof(channels));

        DateTimeOffset started = DateTimeOffset.UtcNow;
        string start = started.AddHours(-hours).ToString("yyyy-MM-ddTHH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture);
        string end = started.ToString("yyyy-MM-ddTHH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture);
        string query = $"*[System[TimeCreated[@SystemTime >= '{start}' and @SystemTime <= '{end}']]]";
        var records = new List<EvidenceEvent>();
        var coverage = new List<ChannelCoverage>();
        int retainedCharacters = 0;

        foreach (string source in sources)
        {
            cancellationToken.ThrowIfCancellationRequested();
            coverage.Add(ReadSource(source, PathType.LogName, query, maxPerChannel, records, ref retainedCharacters, cancellationToken));
        }

        return new EvidenceCase($"Local recording · {hours:N0} h", started, OrderEvents(records), coverage.ToArray());
    }

    public static EvidenceCase ImportEvtx(string path, int maxEvents = 10_000, CancellationToken cancellationToken = default)
    {
        if (maxEvents is < 1 or > 25_000)
            throw new ArgumentOutOfRangeException(nameof(maxEvents));

        string fullPath = Path.GetFullPath(path);
        if (!string.Equals(Path.GetExtension(fullPath), ".evtx", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Select a Windows Event Log (.evtx) file.", nameof(path));
        if (!File.Exists(fullPath))
            throw new FileNotFoundException("The event log export could not be found.", fullPath);

        var records = new List<EvidenceEvent>();
        DateTimeOffset started = DateTimeOffset.UtcNow;
        int retainedCharacters = 0;
        ChannelCoverage coverage = ReadSource(fullPath, PathType.FilePath, "*", maxEvents, records, ref retainedCharacters, cancellationToken);
        return new EvidenceCase($"Import · {Path.GetFileName(fullPath)}", started, OrderEvents(records), new[] { coverage });
    }

    public static EvidenceCase CreateDemo()
    {
        DateTimeOffset started = new(2026, 1, 9, 10, 8, 0, TimeSpan.Zero);
        const string root = "{4e94c041-a035-4fc6-be1c-6ee0e01f6810}";
        const string worker = "{4e94c041-a035-4fc6-be1c-6ee0e01f6811}";
        const string child = "{4e94c041-a035-4fc6-be1c-6ee0e01f6812}";
        const string missing = "{4e94c041-a035-4fc6-be1c-6ee0e01f6813}";
        const string driver = @"C:\Program Files\Witness Demo\WitnessDemo.exe";
        const string helper = @"C:\Program Files\Witness Demo\ExampleWorker.exe";

        var records = new[]
        {
            DemoRecord(1, 1000, started, ("ProcessGuid", root), ("ProcessId", "7420"), ("Image", driver)),
            DemoRecord(1, 1001, started.AddSeconds(1), ("ProcessGuid", worker), ("ParentProcessGuid", root),
                ("ProcessId", "7584"), ("ParentProcessId", "7420"), ("Image", helper), ("ParentImage", driver)),
            DemoRecord(11, 1002, started.AddSeconds(2), ("ProcessGuid", worker), ("ProcessId", "7584"), ("Image", helper),
                ("TargetFilename", @"C:\ProgramData\Witness Demo\capture.json")),
            DemoRecord(3, 1003, started.AddSeconds(4), ("ProcessGuid", worker), ("ProcessId", "7584"), ("Image", helper),
                ("DestinationIp", "127.0.0.1"), ("DestinationPort", "8765"), ("Protocol", "tcp")),
            DemoRecord(1, 1004, started.AddSeconds(8), ("ProcessGuid", child), ("ParentProcessGuid", missing),
                ("ProcessId", "8120"), ("ParentProcessId", "8096"), ("Image", @"C:\Program Files\Witness Demo\Verifier.exe")),
            DemoRecord(5, 1005, started.AddSeconds(13), ("ProcessGuid", worker), ("ProcessId", "7584"), ("Image", helper))
        };

        return new EvidenceCase("Demo · Trace a local worker", started.AddSeconds(15), records, new[]
        {
            new ChannelCoverage(SysmonChannel, "Partial", records.Length,
                "Synthetic records include a missing parent so the timeline can demonstrate an unresolved relationship."),
            new ChannelCoverage("Security", "Unavailable", 0, "The demo contains Sysmon records only.")
        });
    }

    private static ChannelCoverage ReadSource(
        string source, PathType type, string filter, int limit, List<EvidenceEvent> output,
        ref int retainedCharacters, CancellationToken cancellationToken)
    {
        string label = type == PathType.FilePath ? Path.GetFileName(source) : source;
        int initialCount = output.Count;
        int sourceStartCharacters = retainedCharacters;
        int sourceCharacterLimit = type == PathType.FilePath ? MaxCaptureXmlCharacters : MaxChannelXmlCharacters;
        int unreadable = 0;
        string? clipReason = null;
        bool disabled = type == PathType.LogName && IsDisabled(source);

        try
        {
            var query = new EventLogQuery(source, type, filter) { ReverseDirection = true };
            using var reader = new EventLogReader(query);
            for (int examined = 0; ; examined++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                using EventRecord? record = reader.ReadEvent();
                if (record is null)
                    break;
                if (examined == limit)
                {
                    clipReason = $"The source has more than {limit:N0} matching records. Only the newest records were examined.";
                    break;
                }

                try
                {
                    string rawXml = record.ToXml();
                    if (retainedCharacters + rawXml.Length > MaxCaptureXmlCharacters ||
                        retainedCharacters - sourceStartCharacters + rawXml.Length > sourceCharacterLimit)
                    {
                        clipReason = "The retained XML reached its size limit. Older matching records were skipped.";
                        break;
                    }

                    output.Add(EvidenceXml.Parse(rawXml));
                    retainedCharacters += rawXml.Length;
                }
                catch (Exception failure) when (failure is EventLogException or XmlException or InvalidDataException)
                {
                    unreadable++;
                }
            }
        }
        catch (UnauthorizedAccessException)
        {
            return new ChannelCoverage(label, "Access denied", output.Count - initialCount,
                "Windows refused read access to this source for the current user.");
        }
        catch (EventLogProviderDisabledException)
        {
            return new ChannelCoverage(label, "Disabled", output.Count - initialCount, "Windows reports that the provider is disabled.");
        }
        catch (EventLogNotFoundException)
        {
            return new ChannelCoverage(label, "Missing", output.Count - initialCount,
                type == PathType.LogName ? "This channel is absent on the local system." : "The export could not be opened by Windows Event Log.");
        }
        catch (EventLogException failure)
        {
            int captured = output.Count - initialCount;
            return new ChannelCoverage(label, captured == 0 ? "Unavailable" : "Partial", captured,
                $"Windows stopped the read ({failure.HResult:X8}): {failure.Message}");
        }

        int count = output.Count - initialCount;
        var details = new List<string>();
        if (disabled)
            details.Add("The channel is currently disabled. Any retained records are included.");
        if (clipReason is not null)
            details.Add(clipReason);
        if (unreadable > 0)
            details.Add($"Windows returned {unreadable:N0} record(s) that could not be rendered or parsed.");
        if (details.Count == 0)
            details.Add(count == 0 ? "Windows returned no records for this selection." : "All records returned by this query were read.");

        string state = disabled ? "Disabled" : clipReason is not null ? "Clipped" : unreadable > 0 ? "Partial" : count == 0 ? "No matching records" : "Available";
        return new ChannelCoverage(label, state, count, string.Join(" ", details));
    }

    private static bool IsDisabled(string source)
    {
        try
        {
            using var config = new EventLogConfiguration(source);
            return !config.IsEnabled;
        }
        catch (Exception failure) when (failure is EventLogException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    internal static EvidenceEvent[] OrderEvents(IEnumerable<EvidenceEvent> events) => events
        .DistinctBy(item => item.Id, StringComparer.Ordinal)
        .OrderBy(item => item.TimestampUtc)
        .ThenBy(item => item.Computer, StringComparer.OrdinalIgnoreCase)
        .ThenBy(item => item.Channel, StringComparer.OrdinalIgnoreCase)
        .ThenBy(item => item.RecordId)
        .ThenBy(item => item.Id, StringComparer.Ordinal)
        .ToArray();

    private static EvidenceEvent DemoRecord(int id, long record, DateTimeOffset at, params (string Name, string Value)[] fields)
    {
        XNamespace ns = EvidenceXml.Namespace;
        var xml = new XElement(ns + "Event",
            new XElement(ns + "System",
                new XElement(ns + "Provider", new XAttribute("Name", EvidenceXml.Sysmon)),
                new XElement(ns + "EventID", id),
                new XElement(ns + "TimeCreated", new XAttribute("SystemTime", at.ToString("O", CultureInfo.InvariantCulture))),
                new XElement(ns + "EventRecordID", record),
                new XElement(ns + "Channel", SysmonChannel),
                new XElement(ns + "Computer", "WITNESS-DEMO")),
            new XElement(ns + "EventData", fields.Select(field => new XElement(ns + "Data", new XAttribute("Name", field.Name), field.Value))));
        return EvidenceXml.Parse(xml.ToString());
    }
}

public static class EvidenceGraph
{
    public static EvidenceLink[] Build(EvidenceCase evidence)
    {
        EvidenceEvent[] events = EvidenceCapture.OrderEvents(evidence.Events);
        var processStarts = new Dictionary<(string Computer, string Guid), EvidenceEvent>();
        var ambiguousStarts = new HashSet<(string Computer, string Guid)>();
        var links = new List<EvidenceLink>();

        foreach (EvidenceEvent item in events)
        {
            if (!EvidenceXml.IsSysmon(item) || item.EventId != 1 || item.ProcessGuid is null)
                continue;

            var key = Key(item, item.ProcessGuid);
            if (!processStarts.TryAdd(key, item))
                ambiguousStarts.Add(key);
        }

        foreach (EvidenceEvent item in events)
        {
            if (EvidenceXml.IsSysmon(item))
            {
                if (item.EventId == 1 && item.ParentProcessGuid is not null)
                    AddLink(item, item.ParentProcessGuid, "Parent launched this process", "Parent process creation is outside the evidence or ambiguous.");
                else if (item.EventId == 1 && item.ParentProcessId is not null)
                    links.Add(new EvidenceLink("", item.Id, "Parent PID is present without a process GUID.", "Uncertain"));
                else if (item.EventId != 1 && item.ProcessGuid is not null)
                    AddLink(item, item.ProcessGuid, "Activity attributed by process GUID", "Process creation is outside the evidence or ambiguous.");
            }
            else if (item.Category == "Process" && item.ParentProcessId is not null)
            {
                links.Add(new EvidenceLink("", item.Id, "Creator PID is present. A unique process identity is unavailable.", "Uncertain"));
            }
        }

        return links.ToArray();

        void AddLink(EvidenceEvent item, string processGuid, string observed, string uncertain)
        {
            var key = Key(item, processGuid);
            if (!ambiguousStarts.Contains(key) && processStarts.TryGetValue(key, out EvidenceEvent? start) &&
                start.Id != item.Id && start.TimestampUtc <= item.TimestampUtc)
            {
                links.Add(new EvidenceLink(start.Id, item.Id, observed, "Observed"));
                return;
            }

            links.Add(new EvidenceLink("", item.Id, uncertain, "Uncertain"));
        }
    }

    private static (string Computer, string Guid) Key(EvidenceEvent item, string guid) => (item.Computer.ToUpperInvariant(), guid);
}

public static class EvidenceCaseFile
{
    private const string Format = "WindowsEventWitness/1";
    private const int MaxFileBytes = 64 * 1024 * 1024;
    private const int MaxEvents = 50_000;
    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        MaxDepth = 48,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    private sealed record StoredCase(string Title, DateTimeOffset CapturedUtc, StoredEvent[] Events, ChannelCoverage[] Coverage);

    private sealed record StoredEvent(string Id, string RawXml);

    public static void Save(string path, EvidenceCase evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        if (evidence.Events is null || evidence.Events.Length > MaxEvents || evidence.Events.Any(item => item is null))
            throw new InvalidDataException("The case contains an invalid event collection.");
        var stored = new StoredCase(evidence.Title, evidence.CapturedUtc,
            evidence.Events.Select(item => new StoredEvent(item.Id, item.RawXml)).ToArray(), evidence.Coverage);
        Validate(stored);
        string fullPath = Path.GetFullPath(path);
        if (string.Equals(Path.GetExtension(fullPath), ".evtx", StringComparison.OrdinalIgnoreCase))
            throw new IOException("Choose a separate case file so the original event export is preserved.");

        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(stored, Options);
        if (payload.Length > MaxFileBytes - 512)
            throw new InvalidDataException("The case exceeds 64 MiB. Capture a smaller time window or fewer channels.");

        string directory = Path.GetDirectoryName(fullPath) ?? throw new IOException("The case destination is invalid.");
        string temporary = Path.Combine(directory, $".witness-{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            using (var envelope = new Utf8JsonWriter(stream))
            {
                envelope.WriteStartObject();
                envelope.WriteString("format", Format);
                envelope.WriteString("sha256", Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant());
                envelope.WritePropertyName("caseData");
                envelope.WriteRawValue(payload, skipInputValidation: true);
                envelope.WriteEndObject();
                envelope.Flush();
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporary, fullPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
                File.Delete(temporary);
        }
    }

    public static EvidenceCase Load(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length is < 1 or > MaxFileBytes)
            throw new InvalidDataException("The case must be between 1 byte and 64 MiB.");

        try
        {
            using JsonDocument json = JsonDocument.Parse(stream, new JsonDocumentOptions { MaxDepth = 48 });
            JsonElement root = json.RootElement;
            if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Count() != 3 ||
                !root.TryGetProperty("format", out JsonElement format) || format.ValueKind != JsonValueKind.String || format.GetString() != Format ||
                !root.TryGetProperty("sha256", out JsonElement digest) || digest.ValueKind != JsonValueKind.String ||
                !root.TryGetProperty("caseData", out JsonElement payload) || payload.ValueKind != JsonValueKind.Object)
                throw new InvalidDataException("This file does not contain a supported Windows Event Witness case.");

            string? expected = digest.GetString();
            if (expected is null || expected.Length != 64 || !expected.All(Uri.IsHexDigit))
                throw new InvalidDataException("The case has an invalid integrity value.");

            byte[] computed = SHA256.HashData(Encoding.UTF8.GetBytes(payload.GetRawText()));
            if (!CryptographicOperations.FixedTimeEquals(computed, Convert.FromHexString(expected)))
                throw new InvalidDataException("The case integrity check failed. The saved case data has changed.");

            StoredCase result = payload.Deserialize<StoredCase>(Options) ?? throw new InvalidDataException("The case data is empty.");
            Validate(result);
            var canonical = new EvidenceEvent[result.Events.Length];
            var ids = new HashSet<string>(StringComparer.Ordinal);
            for (int index = 0; index < canonical.Length; index++)
            {
                StoredEvent stored = result.Events[index];
                EvidenceEvent parsed = EvidenceXml.Parse(stored.RawXml);
                if (!string.Equals(parsed.Id, stored.Id, StringComparison.Ordinal) || !ids.Add(parsed.Id))
                    throw new InvalidDataException("The saved evidence contains an inconsistent or duplicate event identity.");
                canonical[index] = parsed;
            }

            return new EvidenceCase(result.Title, result.CapturedUtc, EvidenceCapture.OrderEvents(canonical), result.Coverage);
        }
        catch (Exception failure) when (failure is JsonException or XmlException)
        {
            throw new InvalidDataException("The case contains malformed data.", failure);
        }
    }

    private static void Validate(StoredCase evidence)
    {
        if (string.IsNullOrWhiteSpace(evidence.Title) || evidence.Title.Length > 1024 || evidence.CapturedUtc == default ||
            evidence.Events is null || evidence.Events.Length > MaxEvents || evidence.Coverage is null || evidence.Coverage.Length > 30)
            throw new InvalidDataException("The case metadata or event count is invalid.");

        if (evidence.Events.Any(item => item is null || string.IsNullOrEmpty(item.Id) ||
            string.IsNullOrEmpty(item.RawXml) || item.RawXml.Length > EvidenceXml.MaxRecordCharacters))
            throw new InvalidDataException("The case contains an invalid event record.");
        if (evidence.Events.Sum(item => (long)item.RawXml.Length) > EvidenceCapture.MaxCaptureXmlCharacters)
            throw new InvalidDataException("The raw event data exceeds the case limit.");

        if (evidence.Coverage.Any(item => item is null || string.IsNullOrEmpty(item.Source) ||
            string.IsNullOrEmpty(item.State) || item.Count < 0 || item.Detail is null))
            throw new InvalidDataException("The case coverage information is invalid.");
    }
}

internal static class EvidenceXml
{
    internal const string Namespace = "http://schemas.microsoft.com/win/2004/08/events/event";
    internal const string Sysmon = "Microsoft-Windows-Sysmon";
    internal const int MaxRecordCharacters = 512 * 1024;
    private const int MaxXmlDepth = 32;
    private const int MaxStructuredFields = 512;
    private const string Security = "Microsoft-Windows-Security-Auditing";
    private const string Defender = "Microsoft-Windows-Windows Defender";
    private const string EventLog = "Microsoft-Windows-Eventlog";
    private const string ServiceManager = "Service Control Manager";

    internal static bool IsSysmon(EvidenceEvent item) => ProviderIs(item.Provider, Sysmon);

    internal static EvidenceEvent Parse(string raw)
    {
        if (raw.Length == 0 || raw.Length > MaxRecordCharacters)
            throw new InvalidDataException("The event XML is missing or exceeds the per-record limit.");

        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = MaxRecordCharacters,
            MaxCharactersFromEntities = 0
        };
        using (var structuralInput = new StringReader(raw))
        using (XmlReader structure = XmlReader.Create(structuralInput, settings))
        {
            while (structure.Read())
                if (structure.Depth > MaxXmlDepth)
                    throw new InvalidDataException("The event XML is nested too deeply.");
        }

        using var input = new StringReader(raw);
        using XmlReader xml = XmlReader.Create(input, settings);
        XElement root = XElement.Load(xml, LoadOptions.None);
        XNamespace ns = Namespace;
        if (root.Name != ns + "Event" || root.Element(ns + "System") is not XElement system)
            throw new InvalidDataException("The XML has no Windows Event Log system metadata.");

        string computer = system.Element(ns + "Computer")?.Value.Trim() ?? "";
        string channel = system.Element(ns + "Channel")?.Value.Trim() ?? "";
        string provider = system.Element(ns + "Provider")?.Attribute("Name")?.Value.Trim() ?? "";
        string? timestamp = system.Element(ns + "TimeCreated")?.Attribute("SystemTime")?.Value;
        if (!int.TryParse(system.Element(ns + "EventID")?.Value, NumberStyles.None, CultureInfo.InvariantCulture, out int eventId) ||
            !DateTimeOffset.TryParse(timestamp, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out DateTimeOffset at) ||
            string.IsNullOrWhiteSpace(computer) || string.IsNullOrWhiteSpace(channel) || string.IsNullOrWhiteSpace(provider))
            throw new InvalidDataException("The event XML lacks an event ID, source, or valid timestamp.");

        at = at.ToUniversalTime();
        long? recordId = long.TryParse(system.Element(ns + "EventRecordID")?.Value,
            NumberStyles.None, CultureInfo.InvariantCulture, out long number) && number > 0 ? number : null;
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        int fieldIndex = 0;
        foreach (XElement data in root.Element(ns + "EventData")?.Elements(ns + "Data") ?? Enumerable.Empty<XElement>())
        {
            if (fieldIndex == MaxStructuredFields)
                break;
            fieldIndex++;
            string fieldName = data.Attribute("Name")?.Value.Trim() ?? "";
            if (fieldName.Length == 0)
                fieldName = $"Data[{fieldIndex}]";
            AddField(fields, fieldName, data.Value, fieldIndex);
        }

        foreach (XElement data in root.Element(ns + "UserData")?.Descendants() ?? Enumerable.Empty<XElement>())
        {
            if (fieldIndex == MaxStructuredFields)
                break;
            if (data.HasElements)
                continue;
            fieldIndex++;
            AddField(fields, data.Name.LocalName, data.Value, fieldIndex);
        }

        string? processGuid = null;
        string? parentGuid = null;
        int? pid = null;
        int? parentPid = null;
        if (ProviderIs(provider, Sysmon))
        {
            processGuid = ParseGuid(fields.GetValueOrDefault("ProcessGuid"));
            parentGuid = ParseGuid(fields.GetValueOrDefault("ParentProcessGuid"));
            pid = ParsePid(fields.GetValueOrDefault("ProcessId"));
            parentPid = ParsePid(fields.GetValueOrDefault("ParentProcessId"));
        }
        else if (ProviderIs(provider, Security) && eventId == 4688)
        {
            pid = ParsePid(fields.GetValueOrDefault("NewProcessId"));
            parentPid = ParsePid(fields.GetValueOrDefault("ProcessId"));
        }

        string identity = string.Join("\0", computer.ToUpperInvariant(), channel.ToUpperInvariant(),
            provider.ToUpperInvariant(), eventId.ToString(CultureInfo.InvariantCulture), at.ToString("O", CultureInfo.InvariantCulture),
            recordId?.ToString(CultureInfo.InvariantCulture) ?? Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw))));
        string id = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(identity))).ToLowerInvariant();
        (string category, string title, string summary) = Describe(provider, eventId, fields);

        return new EvidenceEvent(id, at, computer, channel, provider, eventId, recordId, category, title, summary,
            processGuid, parentGuid, pid, parentPid, fields, raw);
    }

    private static void AddField(Dictionary<string, string> fields, string key, string value, int index)
    {
        while (!fields.TryAdd(key, value))
            key += $" [{index}]";
    }

    private static string? ParseGuid(string? value) => Guid.TryParse(value, out Guid parsed) && parsed != Guid.Empty ? parsed.ToString("D") : null;

    private static int? ParsePid(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;

        value = value.Trim();
        bool hex = value.StartsWith("0x", StringComparison.OrdinalIgnoreCase);
        return int.TryParse(hex ? value[2..] : value, hex ? NumberStyles.AllowHexSpecifier : NumberStyles.None,
            CultureInfo.InvariantCulture, out int parsed) && parsed > 0 ? parsed : null;
    }

    private static bool ProviderIs(string provider, string expected) => string.Equals(provider, expected, StringComparison.OrdinalIgnoreCase);

    private static (string Category, string Title, string Summary) Describe(string provider, int id, Dictionary<string, string> fields)
    {
        string Field(string name, string fallback = "") => fields.TryGetValue(name, out string? value) && value.Length > 0
            ? value.Length <= 260 ? value : value[..257] + "…"
            : fallback;

        const string unavailable = "No additional event details.";
        switch (provider.ToUpperInvariant(), id)
        {
            case ("MICROSOFT-WINDOWS-SYSMON", 1): return ("Process", "Process started", Field("Image", unavailable));
            case ("MICROSOFT-WINDOWS-SYSMON", 2): return ("File", "File timestamp changed", Field("TargetFilename", unavailable));
            case ("MICROSOFT-WINDOWS-SYSMON", 3): return ("Network", "Network connection", $"{Field("DestinationIp", "Unknown destination")}:{Field("DestinationPort", "?")}");
            case ("MICROSOFT-WINDOWS-SYSMON", 5): return ("Process", "Process exited", Field("Image", unavailable));
            case ("MICROSOFT-WINDOWS-SYSMON", 6): return ("System", "Driver loaded", Field("ImageLoaded", unavailable));
            case ("MICROSOFT-WINDOWS-SYSMON", 7): return ("Image", "Image loaded", Field("ImageLoaded", unavailable));
            case ("MICROSOFT-WINDOWS-SYSMON", 8): return ("Process", "Remote thread recorded", Field("TargetImage", unavailable));
            case ("MICROSOFT-WINDOWS-SYSMON", 10): return ("Process", "Process access recorded", Field("TargetImage", unavailable));
            case ("MICROSOFT-WINDOWS-SYSMON", 11): return ("File", "File created or overwritten", Field("TargetFilename", unavailable));
            case ("MICROSOFT-WINDOWS-SYSMON", 12 or 13 or 14): return ("Registry", "Registry change", Field("TargetObject", unavailable));
            case ("MICROSOFT-WINDOWS-SYSMON", 22): return ("Network", "DNS query", Field("QueryName", unavailable));
            case ("MICROSOFT-WINDOWS-SYSMON", 23 or 26): return ("File", "File deleted", Field("TargetFilename", unavailable));
            case ("MICROSOFT-WINDOWS-SYSMON", 25): return ("Process", "Process tampering reported", Field("Image", unavailable));
        }

        if (ProviderIs(provider, Security))
        {
            return id switch
            {
                4624 => ("Logon", "Successful logon", Field("TargetUserName", unavailable)),
                4625 => ("Logon", "Failed logon", Field("TargetUserName", unavailable)),
                4688 => ("Process", "Process creation audited", Field("NewProcessName", unavailable)),
                4689 => ("Process", "Process termination audited", Field("ProcessName", unavailable)),
                4697 => ("System", "Service installation audited", Field("ServiceName", unavailable)),
                4698 => ("System", "Scheduled task created", Field("TaskName", unavailable)),
                4702 => ("System", "Scheduled task updated", Field("TaskName", unavailable)),
                _ => ("Security", $"Security audit event {id}", unavailable)
            };
        }

        if (ProviderIs(provider, Defender))
        {
            return id switch
            {
                1116 => ("Detection", "Defender detection", Field("Threat Name", unavailable)),
                1117 => ("Detection", "Defender action recorded", Field("Threat Name", unavailable)),
                5007 => ("Security", "Defender configuration changed", unavailable),
                _ => ("Defender", $"Defender event {id}", unavailable)
            };
        }

        if (ProviderIs(provider, EventLog) && id is 104 or 1102)
            return ("Coverage", "Event log clear recorded", Field("Channel", unavailable));

        if (ProviderIs(provider, ServiceManager) && id == 7045)
            return ("System", "Service installed", Field("ServiceName", unavailable));

        return ("Event", $"{provider} · {id}", Field("Data[1]", unavailable));
    }
}
