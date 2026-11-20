using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace WindowsEventWitness.Core;

public sealed record GeminiEvidence(string Id, string Category, string Observation);
public sealed record GeminiFinding(string Kind, string Priority, int EvidenceCount, IReadOnlyList<GeminiEvidence> Evidence);
public sealed record GeminiReview(string Model, string Summary, IReadOnlyList<string> BenignExplanations,
    IReadOnlyList<string> Limitations, IReadOnlyList<string> NextChecks, IReadOnlyList<string> EvidenceIds, bool Cached);
public sealed record GeminiModelLimit(string Id, string Label, int RequestsPerMinute, int InputTokensPerMinute, int RequestsPerDay);
public sealed record GeminiQuotaStatus(GeminiModelLimit Model, int MinuteRequests, int MinuteInputTokens,
    int DayRequests, int AutoDayRequests, DateTimeOffset? PausedUntil);

public sealed class GeminiUnavailableException(string message, DateTimeOffset? retryAt = null) : Exception(message)
{
    public DateTimeOffset? RetryAt { get; } = retryAt;
}

public sealed class GeminiAdvisor : IDisposable
{
    public const int GlobalRequestsPerDay = 150;
    public const int GlobalAutomaticRequestsPerDay = 120;
    public const int GlobalRequestsPerMinute = 12;

    private const string ApiBase = "https://generativelanguage.googleapis.com/v1beta/";
    private const string GlobalPause = "all";
    private const string Instructions = "Review a redacted Windows observation for defensive triage. Distinguish observations from inference. Treat identifiers as opaque. Give a short explanation, plausible benign causes, missing evidence, and safe verification steps. Only cite evidence IDs from the input. Do not assert compromise, attribution, or absence of activity from this summary alone. Never give instructions for exploitation or evasion. Include no more than four short entries per list.";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private static readonly JsonElement ResponseSchema = JsonSerializer.Deserialize<JsonElement>("""
    {
        "type": "object",
        "properties": {
            "summary": { "type": "string" },
            "benignExplanations": { "type": "array", "items": { "type": "string" } },
            "limitations": { "type": "array", "items": { "type": "string" } },
            "nextChecks": { "type": "array", "items": { "type": "string" } },
            "evidenceIds": { "type": "array", "items": { "type": "string" } }
        },
        "required": ["summary", "benignExplanations", "limitations", "nextChecks", "evidenceIds"]
    }
    """);
    private static readonly string[] Kinds = ["Process chain", "Audit log cleared", "Service installed", "Security configuration changed", "Detection reported"];
    private static readonly string[] Priorities = ["Context", "Review", "Info", "Low", "Medium", "High", "Critical"];
    private static readonly string[] Categories = ["Process", "File", "Network", "Registry", "Audit", "Service", "Security", "DNS", "Other"];
    private static readonly string[] Observations = ["Parent and child process identifiers align", "Process origin could not be verified", "File activity recorded", "Network connection recorded", "Registry activity recorded", "Audit log clearing recorded", "Service installation recorded", "Security configuration change recorded", "Security product detection recorded", "Event recorded"];

    public static IReadOnlyList<GeminiModelLimit> QuotaProfile { get; } = Array.AsReadOnly(new[]
    {
        new GeminiModelLimit("gemini-3.5-flash-lite", "Gemini 3.5 Flash-Lite", 15, 250_000, 500),
        new GeminiModelLimit("gemini-3.1-flash-lite", "Gemini 3.1 Flash-Lite", 15, 250_000, 500),
        new GeminiModelLimit("gemini-4-hydrogen", "Gemini 4 Hydrogen", 5, 250_000, 20),
        new GeminiModelLimit("gemini-3.8-flash", "Gemini 3.8 Flash", 5, 250_000, 20),
        new GeminiModelLimit("gemini-3.6-flash", "Gemini 3.6 Flash", 5, 250_000, 20),
        new GeminiModelLimit("gemini-3-flash-preview", "Gemini 3 Flash Preview", 5, 250_000, 20),
        new GeminiModelLimit("gemini-2.5-flash-lite", "Gemini 2.5 Flash-Lite", 10, 250_000, 20),
        new GeminiModelLimit("gemini-2.5-flash", "Gemini 2.5 Flash", 5, 250_000, 20)
    });

    private static readonly TimeZoneInfo Pacific = TimeZoneInfo.FindSystemTimeZoneById("Pacific Standard Time");
    private readonly HttpClient client;
    private readonly bool ownsClient;
    private readonly TimeProvider clock;
    private readonly string usageFile;
    private readonly SemaphoreSlim reviewGate = new(1, 1);
    private readonly Dictionary<string, GeminiReview> cache = new(StringComparer.Ordinal);

    public GeminiAdvisor(string usageFile, HttpClient? httpClient = null, TimeProvider? timeProvider = null)
    {
        this.usageFile = Path.GetFullPath(usageFile);
        ownsClient = httpClient is null;
        client = httpClient ?? new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
        {
            Timeout = TimeSpan.FromSeconds(30),
            MaxResponseContentBufferSize = 2 * 1024 * 1024
        };
        clock = timeProvider ?? TimeProvider.System;
    }

    public static string Preview(GeminiFinding finding) => JsonSerializer.Serialize(Redact(finding).Payload,
        new JsonSerializerOptions(JsonOptions) { WriteIndented = true });

    public async Task<IReadOnlyList<GeminiModelLimit>> DiscoverAsync(string apiKey, CancellationToken ct = default)
    {
        var key = NormalizeKey(apiKey);
        var ids = new HashSet<string>(StringComparer.Ordinal);
        string? token = null;
        for (var page = 0; page < 10; page++)
        {
            var endpoint = "models?pageSize=100";
            if (!string.IsNullOrEmpty(token)) endpoint += "&pageToken=" + Uri.EscapeDataString(token);
            using var response = await SendAsync(HttpMethod.Get, endpoint, key, null, ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode) throw RequestError(response.StatusCode);
            var body = await ReadJsonAsync(response, ct).ConfigureAwait(false);
            foreach (var model in ArrayAt(body, "models"))
            {
                var name = TextAt(model, "name");
                if (name.StartsWith("models/", StringComparison.Ordinal) && ArrayAt(model, "supportedGenerationMethods")
                    .Any(item => item.ValueKind == JsonValueKind.String && item.GetString() == "generateContent"))
                    ids.Add(name[7..]);
            }
            token = TextAt(body, "nextPageToken");
            if (token.Length == 0) break;
        }
        return QuotaProfile.Where(model => ids.Contains(model.Id)).ToArray();
    }

    public IReadOnlyList<GeminiQuotaStatus> GetQuotaStatus()
    {
        var now = clock.GetUtcNow();
        return AccessUsage((state, _) =>
        {
            return QuotaProfile.Select(model =>
            {
                var today = state.Attempts.Where(attempt => attempt.Model == model.Id && PacificDay(attempt.At) == PacificDay(now)).ToArray();
                var minute = state.Attempts.Where(attempt => attempt.Model == model.Id && IsInMinute(attempt.At, now)).ToArray();
                var cooldown = Cooldown(state, model.Id);
                return new GeminiQuotaStatus(model, minute.Length, minute.Sum(attempt => attempt.InputTokens), today.Length,
                    today.Count(attempt => attempt.Automatic), cooldown > now ? cooldown : null);
            }).ToArray();
        }, write: false);
    }

    public async Task<GeminiReview> ReviewAsync(string apiKey, GeminiFinding finding, IReadOnlyList<string> enabledModelIds,
        bool automatic, CancellationToken ct = default)
    {
        var key = NormalizeKey(apiKey);
        var (payload, ids) = Redact(finding);
        if (automatic && payload.Priority is not ("High" or "Critical"))
            throw new GeminiUnavailableException("Automatic review covers high and critical findings.");
        var models = enabledModelIds.Distinct(StringComparer.Ordinal)
            .Select(id => QuotaProfile.FirstOrDefault(model => model.Id == id)).OfType<GeminiModelLimit>().ToArray();
        if (models.Length == 0) throw new GeminiUnavailableException("Select a discovered Gemini model to review this finding.");

        var input = JsonSerializer.Serialize(payload, JsonOptions);
        var fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(input)));
        await reviewGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var attempts = 0;
            DateTimeOffset? retryAt = null;
            foreach (var model in models)
            {
                ct.ThrowIfCancellationRequested();
                var cacheKey = model.Id + ":" + fingerprint;
                if (cache.TryGetValue(cacheKey, out var previous))
                    return MapIds(previous with { Cached = true }, ids);
                if (attempts >= 2) continue;
                var request = JsonSerializer.Serialize(new
                {
                    model = model.Id,
                    input,
                    system_instruction = Instructions,
                    store = false,
                    generation_config = new { max_output_tokens = 1536 },
                    response_format = new { type = "text", mime_type = "application/json", schema = ResponseSchema }
                }, JsonOptions);
                var reservation = Reserve(model, Encoding.UTF8.GetByteCount(request) + 256, automatic);
                if (reservation is not null)
                {
                    retryAt = Earliest(retryAt, reservation);
                    continue;
                }

                attempts++;
                using var response = await SendAsync(HttpMethod.Post, "interactions", key, request, ct).ConfigureAwait(false);
                if ((int)response.StatusCode == 429)
                {
                    var now = clock.GetUtcNow();
                    var error = await ReadErrorAsync(response, ct).ConfigureAwait(false);
                    var (until, modelScoped) = RateLimitPause(model, response, error, now);
                    Pause(modelScoped ? model.Id : GlobalPause, until);
                    if (!modelScoped) throw new GeminiUnavailableException("Google paused this project. The finding is available locally.", until);
                    retryAt = Earliest(retryAt, until);
                    continue;
                }
                if (response.StatusCode == HttpStatusCode.NotFound)
                {
                    var until = clock.GetUtcNow().AddMinutes(15);
                    Pause(model.Id, until);
                    retryAt = Earliest(retryAt, until);
                    continue;
                }
                if ((int)response.StatusCode >= 500)
                {
                    var now = clock.GetUtcNow();
                    var until = HeaderPause(response, now) ?? now.AddSeconds(60);
                    Pause(GlobalPause, until);
                    throw new GeminiUnavailableException("Gemini is temporarily unavailable. The finding is available locally.", until);
                }
                if (!response.IsSuccessStatusCode) throw RequestError(response.StatusCode);
                var body = await ReadJsonAsync(response, ct).ConfigureAwait(false);
                var review = ParseReview(model.Id, body);
                if (cache.Count >= 512) cache.Remove(cache.Keys.First());
                cache[cacheKey] = review;
                return MapIds(review, ids);
            }
            throw new GeminiUnavailableException("Selected Gemini models are outside their current review budget or unavailable.", retryAt);
        }
        finally
        {
            reviewGate.Release();
        }
    }

    private static (WireFinding Payload, Dictionary<string, string> Ids) Redact(GeminiFinding finding)
    {
        var ids = new Dictionary<string, string>(StringComparer.Ordinal);
        var rows = new List<GeminiEvidence>();
        foreach (var evidence in finding.Evidence.Take(12))
        {
            if (string.IsNullOrEmpty(evidence.Id)) continue;
            var alias = "E" + (rows.Count + 1).ToString(CultureInfo.InvariantCulture);
            ids[alias] = evidence.Id;
            rows.Add(new GeminiEvidence(alias, Canonical(Categories, evidence.Category, "Other"),
                Canonical(Observations, evidence.Observation, "Event recorded")));
        }
        return (new WireFinding(Canonical(Kinds, finding.Kind, "Other finding"),
            Canonical(Priorities, finding.Priority, "Unknown"), Math.Clamp(finding.EvidenceCount, 0, 1_000_000), rows), ids);
    }

    private static string Canonical(IEnumerable<string> accepted, string value, string fallback) =>
        accepted.FirstOrDefault(item => string.Equals(item, value, StringComparison.OrdinalIgnoreCase)) ?? fallback;

    private static GeminiReview MapIds(GeminiReview review, Dictionary<string, string> ids) => review with
    {
        EvidenceIds = review.EvidenceIds.Where(ids.ContainsKey).Select(id => ids[id]).Distinct(StringComparer.Ordinal).ToArray()
    };

    private async Task<HttpResponseMessage> SendAsync(HttpMethod method, string endpoint, string key, string? body, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(method, ApiBase + endpoint);
        request.Headers.Add("x-goog-api-key", key);
        if (body is not null)
        {
            request.Headers.Add("Api-Revision", "2026-05-20");
            request.Content = new StringContent(body, Encoding.UTF8, "application/json");
        }
        try { return await client.SendAsync(request, ct).ConfigureAwait(false); }
        catch (HttpRequestException)
        {
            throw new GeminiUnavailableException("Gemini could not be reached. Check your network connection.");
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new GeminiUnavailableException("Gemini did not respond within the connection timeout.");
        }
    }

    private static async Task<JsonElement> ReadJsonAsync(HttpResponseMessage response, CancellationToken ct)
    {
        try
        {
            var text = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            return JsonSerializer.Deserialize<JsonElement>(text);
        }
        catch (JsonException)
        {
            throw new GeminiUnavailableException("Gemini returned an unreadable response.");
        }
    }

    private static async Task<JsonElement> ReadErrorAsync(HttpResponseMessage response, CancellationToken ct)
    {
        try { return await ReadJsonAsync(response, ct).ConfigureAwait(false); }
        catch (GeminiUnavailableException) { return default; }
    }

    private static GeminiReview ParseReview(string model, JsonElement body)
    {
        var content = ArrayAt(body, "steps").Where(step => TextAt(step, "type") == "model_output")
            .SelectMany(step => ArrayAt(step, "content")).Where(part => TextAt(part, "type") == "text")
            .Select(part => TextAt(part, "text"));
        JsonElement result;
        try { result = JsonSerializer.Deserialize<JsonElement>(string.Concat(content)); }
        catch (JsonException) { throw new GeminiUnavailableException("Gemini returned no valid structured review."); }
        var summary = Clean(TextAt(result, "summary"), 800);
        if (summary.Length == 0 || new[] { "benignExplanations", "limitations", "nextChecks", "evidenceIds" }
            .Any(name => !result.TryGetProperty(name, out var field) || field.ValueKind != JsonValueKind.Array))
            throw new GeminiUnavailableException("Gemini returned an incomplete structured review.");
        return new GeminiReview(model, summary, SafeList(result, "benignExplanations"), SafeList(result, "limitations"),
            SafeList(result, "nextChecks"), SafeList(result, "evidenceIds", 12, 8), false);
    }

    private static string[] SafeList(JsonElement root, string name, int count = 4, int length = 240) => ArrayAt(root, name)
        .Where(value => value.ValueKind == JsonValueKind.String).Take(count)
        .Select(value => Clean(value.GetString() ?? "", length)).Where(value => value.Length > 0).ToArray();

    private static string Clean(string value, int length) => string.Concat(value.Take(length)
        .Select(character => char.IsWhiteSpace(character) ? ' ' : character)
        .Where(character => !char.IsControl(character) && CharUnicodeInfo.GetUnicodeCategory(character) != UnicodeCategory.Format)).Trim();

    private static JsonElement FieldAt(JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value) ? value : default;

    private static string TextAt(JsonElement element, string name)
    {
        var value = FieldAt(element, name);
        return value.ValueKind == JsonValueKind.String ? value.GetString() ?? "" : "";
    }

    private static IEnumerable<JsonElement> ArrayAt(JsonElement element, string name)
    {
        var value = FieldAt(element, name);
        return value.ValueKind == JsonValueKind.Array ? value.EnumerateArray() : Enumerable.Empty<JsonElement>();
    }

    private DateTimeOffset? Reserve(GeminiModelLimit model, int inputTokens, bool automatic)
    {
        return AccessUsage<DateTimeOffset?>((state, now) =>
        {
            var cooldown = Cooldown(state, model.Id);
            if (cooldown > now) return cooldown;
            var today = state.Attempts.Where(attempt => PacificDay(attempt.At) == PacificDay(now)).ToArray();
            var modelToday = today.Where(attempt => attempt.Model == model.Id).ToArray();
            var autoModelLimit = model.RequestsPerDay - Math.Max(3, (model.RequestsPerDay + 4) / 5);
            if (today.Length >= GlobalRequestsPerDay || modelToday.Length >= model.RequestsPerDay ||
                automatic && (today.Length >= GlobalAutomaticRequestsPerDay || modelToday.Length >= autoModelLimit))
                return NextPacificMidnight(now);
            var minute = state.Attempts.Where(attempt => IsInMinute(attempt.At, now)).OrderBy(attempt => attempt.At).ToArray();
            var modelMinute = minute.Where(attempt => attempt.Model == model.Id).ToArray();
            if (minute.Length >= GlobalRequestsPerMinute) return minute[0].At.AddMinutes(1);
            if (modelMinute.Length >= model.RequestsPerMinute || modelMinute.Sum(attempt => attempt.InputTokens) + inputTokens > model.InputTokensPerMinute)
                return modelMinute.Length == 0 ? now.AddMinutes(1) : modelMinute[0].At.AddMinutes(1);
            state.Attempts.Add(new Attempt(model.Id, now, inputTokens, automatic));
            return null;
        });
    }

    private void Pause(string scope, DateTimeOffset until) => AccessUsage((state, _) =>
    {
        if (!state.Cooldowns.TryGetValue(scope, out var previous) || previous < until) state.Cooldowns[scope] = until;
        return true;
    });

    private T AccessUsage<T>(Func<UsageData, DateTimeOffset, T> access, bool write = true)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(usageFile)!);
            using var fileLock = OpenUsageLock();
            var state = File.Exists(usageFile)
                ? JsonSerializer.Deserialize<UsageData>(File.ReadAllText(usageFile), JsonOptions) ?? throw new JsonException()
                : new UsageData([], []);
            var now = clock.GetUtcNow();
            state.Attempts.RemoveAll(attempt => PacificDay(attempt.At) < PacificDay(now) && !IsInMinute(attempt.At, now));
            foreach (var expired in state.Cooldowns.Where(entry => entry.Value <= now).Select(entry => entry.Key).ToArray())
                state.Cooldowns.Remove(expired);
            var result = access(state, now);
            if (write)
            {
                var pending = usageFile + ".pending";
                using (var stream = new FileStream(pending, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    JsonSerializer.Serialize(stream, state, JsonOptions);
                    stream.Flush(flushToDisk: true);
                }
                File.Move(pending, usageFile, overwrite: true);
            }
            return result;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            throw new GeminiUnavailableException("The local usage ledger is unavailable. Review is paused until it can be read and written.");
        }
    }

    private FileStream OpenUsageLock()
    {
        for (var attempt = 0; ; attempt++)
        {
            try { return new FileStream(usageFile + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
            catch (IOException) when (attempt < 5) { Thread.Sleep(20); }
        }
    }

    private static DateTimeOffset Cooldown(UsageData state, string model)
    {
        var global = state.Cooldowns.GetValueOrDefault(GlobalPause);
        var local = state.Cooldowns.GetValueOrDefault(model);
        return global > local ? global : local;
    }

    private static (DateTimeOffset Until, bool ModelScoped) RateLimitPause(GeminiModelLimit model, HttpResponseMessage response,
        JsonElement error, DateTimeOffset now)
    {
        var until = HeaderPause(response, now) ?? now.AddMinutes(1);
        var details = ArrayAt(FieldAt(error, "error"), "details").ToArray();
        var violations = details.SelectMany(detail => ArrayAt(detail, "violations")).ToArray();
        var modelScoped = violations.Length != 0 && violations.All(violation =>
            TextAt(FieldAt(violation, "quotaDimensions"), "model") == model.Id);
        if (modelScoped && violations.Any(violation => TextAt(violation, "quotaId").Contains("PerDay", StringComparison.OrdinalIgnoreCase)))
        {
            var reset = NextPacificMidnight(now);
            if (reset > until) until = reset;
        }
        foreach (var detail in details)
        {
            var delay = TextAt(detail, "retryDelay");
            if (delay.EndsWith('s') && double.TryParse(delay[..^1], NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out var seconds)
                && double.IsFinite(seconds) && seconds > 0 && seconds < TimeSpan.FromDays(365).TotalSeconds)
            {
                var retry = now.AddSeconds(seconds);
                if (retry > until) until = retry;
            }
        }
        return (until, modelScoped);
    }

    private static DateTimeOffset? HeaderPause(HttpResponseMessage response, DateTimeOffset now)
    {
        var retry = response.Headers.RetryAfter;
        if (retry?.Date is DateTimeOffset date && date > now) return date;
        if (retry?.Delta is TimeSpan delay && delay > TimeSpan.Zero) return now + delay;
        return null;
    }

    private static DateTime PacificDay(DateTimeOffset value) => TimeZoneInfo.ConvertTime(value, Pacific).Date;
    private static bool IsInMinute(DateTimeOffset value, DateTimeOffset now) => value > now.AddMinutes(-1);
    private static DateTimeOffset NextPacificMidnight(DateTimeOffset now) => TimeZoneInfo.ConvertTimeToUtc(PacificDay(now).AddDays(1), Pacific);
    private static DateTimeOffset? Earliest(DateTimeOffset? previous, DateTimeOffset? candidate) =>
        previous is null || candidate < previous ? candidate : previous;

    private static GeminiUnavailableException RequestError(HttpStatusCode status) => status switch
    {
        HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => new("Gemini rejected access for this key or project."),
        HttpStatusCode.BadRequest => new("Gemini rejected the request. Check the key in AI Studio and try an available model."),
        HttpStatusCode.TooManyRequests => new("Gemini reported a request limit. Wait before testing the connection again."),
        _ => new($"Gemini returned HTTP {(int)status}. The finding is available locally.")
    };

    internal static string NormalizeKey(string apiKey)
    {
        var key = apiKey.Trim();
        if (key.Length is < 20 or > 256 || key.Any(value => !char.IsAsciiLetterOrDigit(value) && value is not ('-' or '_' or '.')))
            throw new ArgumentException("Enter a Gemini API key from Google AI Studio.");
        return key;
    }

    public void Dispose()
    {
        if (ownsClient) client.Dispose();
    }

    private sealed record WireFinding(string Kind, string Priority, int EvidenceCount, IReadOnlyList<GeminiEvidence> Evidence);
    private sealed record Attempt(string Model, DateTimeOffset At, int InputTokens, bool Automatic);
    private sealed record UsageData(List<Attempt> Attempts, Dictionary<string, DateTimeOffset> Cooldowns);
}

public static class GeminiCredential
{
    private const string Target = "WindowsEventWitness/GeminiApiKey";
    private const uint Generic = 1;
    private const uint LocalMachine = 2;
    private const int NotFound = 1168;

    public static string? Load()
    {
        if (!CredRead(Target, Generic, 0, out var pointer))
        {
            var error = Marshal.GetLastWin32Error();
            if (error == NotFound) return null;
            throw new Win32Exception(error, "Windows could not open the Gemini credential.");
        }
        try
        {
            var credential = Marshal.PtrToStructure<Credential>(pointer);
            if (credential.BlobSize is < 1 or > 256 || credential.Blob == IntPtr.Zero) return null;
            var bytes = new byte[credential.BlobSize];
            try
            {
                Marshal.Copy(credential.Blob, bytes, 0, bytes.Length);
                return Encoding.UTF8.GetString(bytes);
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        finally { CredFree(pointer); }
    }

    public static void Save(string key)
    {
        var bytes = Encoding.UTF8.GetBytes(GeminiAdvisor.NormalizeKey(key));
        var pin = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        try
        {
            var credential = new Credential
            {
                Type = Generic, TargetName = Target, BlobSize = bytes.Length,
                Blob = pin.AddrOfPinnedObject(), Persist = LocalMachine, UserName = "Gemini API key"
            };
            if (!CredWrite(ref credential, 0))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Windows could not store the Gemini credential.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
            pin.Free();
        }
    }

    public static void Remove()
    {
        if (CredDelete(Target, Generic, 0)) return;
        var error = Marshal.GetLastWin32Error();
        if (error != NotFound) throw new Win32Exception(error, "Windows could not remove the Gemini credential.");
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Credential
    {
        public uint Flags;
        public uint Type;
        public string TargetName;
        public string? Comment;
        public FILETIME LastWritten;
        public int BlobSize;
        public IntPtr Blob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public string? TargetAlias;
        public string UserName;
    }

    [DllImport("advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CredRead(string targetName, uint type, uint flags, out IntPtr credential);

    [DllImport("advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CredWrite(ref Credential credential, uint flags);

    [DllImport("advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CredDelete(string targetName, uint type, uint flags);

    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern void CredFree(IntPtr credential);
}
