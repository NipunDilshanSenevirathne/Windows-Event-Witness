using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using WindowsEventWitness.Core;

var tests = new (string Name, Func<Task> Run)[]
{
    ("Model discovery, redaction and evidence references", TestDiscoveryAndRedaction),
    ("Model-scoped fallback and shared rate limit", TestRateLimitScope),
    ("Model limits, manual reserve and Pacific reset", TestModelBudget),
    ("App-wide minute and daily budgets", TestAppBudget)
};
foreach (var test in tests)
{
    await test.Run();
    Console.WriteLine($"PASS {test.Name}");
}

static async Task TestDiscoveryAndRedaction()
{
    var listRequests = 0;
    using var fixture = new Fixture(async request =>
    {
        if (request.Method == HttpMethod.Get)
        {
            listRequests++;
            if (listRequests == 1)
                return Reply(200, """
                {"models":[{"name":"models/gemini-3.1-flash-lite","supportedGenerationMethods":["generateContent"]},{"name":"models/gemini-3.8-flash","supportedGenerationMethods":["embedContent"]}],"nextPageToken":"a+b c"}
                """);
            Check(request.RequestUri!.Query.Contains("pageToken=a%2Bb%20c", StringComparison.Ordinal), "Page token was not encoded");
            return Reply(200, """
            {"models":[{"name":"models/gemini-3.5-flash-lite","supportedGenerationMethods":["generateContent"]},{"name":"models/unbudgeted-model","supportedGenerationMethods":["generateContent"]}]}
            """);
        }

        Check(request.RequestUri!.AbsolutePath.EndsWith("/interactions", StringComparison.Ordinal), "Review endpoint differs");
        Check(request.Headers.GetValues("Api-Revision").Single() == "2026-05-20", "Interaction revision missing");
        using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync());
        var root = body.RootElement;
        Check(root.GetProperty("model").GetString() == Fixture.FlashLite, "Review routed to a different model");
        Check(!root.GetProperty("store").GetBoolean() && !root.TryGetProperty("tools", out _), "Request enables server state or tools");
        Check(root.GetProperty("response_format").GetProperty("mime_type").GetString() == "application/json", "Structured output missing");
        var requestText = root.GetProperty("input").GetString()!;
        Check(!requestText.Contains("Private", StringComparison.OrdinalIgnoreCase), "The raw local evidence reached the request");
        using var evidence = JsonDocument.Parse(requestText);
        var first = evidence.RootElement.GetProperty("evidence")[0];
        Check(first.GetProperty("id").GetString() == "E1", "Local evidence ID was sent");
        Check(first.GetProperty("category").GetString() == "Other", "Unknown category was not redacted");
        Check(first.GetProperty("observation").GetString() == "Event recorded", "Unknown observation was not redacted");
        return Review("E1", "invented");
    });
    using var advisor = fixture.NewAdvisor();
    var models = await advisor.DiscoverAsync(Fixture.FakeKey);
    Check(models.Select(model => model.Id).SequenceEqual([Fixture.FlashLite, Fixture.OtherFlashLite]), "Discovery did not filter by capability and quota profile");

    var privateFinding = Finding(5, "C:\\Private\\File.txt");
    var preview = GeminiAdvisor.Preview(privateFinding);
    Check(!preview.Contains("Private", StringComparison.OrdinalIgnoreCase), "Preview included private evidence");
    var firstReview = await advisor.ReviewAsync(Fixture.FakeKey, privateFinding, [Fixture.FlashLite], true);
    Check(firstReview.EvidenceIds.SequenceEqual(["C:\\Private\\File.txt"]) && !firstReview.Cached, "Invalid citations were returned or known IDs were lost");
    var secondReview = await advisor.ReviewAsync(Fixture.FakeKey, Finding(5, "private://different-record"), [Fixture.FlashLite], true);
    Check(secondReview.EvidenceIds.SequenceEqual(["private://different-record"]) && secondReview.Cached, "Cached citations were not remapped");
    Check(fixture.Calls == 3, "A duplicate consumed an API request");
}

static async Task TestRateLimitScope()
{
    var failShared = false;
    using var fixture = new Fixture(async request =>
    {
        using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync());
        var model = body.RootElement.GetProperty("model").GetString();
        if (failShared)
        {
            Check(model == Fixture.OtherFlashLite, "Daily scoped pause did not skip its unavailable model");
            var result = Reply(429, """{"error":{"details":[{"retryDelay":"90s"}]}}""");
            result.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromSeconds(50));
            return result;
        }
        if (model == Fixture.FlashLite)
            return Reply(429, """
            {"error":{"details":[{"violations":[{"quotaId":"GenerateRequestsPerDayPerProjectPerModel","quotaDimensions":{"model":"gemini-3.5-flash-lite"}}]},{"retryDelay":"20s"}]}}
            """);
        return Review();
    });
    using var advisor = fixture.NewAdvisor();
    string[] models = [Fixture.FlashLite, Fixture.OtherFlashLite];
    var answer = await advisor.ReviewAsync(Fixture.FakeKey, Finding(1), models, true);
    Check(answer.Model == Fixture.OtherFlashLite && fixture.Calls == 2, "Model-scoped limit did not use one authorized fallback");
    var status = advisor.GetQuotaStatus();
    Check(status[0].DayRequests == 1 && status[1].DayRequests == 1, "Attempts were not counted");
    Check(status[0].PausedUntil == DateTimeOffset.Parse("2026-11-21T08:00:00Z"), "Model day limit resumed before Pacific midnight");

    failShared = true;
    var paused = await ExpectUnavailable(advisor.ReviewAsync(Fixture.FakeKey, Finding(2), models, true));
    using var reopened = fixture.NewAdvisor();
    var blocked = await ExpectUnavailable(reopened.ReviewAsync(Fixture.FakeKey, Finding(3), ["gemini-4-hydrogen"], false));
    Check(paused.RetryAt == fixture.Clock.Now.AddSeconds(90) && paused.RetryAt == blocked.RetryAt,
        "Shared rate limit or provider cooldown was not honored across app restarts");
    Check(fixture.Calls == 3, "Shared 429 attempted another model");
}

static async Task TestModelBudget()
{
    using var fixture = new Fixture(_ => Task.FromResult(Review()));
    using var advisor = fixture.NewAdvisor();
    string[] model = ["gemini-4-hydrogen"];
    for (var i = 0; i < 5; i++)
        await advisor.ReviewAsync(Fixture.FakeKey, Finding(i), model, true);
    var minute = await ExpectUnavailable(advisor.ReviewAsync(Fixture.FakeKey, Finding(5), model, true));
    Check(minute.RetryAt == fixture.Clock.Now.AddMinutes(1), "Model rolling-minute limit missing");
    for (var i = 5; i < 16; i++)
    {
        fixture.Clock.Now = fixture.Clock.Now.AddMinutes(1);
        await advisor.ReviewAsync(Fixture.FakeKey, Finding(i), model, true);
    }

    fixture.Clock.Now = fixture.Clock.Now.AddMinutes(1);
    await ExpectUnavailable(advisor.ReviewAsync(Fixture.FakeKey, Finding(16), model, true));
    for (var i = 16; i < 20; i++)
        await advisor.ReviewAsync(Fixture.FakeKey, Finding(i), model, false);
    await ExpectUnavailable(advisor.ReviewAsync(Fixture.FakeKey, Finding(20), model, false));

    using var restarted = fixture.NewAdvisor();
    fixture.Clock.Now = DateTimeOffset.Parse("2026-11-21T07:59:59Z");
    await ExpectUnavailable(restarted.ReviewAsync(Fixture.FakeKey, Finding(21), model, false));
    fixture.Clock.Now = fixture.Clock.Now.AddSeconds(1);
    await restarted.ReviewAsync(Fixture.FakeKey, Finding(21), model, false);
    Check(fixture.Calls == 21, "Model daily cap, manual reserve or exact Pacific reset failed");
}

static async Task TestAppBudget()
{
    using var fixture = new Fixture(_ => Task.FromResult(Review()));
    using var advisor = fixture.NewAdvisor();
    string[] models = [Fixture.FlashLite, Fixture.OtherFlashLite];
    var low = Finding(1) with { Priority = "Low" };
    await ExpectUnavailable(advisor.ReviewAsync(Fixture.FakeKey, low, models, true));
    for (var i = 0; i < GeminiAdvisor.GlobalRequestsPerMinute; i++)
        await advisor.ReviewAsync(Fixture.FakeKey, Finding(i), models, true);
    await ExpectUnavailable(advisor.ReviewAsync(Fixture.FakeKey, Finding(12), models, true));
    Check(fixture.Calls == 12, "Different model bypassed the app-wide minute cap");

    for (var i = 12; i < GeminiAdvisor.GlobalAutomaticRequestsPerDay; i++)
    {
        if (i % 12 == 0) fixture.Clock.Now = fixture.Clock.Now.AddMinutes(1);
        await advisor.ReviewAsync(Fixture.FakeKey, Finding(i), models, true);
    }
    fixture.Clock.Now = fixture.Clock.Now.AddMinutes(1);
    await ExpectUnavailable(advisor.ReviewAsync(Fixture.FakeKey, Finding(120), models, true));
    for (var i = 120; i < GeminiAdvisor.GlobalRequestsPerDay; i++)
    {
        if (i % 12 == 0) fixture.Clock.Now = fixture.Clock.Now.AddMinutes(1);
        await advisor.ReviewAsync(Fixture.FakeKey, Finding(i), models, false);
    }
    await ExpectUnavailable(advisor.ReviewAsync(Fixture.FakeKey, Finding(150), models, false));
    Check(fixture.Calls == 150, "App-wide automatic reserve or hard day cap failed");
}

static GeminiFinding Finding(int count, string record = "local-record") =>
    new("Audit log cleared", "High", count, [new(record, "PrivateCategory", "Private observation")]);

static HttpResponseMessage Review(params string[] ids)
{
    var text = JsonSerializer.Serialize(new
    {
        summary = "An audit log operation was recorded.",
        benignExplanations = new[] { "Approved system maintenance" },
        limitations = new[] { "Process context is missing" },
        nextChecks = new[] { "Compare with a maintenance record" },
        evidenceIds = ids
    });
    return Reply(200, JsonSerializer.Serialize(new
    {
        steps = new[] { new { type = "model_output", content = new[] { new { type = "text", text } } } }
    }));
}

static HttpResponseMessage Reply(int status, string body) =>
    new((HttpStatusCode)status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

static async Task<GeminiUnavailableException> ExpectUnavailable(Task<GeminiReview> request)
{
    try { await request; }
    catch (GeminiUnavailableException exception) { return exception; }
    throw new InvalidOperationException("Expected Gemini review to be unavailable");
}

static void Check(bool condition, string reason)
{
    if (!condition) throw new InvalidOperationException(reason);
}

sealed class Fixture : IDisposable
{
    public const string FlashLite = "gemini-3.5-flash-lite";
    public const string OtherFlashLite = "gemini-3.1-flash-lite";
    public const string FakeKey = "fake-test-key-with-no-network";

    private readonly DirectoryInfo directory = Directory.CreateTempSubdirectory("event-witness-gemini-");
    private readonly StubHandler handler;
    private readonly HttpClient client;

    public Fixture(Func<HttpRequestMessage, Task<HttpResponseMessage>> respond)
    {
        handler = new StubHandler(respond);
        client = new HttpClient(handler);
    }

    public FakeClock Clock { get; } = new();
    public int Calls => handler.Calls;
    public GeminiAdvisor NewAdvisor() => new(Path.Combine(directory.FullName, "usage.json"), client, Clock);

    public void Dispose()
    {
        client.Dispose();
        foreach (FileInfo file in directory.GetFiles()) file.Delete();
        directory.Delete();
    }

    private sealed class StubHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> respond) : HttpMessageHandler
    {
        public int Calls { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (request.RequestUri?.Host != "generativelanguage.googleapis.com" || request.RequestUri.Query.Contains(FakeKey) ||
                request.Headers.GetValues("x-goog-api-key").Single() != FakeKey)
                throw new InvalidOperationException("Unexpected API destination or credential carriage");
            Calls++;
            return respond(request);
        }
    }
}

sealed class FakeClock : TimeProvider
{
    public DateTimeOffset Now { get; set; } = DateTimeOffset.Parse("2026-11-20T22:00:00Z");
    public override DateTimeOffset GetUtcNow() => Now;
}
