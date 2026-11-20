using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Microsoft.Win32;
using WindowsEventWitness.Core;

namespace WindowsEventWitness;

public partial class MainWindow : Window
{
    private static readonly string UserDirectory = Environment.GetEnvironmentVariable("WINDOWS_EVENT_WITNESS_DATA") is { Length: > 0 } directory
        ? Path.GetFullPath(directory)
        : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Windows Event Witness", "Data");
    private readonly string settingsFile;
    private readonly UserSettings settings;
    private readonly GeminiAdvisor advisor;
    private readonly CancellationTokenSource lifetime = new();
    private CancellationTokenSource reviews = new();
    private readonly Dictionary<Finding, GeminiReview> answers = [];
    private readonly HashSet<Finding> pending = [];
    private EvidenceCase? activeCase;
    private EvidenceCase? baseline;
    private Dictionary<string, EvidenceEvent> evidence = new(StringComparer.Ordinal);
    private EvidenceLink[] links = [];
    private Finding[] findings = [];
    private bool busy;
    private bool unsaved;

    public MainWindow()
    {
        Directory.CreateDirectory(UserDirectory);
        settingsFile = Path.Combine(UserDirectory, "settings.json");
        settings = UserSettings.Load(settingsFile);
        settings.EnabledModels ??= [];
        advisor = new GeminiAdvisor(Path.Combine(UserDirectory, "gemini-usage.json"));
        InitializeComponent();
        RefreshReview();
    }

    private void FirstLaunch(object sender, RoutedEventArgs e)
    {
        Loaded -= FirstLaunch;
        if (!settings.WalkthroughComplete)
            ShowWalkthrough();
    }

    private void OpenWalkthrough(object sender, RoutedEventArgs e) => ShowWalkthrough();

    private void ShowWalkthrough()
    {
        var tour = new WalkthroughDialog(this, ShowSettings);
        tour.ShowDialog();
        if (tour.DialogResult == true)
        {
            settings.WalkthroughComplete = true;
            PersistSettings();
            if (tour.LoadDemo && MayReplaceCase())
                DisplayCase(EvidenceCapture.CreateDemo());
        }
    }

    private void OpenSettings(object sender, RoutedEventArgs e) => ShowSettings(this);

    private void ShowSettings(Window owner)
    {
        var dialog = new GeminiSettingsDialog(owner, advisor, settings);
        if (dialog.ShowDialog() == true)
        {
            ResetReviewQueue();
            PersistSettings();
            RefreshReview();
            QueueAutomaticReviews();
        }
    }

    private void PersistSettings()
    {
        try
        {
            settings.Save(settingsFile);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            SetStatus("Settings could not be saved. " + error.Message);
        }
    }

    private async void CollectEvents(object sender, RoutedEventArgs e)
    {
        if (busy || !MayReplaceCase())
            return;
        var dialog = new CaptureDialog(this);
        if (dialog.ShowDialog() != true)
            return;
        await RunOperation("Reading Windows event logs…", async () =>
        {
            var result = await Task.Run(() => EvidenceCapture.CollectRecent(dialog.Hours, dialog.RecordLimit, lifetime.Token, dialog.Channels), lifetime.Token);
            DisplayCase(result, true);
        });
    }

    private async void OpenCase(object sender, RoutedEventArgs e)
    {
        if (busy || !MayReplaceCase())
            return;
        var file = new OpenFileDialog { Filter = "Windows Event Witness cases (*.wew)|*.wew", CheckFileExists = true };
        if (file.ShowDialog(this) != true)
            return;
        await RunOperation("Verifying case integrity…", async () =>
        {
            var result = await Task.Run(() => EvidenceCaseFile.Load(file.FileName), lifetime.Token);
            DisplayCase(result);
        });
    }

    private async void ImportEvents(object sender, RoutedEventArgs e)
    {
        if (busy || !MayReplaceCase())
            return;
        var file = new OpenFileDialog { Filter = "Windows event logs (*.evtx)|*.evtx", CheckFileExists = true };
        if (file.ShowDialog(this) != true)
            return;
        await RunOperation("Reading the EVTX export…", async () =>
        {
            var result = await Task.Run(() => EvidenceCapture.ImportEvtx(file.FileName, cancellationToken: lifetime.Token), lifetime.Token);
            DisplayCase(result, true);
        });
    }

    private async void SaveCase(object sender, RoutedEventArgs e)
    {
        if (busy || activeCase is not { } current)
            return;
        var file = new SaveFileDialog { Filter = "Windows Event Witness case (*.wew)|*.wew", DefaultExt = ".wew", AddExtension = true, FileName = "Investigation.wew" };
        if (file.ShowDialog(this) != true)
            return;
        await RunOperation("Saving the case…", async () =>
        {
            await Task.Run(() => EvidenceCaseFile.Save(file.FileName, current), lifetime.Token);
            unsaved = false;
            SetStatus("Case saved to " + file.FileName);
        });
    }

    private void LoadExample(object sender, RoutedEventArgs e)
    {
        if (!busy && MayReplaceCase())
            DisplayCase(EvidenceCapture.CreateDemo());
    }

    private async void SelectBaseline(object sender, RoutedEventArgs e)
    {
        if (busy || activeCase is null)
            return;
        var file = new OpenFileDialog { Filter = "Windows Event Witness cases (*.wew)|*.wew", CheckFileExists = true };
        if (file.ShowDialog(this) != true)
            return;
        await RunOperation("Loading the baseline…", async () =>
        {
            baseline = await Task.Run(() => EvidenceCaseFile.Load(file.FileName), lifetime.Token);
            RefreshComparison();
            SetStatus("Baseline loaded.");
        });
    }

    private async Task RunOperation(string message, Func<Task> operation)
    {
        busy = true;
        UpdateActions();
        SetStatus(message);
        try
        {
            await operation();
        }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested)
        {
        }
        catch (Exception error)
        {
            SetStatus("Operation failed. " + error.Message);
        }
        finally
        {
            busy = false;
            UpdateActions();
        }
    }

    private void DisplayCase(EvidenceCase current, bool needsSave = false)
    {
        ResetReviewQueue();
        activeCase = current;
        unsaved = needsSave;
        evidence = current.Events.ToDictionary(record => record.Id, StringComparer.Ordinal);
        links = EvidenceGraph.Build(current);
        findings = Investigation.Findings(current, links);
        answers.Clear();
        CaseTitle.Text = current.Title;
        CaseInfo.Text = FormattableString.Invariant($"{current.Events.Length:N0} events   /   {links.Length:N0} relationships   /   Collected {current.CapturedUtc:yyyy-MM-dd HH:mm} UTC");
        CoverageList.ItemsSource = current.Coverage;
        CoverageEmpty.Visibility = current.Coverage.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
        RelationshipGrid.ItemsSource = links.Select(link => new RelationshipRow(link, GetTitle(link.FromId), GetTitle(link.ToId))).ToArray();
        FindingGrid.ItemsSource = findings;
        FilterBox.Clear();
        FilterTimeline();
        RefreshComparison();
        RefreshReview();
        UpdateActions();
        Sections.SelectedItem = TimelineTab;
        Inspector.SelectedItem = OverviewTab;
        TimelineGrid.SelectedIndex = current.Events.Length > 0 ? 0 : -1;
        if (current.Events.Length == 0)
            DisplayEvent(null);
        SetStatus(current.Events.Length > 0 ? "Case ready. Select a row to inspect its source record." : "No matching events. Review source coverage for details.");
        QueueAutomaticReviews();
    }

    private void ResetReviewQueue()
    {
        reviews.Cancel();
        reviews.Dispose();
        reviews = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
        pending.Clear();
    }

    private void FilterChanged(object sender, TextChangedEventArgs e) => FilterTimeline();

    private void FilterTimeline()
    {
        if (TimelineGrid is null || FilterCount is null)
            return;
        var query = FilterBox.Text.Trim();
        var rows = activeCase?.Events.Where(record => query.Length == 0 ||
            record.Title.Contains(query, StringComparison.OrdinalIgnoreCase) ||
            record.Summary.Contains(query, StringComparison.OrdinalIgnoreCase) ||
            record.Category.Contains(query, StringComparison.OrdinalIgnoreCase) ||
            record.Provider.Contains(query, StringComparison.OrdinalIgnoreCase) ||
            record.EventId.ToString(CultureInfo.InvariantCulture) == query)
            .Select(record => new TimelineRow(record)).ToArray() ?? [];
        TimelineGrid.ItemsSource = rows;
        FilterCount.Text = activeCase is null ? "" : $"{rows.Length:N0} shown";
    }

    private void TimelineSelected(object sender, SelectionChangedEventArgs e)
    {
        if (TimelineGrid.SelectedItem is TimelineRow row)
            DisplayEvent(row.Event);
    }

    private void RelationshipSelected(object sender, SelectionChangedEventArgs e)
    {
        if (RelationshipGrid.SelectedItem is not RelationshipRow row)
        {
            RelationshipCard.Visibility = Visibility.Collapsed;
            return;
        }

        RelationshipCard.Visibility = Visibility.Visible;
        EdgeFrom.Content = row.From;
        EdgeFrom.ToolTip = row.From;
        EdgeFrom.IsEnabled = evidence.ContainsKey(row.Link.FromId);
        EdgeTo.Content = row.To;
        EdgeTo.ToolTip = row.To;
        EdgeReason.Text = row.Link.Certainty + " · " + row.Link.Description;
        DisplayEvent(evidence.GetValueOrDefault(row.Link.ToId));
    }

    private void OpenEdgeFrom(object sender, RoutedEventArgs e)
    {
        if (RelationshipGrid.SelectedItem is RelationshipRow row)
            JumpToEvidence(row.Link.FromId);
    }

    private void OpenEdgeTo(object sender, RoutedEventArgs e)
    {
        if (RelationshipGrid.SelectedItem is RelationshipRow row)
            JumpToEvidence(row.Link.ToId);
    }

    private void FindingSelected(object sender, SelectionChangedEventArgs e)
    {
        if (FindingGrid.SelectedItem is Finding finding)
        {
            DetailPanel.Children.Clear();
            InspectorTitle.Text = finding.Kind;
            AddField(DetailPanel, finding.Priority + " priority", finding.Detail);
            AddEvidenceButtons(DetailPanel, finding.EvidenceIds);
            RawRecord.Text = "";
            Inspector.SelectedItem = OverviewTab;
        }
        RefreshReview();
    }

    private void DisplayEvent(EvidenceEvent? record)
    {
        DetailPanel.Children.Clear();
        InspectorTitle.Text = record?.Title ?? "Select an event";
        RawRecord.Text = record?.RawXml ?? "";
        if (record is null)
            return;

        AddField(DetailPanel, "Observation", record.Summary);
        AddField(DetailPanel, "Time (UTC)", record.TimestampUtc.ToString("yyyy-MM-dd HH:mm:ss.fff 'UTC'", CultureInfo.InvariantCulture));
        AddField(DetailPanel, "Source", record.Provider + " · " + record.Channel);
        AddField(DetailPanel, "Host", record.Computer);
        AddField(DetailPanel, "Event / record ID", $"{record.EventId} / {record.RecordId?.ToString(CultureInfo.InvariantCulture) ?? "Unavailable"}");
        foreach (var pair in record.Fields.Take(40))
            AddField(DetailPanel, pair.Key, pair.Value);
        if (record.Fields.Count > 40)
            AddField(DetailPanel, "Additional fields", "See Raw XML for the complete Windows event.");
    }

    private void JumpToEvidence(string id)
    {
        if (!evidence.TryGetValue(id, out var record))
            return;
        FilterBox.Clear();
        Sections.SelectedItem = TimelineTab;
        Inspector.SelectedItem = OverviewTab;
        var row = TimelineGrid.Items.OfType<TimelineRow>().FirstOrDefault(candidate => candidate.Event.Id == id);
        if (row is not null)
        {
            TimelineGrid.SelectedItem = row;
            TimelineGrid.ScrollIntoView(row);
        }
        DisplayEvent(record);
    }

    private void RefreshReview()
    {
        if (ReviewPanel is null)
            return;
        ReviewPanel.Children.Clear();
        if (FindingGrid.SelectedItem is not Finding finding)
        {
            AddField(ReviewPanel, "Review a finding", "Select a finding in the Findings tab to preview its redacted evidence summary.");
            return;
        }

        if (answers.TryGetValue(finding, out var review))
        {
            AddField(ReviewPanel, review.Cached ? "Gemini review · cached" : "Gemini review", review.Summary);
            AddField(ReviewPanel, "Model", review.Model);
            AddReviewSection("Plausible explanations", review.BenignExplanations);
            AddReviewSection("Evidence limitations", review.Limitations);
            AddReviewSection("Next checks", review.NextChecks);
            AddEvidenceButtons(ReviewPanel, review.EvidenceIds);
            AddReviewButton(finding, "Review with preferred model");
            return;
        }

        AddField(ReviewPanel, "Data sent for review", GeminiAdvisor.Preview(Investigation.ForReview(finding, evidence, links)), true);
        AddReviewButton(finding, "Review with Gemini");
    }

    private void AddReviewButton(Finding finding, string label)
    {
        var action = new Button { Content = pending.Contains(finding) ? "Review in progress…" : label, IsEnabled = !pending.Contains(finding) };
        action.Click += async (_, _) => await ReviewFinding(finding, false, reviews.Token);
        ReviewPanel.Children.Add(action);
    }

    private void AddReviewSection(string label, IReadOnlyList<string> entries)
    {
        if (entries.Count != 0)
            AddField(ReviewPanel, label, string.Join(Environment.NewLine, entries.Select(entry => "• " + entry)));
    }

    private async void QueueAutomaticReviews()
    {
        if (!settings.AutoReview || settings.EnabledModels.Length == 0)
            return;

        var token = reviews.Token;
        var queue = findings.Where(finding => finding.Priority is "High" or "Critical").DistinctBy(finding => finding.Kind).Take(4).ToArray();
        foreach (var finding in queue)
        {
            if (token.IsCancellationRequested)
                break;
            await ReviewFinding(finding, true, token);
        }
    }

    private async Task ReviewFinding(Finding finding, bool automatic, CancellationToken token)
    {
        if ((automatic && answers.ContainsKey(finding)) || !pending.Add(finding))
            return;
        try
        {
            var key = GeminiCredential.Load();
            if (string.IsNullOrWhiteSpace(key) || settings.EnabledModels.Length == 0)
            {
                if (!automatic)
                    SetStatus("Connect Gemini and select a model in Settings to review a finding.");
                return;
            }

            RefreshReview();
            var request = Investigation.ForReview(finding, evidence, links);
            var answer = await advisor.ReviewAsync(key, request, settings.EnabledModels, automatic, token);
            if (token.IsCancellationRequested)
                return;
            answers[finding] = answer;
            SetStatus("Gemini review ready. Open the Gemini tab to read it.");
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
        }
        catch (GeminiUnavailableException error)
        {
            if (!token.IsCancellationRequested)
                SetStatus(error.RetryAt is { } retry ? $"Gemini paused until {retry.ToLocalTime():g} or later. Try the review again then." : error.Message);
        }
        catch (Exception error)
        {
            if (!token.IsCancellationRequested)
                SetStatus("Gemini review could not be completed. " + error.Message);
        }
        finally
        {
            if (!token.IsCancellationRequested)
            {
                pending.Remove(finding);
                RefreshReview();
            }
        }
    }

    private void RefreshComparison()
    {
        if (activeCase is not { } current || baseline is not { } reference)
            return;
        var changes = Investigation.Compare(reference, current);
        ComparisonGrid.ItemsSource = changes;
        ComparisonSummary.Text = $"Baseline: {reference.Title} · {changes.Length:N0} changed event groups. Review coverage before interpreting a difference.";
    }

    private void AddEvidenceButtons(Panel panel, IEnumerable<string> ids)
    {
        foreach (var id in ids.Distinct())
        {
            if (!evidence.ContainsKey(id))
                continue;
            var button = new Button { Content = "Open " + GetTitle(id), Margin = new Thickness(0, 0, 0, 6), HorizontalContentAlignment = HorizontalAlignment.Left };
            button.Click += (_, _) => JumpToEvidence(id);
            panel.Children.Add(button);
        }
    }

    private static void AddField(Panel panel, string label, string value, bool mono = false)
    {
        var heading = new TextBlock { Text = label, Margin = new Thickness(0, 0, 0, 3) };
        heading.SetResourceReference(StyleProperty, "Label");
        var content = new TextBlock { Text = value, Margin = new Thickness(0, 0, 0, 12) };
        content.SetResourceReference(StyleProperty, "Muted");
        if (mono)
            content.FontFamily = new System.Windows.Media.FontFamily("Consolas");
        panel.Children.Add(heading);
        panel.Children.Add(content);
    }

    private string GetTitle(string id) => evidence.TryGetValue(id, out var record) ? Describe(record) : "Origin unavailable";

    private static string Describe(EvidenceEvent record)
    {
        if (record.Category is "Process" or "File")
        {
            var separator = record.Summary.LastIndexOfAny(['\\', '/']);
            var name = separator >= 0 ? record.Summary[(separator + 1)..] : "";
            if (name.Length is > 0 and <= 60)
                return record.Title + " · " + name;
        }

        if (record.Category == "Network" && record.Summary.Length is > 0 and <= 60)
            return record.Title + " · " + record.Summary;

        return record.Title;
    }

    private bool MayReplaceCase() => !unsaved || MessageBox.Show(this, "The current case has unsaved evidence. Discard the current case?",
        "Unsaved case", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) == MessageBoxResult.Yes;

    private void WindowClosing(object? sender, CancelEventArgs e)
    {
        e.Cancel = busy || !MayReplaceCase();
        if (e.Cancel)
            return;
        lifetime.Cancel();
        reviews.Cancel();
        advisor.Dispose();
        reviews.Dispose();
        lifetime.Dispose();
    }

    private void SetStatus(string message) => Status.Text = message;

    private void UpdateActions()
    {
        CaptureButton.IsEnabled = OpenButton.IsEnabled = ImportButton.IsEnabled = DemoButton.IsEnabled = !busy;
        SaveButton.IsEnabled = BaselineButton.IsEnabled = !busy && activeCase is not null;
        Mouse.OverrideCursor = busy ? Cursors.Wait : null;
    }

    public sealed record TimelineRow(EvidenceEvent Event)
    {
        public string Time => Event.TimestampUtc.ToString("MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture);
        public string Category => Event.Category;
        public string Title => Describe(Event);
        public int EventId => Event.EventId;
        public override string ToString() => $"{Time} UTC, {Category}, {Title}, event {EventId}";
    }

    public sealed record RelationshipRow(EvidenceLink Link, string From, string To)
    {
        public string Certainty => Link.Certainty;
        public override string ToString() => $"{From} to {To}. {Certainty}.";
    }
}
