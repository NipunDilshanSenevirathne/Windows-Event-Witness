using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Input;
using WindowsEventWitness.Core;

namespace WindowsEventWitness;

internal abstract class WitnessDialog : Window
{
    protected readonly StackPanel Body = new();
    protected readonly StackPanel Actions = new() { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };

    protected WitnessDialog(Window owner, string title, int width, int height)
    {
        Owner = owner;
        Icon = owner.Icon;
        Title = title;
        Width = width;
        Height = height;
        MinWidth = Math.Min(width, 480);
        MinHeight = Math.Min(height, 350);
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;
        SetResourceReference(BackgroundProperty, "BackgroundBrush");
        SetResourceReference(ForegroundProperty, "InkBrush");
        FontSize = 14;

        var layout = new DockPanel { Margin = new Thickness(23) };
        Actions.Margin = new Thickness(0, 15, 0, 0);
        DockPanel.SetDock(Actions, Dock.Bottom);
        layout.Children.Add(Actions);
        layout.Children.Add(new ScrollViewer { Content = Body, VerticalScrollBarVisibility = ScrollBarVisibility.Auto });
        Content = layout;
    }

    protected static TextBlock Text(string text, bool heading = false)
    {
        var block = new TextBlock
        {
            Text = text,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 11),
            FontSize = heading ? 22 : 14,
            FontWeight = heading ? FontWeights.SemiBold : FontWeights.Normal
        };
        if (!heading)
            block.SetResourceReference(StyleProperty, "Muted");
        return block;
    }

    protected static Button Button(string label, Action action, bool primary = false)
    {
        var button = new Button { Content = label, Margin = new Thickness(7, 0, 0, 0), MinHeight = 36 };
        if (primary)
            button.SetResourceReference(StyleProperty, "PrimaryButton");
        button.Click += (_, _) => action();
        return button;
    }
}

internal sealed class WalkthroughDialog : WitnessDialog
{
    private int step;
    private readonly Action<Window> openGemini;
    public bool LoadDemo { get; private set; }

    public WalkthroughDialog(Window owner, Action<Window> openGemini) : base(owner, "Welcome to Windows Event Witness", 580, 390)
    {
        this.openGemini = openGemini;
        Render();
    }

    private void Render()
    {
        Body.Children.Clear();
        Actions.Children.Clear();
        Body.Children.Add(Text($"{step + 1} of 3"));
        if (step == 0)
        {
            Body.Children.Add(Text("Start with a case", true));
            Body.Children.Add(Text("Collect recent events from selected Windows logs, import an EVTX export, or open a saved case."));
            Body.Children.Add(Text("Source coverage shows which logs were readable and whether the record limit clipped the result."));
        }
        else if (step == 1)
        {
            Body.Children.Add(Text("Follow the evidence", true));
            Body.Children.Add(Text("Choose an event to see its original XML. Open Relationships to follow process identifiers and see where an origin could not be verified."));
            Body.Children.Add(Text("Save the case to reopen the same evidence later or compare it with a baseline."));
        }
        else
        {
            Body.Children.Add(Text("Optional Gemini review", true));
            Body.Children.Add(Text("Connect your own Google Gemini key to ask for an explanation of a local finding. The app shows the redacted summary before a manual review. Automatic review is a separate setting."));
            var connect = Button("Connect Gemini", () => openGemini(this));
            connect.HorizontalAlignment = HorizontalAlignment.Left;
            connect.Margin = new Thickness(0, 0, 0, 0);
            Body.Children.Add(connect);
        }

        if (step == 0)
            Actions.Children.Add(Button("Skip walkthrough", Finish));
        else
            Actions.Children.Add(Button("Back", () => { step--; Render(); }));

        if (step < 2)
        {
            var next = Button("Next", () => { step++; Render(); }, true);
            next.IsDefault = true;
            Actions.Children.Add(next);
        }
        else
        {
            Actions.Children.Add(Button("Finish", Finish));
            var example = Button("Open example case", () => { LoadDemo = true; Finish(); }, true);
            example.IsDefault = true;
            Actions.Children.Add(example);
        }
    }

    private void Finish() => DialogResult = true;
}

internal sealed class CaptureDialog : WitnessDialog
{
    private readonly ComboBox range = new() { ItemsSource = new[] { 1, 6, 24, 72, 168 }, SelectedIndex = 2, MinHeight = 32, Margin = new Thickness(0, 0, 0, 9) };
    private readonly ComboBox limit = new() { ItemsSource = new[] { 250, 500, 1000, 2000 }, SelectedIndex = 2, MinHeight = 32, Margin = new Thickness(0, 0, 0, 9) };
    private readonly List<CheckBox> sources = [];

    public CaptureDialog(Window owner) : base(owner, "Collect recent events", 550, 490)
    {
        Body.Children.Add(Text("Collect recent events", true));
        Body.Children.Add(Text("Select the channels and time range for a read-only capture."));
        Body.Children.Add(Text("Look back (hours)"));
        AutomationProperties.SetName(range, "Look back in hours");
        Body.Children.Add(range);
        Body.Children.Add(Text("Maximum events per channel"));
        AutomationProperties.SetName(limit, "Maximum events per channel");
        Body.Children.Add(limit);
        Body.Children.Add(Text("Windows Event Log channels"));
        var collect = Button("Collect", () => DialogResult = true, true);
        foreach (var source in EvidenceCapture.DefaultChannels)
        {
            var check = new CheckBox { Content = source, IsChecked = true };
            check.Checked += (_, _) => collect.IsEnabled = sources.Any(box => box.IsChecked == true);
            check.Unchecked += (_, _) => collect.IsEnabled = sources.Any(box => box.IsChecked == true);
            sources.Add(check);
            Body.Children.Add(check);
        }
        collect.IsDefault = true;
        Actions.Children.Add(Button("Cancel", () => DialogResult = false));
        Actions.Children.Add(collect);
    }

    public int Hours => (int)range.SelectedItem;
    public int RecordLimit => (int)limit.SelectedItem;
    public string[] Channels => sources.Where(box => box.IsChecked == true).Select(box => (string)box.Content).ToArray();
}

internal sealed class GeminiSettingsDialog : WitnessDialog
{
    private readonly GeminiAdvisor advisor;
    private readonly UserSettings settings;
    private readonly PasswordBox password = new() { MaxLength = 500, MinHeight = 36 };
    private readonly TextBlock connection = Text("");
    private readonly StackPanel modelRows = new();
    private readonly ComboBox preferred = new() { MinHeight = 34, DisplayMemberPath = nameof(GeminiModelLimit.Label), Margin = new Thickness(0, 0, 0, 9) };
    private readonly CheckBox auto = new() { Content = "Automatically review high-priority findings" };
    private readonly Dictionary<string, CheckBox> selected = new(StringComparer.Ordinal);
    private readonly Button save;
    private readonly Button discovery;
    private readonly Button disconnect;
    private IReadOnlyList<GeminiModelLimit> models = [];
    private string? storedKey;
    private string? testedKey;
    private bool testInProgress;

    public GeminiSettingsDialog(Window owner, GeminiAdvisor advisor, UserSettings settings) : base(owner, "Gemini connection", 625, 710)
    {
        this.advisor = advisor;
        this.settings = settings;
        Body.Children.Add(Text("Gemini connection", true));
        Body.Children.Add(Text("Use your own Gemini key to review a limited summary. The Windows Credential Manager stores the key under your account."));
        Body.Children.Add(Text("Gemini API key"));
        AutomationProperties.SetName(password, "Gemini API key");
        Body.Children.Add(password);
        var row = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 8, 0, 8) };
        discovery = Button("Test connection", () => _ = TestConnection());
        discovery.Margin = new Thickness(0, 0, 0, 0);
        disconnect = Button("Disconnect", Disconnect);
        row.Children.Add(discovery);
        row.Children.Add(disconnect);
        Body.Children.Add(row);
        AutomationProperties.SetLiveSetting(connection, AutomationLiveSetting.Polite);
        Body.Children.Add(connection);
        Body.Children.Add(Text("Preferred review model"));
        AutomationProperties.SetName(preferred, "Preferred review model");
        Body.Children.Add(preferred);
        Body.Children.Add(Text("Allowed models and local requests today"));
        Body.Children.Add(modelRows);
        auto.Margin = new Thickness(0, 10, 0, 5);
        auto.IsChecked = settings.AutoReview;
        Body.Children.Add(auto);
        Body.Children.Add(Text("A review can fall back to another enabled model within the app's limits. Google project quotas may include usage from other apps."));
        password.PasswordChanged += (_, _) => UpdateState();
        Actions.Children.Add(Button("Cancel", () => DialogResult = false));
        save = Button("Save changes", Save, true);
        Actions.Children.Add(save);
        try
        {
            storedKey = GeminiCredential.Load();
            disconnect.IsEnabled = storedKey is not null;
            connection.Text = storedKey is null ? "Gemini is disconnected." : "A key is stored for this Windows account.";
            ShowModels(GeminiAdvisor.QuotaProfile.Where(model => settings.EnabledModels.Contains(model.Id, StringComparer.Ordinal)).ToArray());
        }
        catch (Exception error)
        {
            connection.Text = "Credential storage is unavailable. " + error.Message;
        }
    }

    private async Task TestConnection()
    {
        var key = password.Password.Trim();
        if (key.Length == 0)
            key = storedKey ?? "";
        if (key.Length == 0)
        {
            connection.Text = "Enter a Gemini API key to test the connection.";
            password.Focus();
            return;
        }

        testInProgress = true;
        discovery.IsEnabled = disconnect.IsEnabled = password.IsEnabled = false;
        UpdateState();
        connection.Text = "Checking available text models…";
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(25));
        EventHandler cancelOnClose = (_, _) => cancellation.Cancel();
        Closed += cancelOnClose;
        try
        {
            var available = await advisor.DiscoverAsync(key, cancellation.Token);
            if (cancellation.IsCancellationRequested)
                return;
            testedKey = available.Count > 0 ? key : null;
            connection.Text = available.Count > 0
                ? $"Connected. {available.Count} compatible model(s) from your quota profile."
                : "This project did not return any supported review models from the quota profile.";
            ShowModels(available);
        }
        catch (OperationCanceledException)
        {
            connection.Text = "The connection check timed out or was canceled.";
        }
        catch (Exception error)
        {
            testedKey = null;
            connection.Text = "Connection failed. " + error.Message;
        }
        finally
        {
            Closed -= cancelOnClose;
            testInProgress = false;
            discovery.IsEnabled = password.IsEnabled = true;
            disconnect.IsEnabled = storedKey is not null;
            UpdateState();
        }
    }

    private void ShowModels(IReadOnlyList<GeminiModelLimit> available)
    {
        models = available;
        var earlier = selected.Where(item => item.Value.IsChecked == true).Select(item => item.Key).ToArray();
        if (selected.Count == 0)
            earlier = settings.EnabledModels;
        if (!available.Any(item => earlier.Contains(item.Id, StringComparer.Ordinal)))
            earlier = available.Take(2).Select(item => item.Id).ToArray();
        var before = (preferred.SelectedItem as GeminiModelLimit)?.Id ?? settings.EnabledModels.FirstOrDefault();
        modelRows.Children.Clear();
        selected.Clear();
        var quota = advisor.GetQuotaStatus().ToDictionary(item => item.Model.Id, StringComparer.Ordinal);
        foreach (var availableModel in models)
        {
            var status = quota.GetValueOrDefault(availableModel.Id);
            var used = status?.DayRequests ?? 0;
            var minuteRequests = status?.MinuteRequests ?? 0;
            var pause = status?.PausedUntil is { } until ? $" · paused to {until.ToLocalTime():g}" : "";
            var check = new CheckBox
            {
                Content = $"{availableModel.Label}  ·  {used}/{availableModel.RequestsPerDay} today  ·  {minuteRequests}/{availableModel.RequestsPerMinute} RPM{pause}",
                IsChecked = earlier.Contains(availableModel.Id, StringComparer.Ordinal)
            };
            check.Checked += (_, _) => RefreshPreferred();
            check.Unchecked += (_, _) => RefreshPreferred();
            selected[availableModel.Id] = check;
            modelRows.Children.Add(check);
        }
        RefreshPreferred(before);
    }

    private void RefreshPreferred(string? keep = null)
    {
        keep ??= (preferred.SelectedItem as GeminiModelLimit)?.Id;
        var enabled = models.Where(model => selected.TryGetValue(model.Id, out var check) && check.IsChecked == true).ToArray();
        preferred.ItemsSource = enabled;
        preferred.SelectedItem = enabled.FirstOrDefault(model => model.Id == keep) ?? enabled.FirstOrDefault();
        auto.IsEnabled = enabled.Length > 0;
    }

    private void UpdateState()
    {
        save.IsEnabled = !testInProgress && (password.Password.Length == 0 ||
            string.Equals(password.Password.Trim(), testedKey, StringComparison.Ordinal));
    }

    private void Disconnect()
    {
        try
        {
            GeminiCredential.Remove();
            settings.EnabledModels = [];
            settings.AutoReview = false;
            password.Clear();
            DialogResult = true;
        }
        catch (Exception error)
        {
            connection.Text = "The key could not be removed. " + error.Message;
        }
    }

    private void Save()
    {
        try
        {
            if (password.Password.Trim() is { Length: > 0 } enteredKey && string.Equals(enteredKey, testedKey, StringComparison.Ordinal))
                GeminiCredential.Save(enteredKey);
            var first = (preferred.SelectedItem as GeminiModelLimit)?.Id;
            var enabled = models.Where(model => selected[model.Id].IsChecked == true).Select(model => model.Id);
            settings.EnabledModels = first is null ? [] : enabled.Prepend(first).Distinct(StringComparer.Ordinal).ToArray();
            settings.AutoReview = settings.EnabledModels.Length > 0 && auto.IsChecked == true;
            password.Clear();
            DialogResult = true;
        }
        catch (Exception error)
        {
            connection.Text = "The connection settings could not be saved. " + error.Message;
        }
    }
}
