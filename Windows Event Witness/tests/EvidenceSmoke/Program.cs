using System;
using System.IO;
using System.Linq;
using System.Xml;
using WindowsEventWitness.Core;

if (args.Length > 2 || (args.Length == 2 && args[0] != "--evtx") || (args.Length == 1 && args[0] != "--probe-live"))
{
    Console.Error.WriteLine("Usage: EvidenceSmoke [--probe-live | --evtx <path>]");
    return 2;
}

string directory = Directory.CreateTempSubdirectory("witness-evidence-").FullName;
string casePath = Path.Combine(directory, "demo.wwcase");
string tamperedPath = Path.Combine(directory, "tampered.wwcase");

try
{
    EvidenceCase demo = EvidenceCapture.CreateDemo();
    Check(demo.Events.Length == 6, "Expected six demo events.");
    Check(demo.Events.Select(item => item.Id).Distinct().Count() == demo.Events.Length, "Demo IDs must be unique.");

    EvidenceLink[] edges = EvidenceGraph.Build(demo);
    Check(edges.Count(edge => edge.Certainty == "Observed" && edge.FromId.Length > 0) == 4, "Expected four observed links.");
    Check(edges.Count(edge => edge.Certainty == "Uncertain" && edge.FromId.Length == 0) == 1, "Expected one unresolved parent.");

    EvidenceCaseFile.Save(casePath, demo);
    EvidenceCaseFile.Save(casePath, demo);
    EvidenceCase restored = EvidenceCaseFile.Load(casePath);
    Check(restored.Title == demo.Title && restored.CapturedUtc == demo.CapturedUtc, "Case metadata changed on replay.");
    Check(restored.Coverage.SequenceEqual(demo.Coverage), "Case coverage changed on replay.");
    Check(restored.Events.Select(item => (item.Id, item.RawXml)).SequenceEqual(demo.Events.Select(item => (item.Id, item.RawXml))),
        "Event identity, content, or replay ordering changed.");
    Check(EvidenceGraph.Build(restored).SequenceEqual(edges), "Process relationships changed on replay.");

    string original = File.ReadAllText(casePath);
    string modified = original.Replace("Trace a local worker", "Trace an edited worker", StringComparison.Ordinal);
    Check(original != modified, "The tamper fixture could not be created.");
    File.WriteAllText(tamperedPath, modified);
    Reject<InvalidDataException>(() => EvidenceCaseFile.Load(tamperedPath), "Case tampering was accepted.");

    const string dtd = "<!DOCTYPE Event [<!ENTITY forbidden SYSTEM 'file:///unused'>]><Event>&forbidden;</Event>";
    Reject<XmlException>(() => EvidenceXml.Parse(dtd), "An external entity declaration was accepted.");
    string nested = string.Concat(Enumerable.Repeat("<n>", 40)) + string.Concat(Enumerable.Repeat("</n>", 40));
    Reject<InvalidDataException>(() => EvidenceXml.Parse(nested), "An excessively nested XML record was accepted.");

    if (args.Length == 1)
    {
        string channel = $"WitnessSmoke-Missing-{Guid.NewGuid():N}";
        EvidenceCase probe = EvidenceCapture.CollectRecent(hours: 1, maxPerChannel: 1, channels: new[] { channel });
        Check(probe.Events.Length == 0 && probe.Coverage.Length == 1, "Unexpected missing channel results.");
        string state = probe.Coverage[0].State;
        Check(state is "Missing" or "Access denied", $"Unexpected state for missing channel ({state}).");
        Console.WriteLine($"Missing channel probe returned {state}.");
    }

    if (args.Length == 2)
    {
        EvidenceCase imported = EvidenceCapture.ImportEvtx(args[1], maxEvents: 5);
        ChannelCoverage source = imported.Coverage.Single();
        Check(imported.Events.Length is > 0 and <= 5, $"EVTX read failed ({source.State}).");
        Check(imported.Events.All(item => item.RawXml.Contains("<Event", StringComparison.Ordinal)), "Imported records must retain original XML.");
        EvidenceCase checkedAgain = EvidenceCapture.ImportEvtx(args[1], maxEvents: 5);
        Check(imported.Events.Select(item => item.Id).SequenceEqual(checkedAgain.Events.Select(item => item.Id)), "EVTX ingest is unstable.");
        Console.WriteLine($"EVTX probe read {imported.Events.Length} record(s). Coverage {source.State}.");
    }

    Console.WriteLine("Evidence smoke checks passed.");
    return 0;
}
catch (Exception failure)
{
    Console.Error.WriteLine(failure.Message);
    return 1;
}
finally
{
    File.Delete(casePath);
    File.Delete(tamperedPath);
    Directory.Delete(directory);
}

static void Check(bool condition, string message)
{
    if (!condition)
        throw new InvalidOperationException(message);
}

static void Reject<T>(Action operation, string message) where T : Exception
{
    try
    {
        operation();
    }
    catch (T)
    {
        return;
    }

    throw new InvalidOperationException(message);
}
