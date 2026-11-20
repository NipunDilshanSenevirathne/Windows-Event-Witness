[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

function Assert-PlainPath([string]$path) {
    if (Test-Path -LiteralPath $path) {
        $item = Get-Item -LiteralPath $path -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Setup cannot use this redirected path: $path"
        }
    }
}

function Remove-Shortcut([string]$path, [string]$target, [string]$arguments) {
    Assert-PlainPath $path
    if ([IO.File]::Exists($path)) {
        $shortcut = $shell.CreateShortcut($path)
        if ($shortcut.TargetPath -eq $target -and $shortcut.Arguments -eq $arguments) {
            [IO.File]::Delete($path)
        }
    }
}

function Remove-EmptyFolder([string]$path) {
    if ([IO.Directory]::Exists($path) -and [IO.Directory]::GetFileSystemEntries($path).Length -eq 0) {
        [IO.Directory]::Delete($path)
    }
}

try {
    $localAppData = [Environment]::GetFolderPath('LocalApplicationData')
    $programs = [Environment]::GetFolderPath('Programs')
    if ([string]::IsNullOrWhiteSpace($localAppData) -or [string]::IsNullOrWhiteSpace($programs)) {
        throw 'Windows did not return the installation folders for this account.'
    }

    $application = Join-Path $localAppData 'Windows Event Witness'
    $program = Join-Path $application 'Program'
    $shortcutFolder = Join-Path $programs 'Windows Event Witness'
    $installedExe = Join-Path $program 'WindowsEventWitness.exe'
    $installedUninstaller = Join-Path $program 'uninstall.ps1'

    foreach ($path in @($application, $program, $shortcutFolder, $installedExe, $installedUninstaller)) {
        Assert-PlainPath $path
    }

    try {
        [IO.File]::Delete($installedExe)
    } catch {
        throw "Close Windows Event Witness and retry. $($_.Exception.Message)"
    }

    $shell = New-Object -ComObject WScript.Shell
    $uninstallTarget = Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
    $uninstallArguments = '-NoLogo -NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $installedUninstaller
    Remove-Shortcut (Join-Path $shortcutFolder 'Windows Event Witness.lnk') $installedExe ''
    Remove-Shortcut (Join-Path $shortcutFolder 'Uninstall Windows Event Witness.lnk') $uninstallTarget $uninstallArguments
    [IO.File]::Delete($installedUninstaller)
    Remove-EmptyFolder $program
    Remove-EmptyFolder $shortcutFolder

    Write-Output 'Removed Windows Event Witness. Local data and Windows Credential Manager entries were retained.'
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
