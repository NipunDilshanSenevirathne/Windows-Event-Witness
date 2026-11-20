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

function Install-File([string]$source, [string]$target) {
    Assert-PlainPath $target
    $pending = Join-Path (Split-Path -LiteralPath $target) ([Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [IO.File]::Copy($source, $pending)
        if ([IO.File]::Exists($target)) {
            [IO.File]::Replace($pending, $target, [NullString]::Value)
        } else {
            [IO.File]::Move($pending, $target)
        }
    } finally {
        if ([IO.File]::Exists($pending)) {
            [IO.File]::Delete($pending)
        }
    }
}

function Write-Shortcut([string]$path, [string]$target, [string]$arguments, [string]$location) {
    Assert-PlainPath $path
    $shortcut = $shell.CreateShortcut($path)
    if ((Test-Path -LiteralPath $path) -and ($shortcut.TargetPath -ne $target -or $shortcut.Arguments -ne $arguments)) {
        throw "Setup found an unrelated Start Menu shortcut at $path."
    }
    $shortcut.TargetPath = $target
    $shortcut.Arguments = $arguments
    $shortcut.WorkingDirectory = $location
    $shortcut.Save()
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
    $executableName = 'WindowsEventWitness.exe'
    $source = Join-Path (Split-Path -LiteralPath $PSScriptRoot) $executableName
    $uninstaller = Join-Path $PSScriptRoot 'uninstall.ps1'
    if (-not [IO.File]::Exists($source) -or -not [IO.File]::Exists($uninstaller)) {
        throw 'Extract the complete release archive before running Install.cmd.'
    }
    if ((Get-Item -LiteralPath $source).Length -eq 0) {
        throw 'The application in this release folder is empty.'
    }

    Assert-PlainPath $application
    Assert-PlainPath $program
    Assert-PlainPath $shortcutFolder
    [IO.Directory]::CreateDirectory($program) | Out-Null
    [IO.Directory]::CreateDirectory($shortcutFolder) | Out-Null

    $installedExe = Join-Path $program $executableName
    $installedUninstaller = Join-Path $program 'uninstall.ps1'
    Install-File $source $installedExe
    Install-File $uninstaller $installedUninstaller

    $shell = New-Object -ComObject WScript.Shell
    $uninstallTarget = Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
    $uninstallArguments = '-NoLogo -NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $installedUninstaller
    Write-Shortcut (Join-Path $shortcutFolder 'Windows Event Witness.lnk') $installedExe '' $program
    Write-Shortcut (Join-Path $shortcutFolder 'Uninstall Windows Event Witness.lnk') $uninstallTarget $uninstallArguments $application

    Start-Process -FilePath $installedExe -WorkingDirectory $program
    Write-Output "Installed Windows Event Witness in $program."
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
