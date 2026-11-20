param(
    [string]$DotNet = 'dotnet',
    [string]$Output = (Join-Path $PSScriptRoot 'dist'),
    [string]$Artifacts = (Join-Path $PSScriptRoot 'obj\release'),
    [string]$RestoreConfig
)

$ErrorActionPreference = 'Stop'
$project = Join-Path $PSScriptRoot 'src\WindowsEventWitness.csproj'
$publish = Join-Path $Artifacts 'publish'
$flags = @(
    '-r', 'win-x64',
    '-p:PublishSingleFile=true',
    '-p:SelfContained=true',
    '-p:EnableCompressionInSingleFile=true',
    '-p:IncludeNativeLibrariesForSelfExtract=true',
    '-p:DebugType=None',
    '-p:DebugSymbols=false'
)

$restore = @('restore', $project, '--artifacts-path', $Artifacts) + $flags
if ($RestoreConfig) {
    $restore += @('--configfile', $RestoreConfig)
}
& $DotNet @restore
if ($LASTEXITCODE -ne 0) { throw "Restore failed with exit code $LASTEXITCODE." }

$arguments = @('publish', $project, '--no-restore', '--configuration', 'Release', '--artifacts-path', $Artifacts, '--output', $publish) + $flags
& $DotNet @arguments
if ($LASTEXITCODE -ne 0) { throw "Publish failed with exit code $LASTEXITCODE." }

$exe = Get-Item -LiteralPath (Join-Path $publish 'WindowsEventWitness.exe')
if ($exe.Length -ge 100000000) { throw 'The standalone executable exceeds the 100 MB budget.' }
$extraFiles = @(Get-ChildItem -LiteralPath $publish -File | Where-Object Name -ne $exe.Name)
if ($extraFiles.Count -ne 0) { throw 'The publish output contains unbundled binaries. Use a clean artifacts directory.' }

New-Item -Path $Output -ItemType Directory -Force | Out-Null
$portable = Join-Path $Output $exe.Name
$archive = Join-Path $Output 'Windows-Event-Witness-win-x64.zip'
Copy-Item -LiteralPath $exe.FullName -Destination $portable -Force
$packaging = Join-Path $PSScriptRoot 'packaging'
$documentation = @((Join-Path $PSScriptRoot 'README.md'), (Join-Path $PSScriptRoot 'docs'))
Compress-Archive -LiteralPath (@($portable, $packaging) + $documentation) -DestinationPath $archive -CompressionLevel Optimal -Force
if ((Get-Item -LiteralPath $archive).Length -ge 100000000) {
    Remove-Item -LiteralPath $archive
    throw 'The installer archive exceeds the 100 MB budget.'
}

$hashes = foreach ($path in @($portable, $archive)) {
    $file = Get-Item -LiteralPath $path
    $hash = Get-FileHash -LiteralPath $path -Algorithm SHA256
    '{0}  {1}' -f $hash.Hash.ToLowerInvariant(), $file.Name
    Write-Host ('{0}  {1:N0} bytes' -f $file.Name, $file.Length)
}
$hashes | Set-Content -LiteralPath (Join-Path $Output 'SHA256SUMS.txt') -Encoding ascii
