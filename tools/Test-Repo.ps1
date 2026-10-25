$ErrorActionPreference = 'Stop'
$WhatIfPreference = $false
$repoRoot = Split-Path -Parent $PSScriptRoot
$moduleName = 'NSP.SSLCertificates'

$manifestPath = Join-Path $repoRoot "$moduleName.psd1"
$manifest = Test-ModuleManifest -Path $manifestPath -ErrorAction Stop
if ($manifest.Name -ne $moduleName) { throw "Unexpected module name: $($manifest.Name)" }

$publicNames = @(Get-ChildItem -Path (Join-Path $repoRoot 'Public') -Filter '*.ps1' -File | ForEach-Object BaseName | Sort-Object)
$exported = @($manifest.ExportedFunctions.Keys | Sort-Object)
if (($publicNames -join ',') -ne ($exported -join ',')) { throw "FunctionsToExport does not match Public: $($exported -join ', ') vs $($publicNames -join ', ')" }

# Public-source gate: every tracked text file, since the repository itself is public. Shows
# locations only, never matched values.
$publicFiles = @(
    Get-ChildItem -Path $repoRoot -Recurse -File | Where-Object {
        $_.FullName -notmatch '\\\.git\\' -and $_.Extension -in '.ps1', '.psm1', '.psd1', '.md', '.txt', '.json', '.xml' -and $_.Name -notlike '*.local.*' -and $_.FullName -ne $PSCommandPath  # this file holds the patterns themselves
    }
    Get-Item (Join-Path $repoRoot 'LICENSE')
)
$privateMarker = '(?i)C:\\GitRepo\\|C:\\Users\\|\\\\[a-z0-9._-]+\\|[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}'
# Customer, site, and person names can't be listed here without publishing them. Keep them one
# per line in tools\PrivateTerms.local.txt (git-ignored); every term is checked as a whole word.
$termsFile = Join-Path $PSScriptRoot 'PrivateTerms.local.txt'
if (Test-Path -LiteralPath $termsFile) {
    $terms = @(Get-Content -LiteralPath $termsFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })
    if ($terms.Count) { $privateMarker += '|(?i)\b(' + (($terms | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')\b' }
} else {
    Write-Warning 'tools\PrivateTerms.local.txt not found; customer and person names are not being checked.'
}
foreach ($file in $publicFiles) {
    $hits = @(Select-String -LiteralPath $file.FullName -Pattern $privateMarker)
    if ($hits.Count) {
        $locations = ($hits | ForEach-Object { "$($file.Name):$($_.LineNumber)" }) -join ', '
        throw "Review possible private reference at $locations."
    }
}

foreach ($file in Get-ChildItem -Path $repoRoot -Recurse -File | Where-Object Extension -In '.ps1', '.psm1') {
    $tokens = $null
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors) | Out-Null
    if ($errors.Count) { throw "PowerShell parser errors in $($file.FullName): $($errors[0].Message)" }
}

Import-Module $manifestPath -Force
foreach ($name in $publicNames) {
    $help = Get-Help $name -Full
    if (-not $help.Synopsis -or $help.Synopsis -eq $name -or -not $help.Examples) { throw "$name needs .SYNOPSIS and .EXAMPLE help." }
}

foreach ($exe in 'powershell.exe', 'pwsh.exe') {
    & $exe -NoProfile -File (Join-Path $repoRoot 'Tests\Smoke.ps1')
    if ($LASTEXITCODE -ne 0) { throw "$exe smoke checks failed." }
}

$analyzer = Get-Module -ListAvailable PSScriptAnalyzer | Select-Object -First 1
if ($analyzer) {
    Import-Module $analyzer.Path -Force
    $findings = @(Invoke-ScriptAnalyzer -Path $repoRoot -Recurse -Settings (Join-Path $repoRoot 'PSScriptAnalyzerSettings.psd1'))
    if ($findings.Count) {
        $findings | Format-Table RuleName, Severity, ScriptName, Line, Message -AutoSize
        throw 'PSScriptAnalyzer reported findings.'
    }
} else {
    Write-Warning 'PSScriptAnalyzer is not installed; parser and behavior checks still ran.'
}

'NSP.SSLCertificates repository checks passed.'
