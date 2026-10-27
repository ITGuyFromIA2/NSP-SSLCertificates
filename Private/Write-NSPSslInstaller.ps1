function Write-NSPSslInstaller {
    # The request's _Install folder: a copy of the PFX plus a ToolShim (NSP.ClientScripts) and its
    # .cmd that run Install-NSPSslCertificate on the server. Returns the .cmd's path.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][pscustomobject]$Layout)

    Import-NSPToolkitModule -Name NSP.ClientScripts -MinimumVersion 0.1.6
    if (-not (Test-Path -LiteralPath $Layout.InstallFolder)) { New-Item -ItemType Directory -Path $Layout.InstallFolder | Out-Null }
    # Only this request's PFX: the installer offers a choice when it finds several.
    Get-ChildItem -LiteralPath $Layout.InstallFolder -Filter '*.pfx' -File | Remove-Item -Force
    Copy-Item -LiteralPath $Layout.PfxPath -Destination $Layout.InstallFolder

    $version = (Import-PowerShellDataFile -LiteralPath (Join-Path $script:ModuleRoot 'NSP.SSLCertificates.psd1')).ModuleVersion
    $shim = @{
        ToolName             = 'Certificate Install'
        ModuleName           = 'NSP.SSLCertificates'
        ModuleMinimumVersion = '0.2.0'
        EntryFunction        = 'Install-NSPSslCertificate'
        Modules              = @(
            @{ Name = 'NSP.SSLCertificates'; MinimumVersion = '0.2.0' }
            @{ Name = 'NSP.Console'; MinimumVersion = '0.1.5' }
            @{ Name = 'NSP.IIS'; MinimumVersion = '0.1.0' }
        )
        Company              = $Layout.Domain
        GeneratedBy          = "Complete-NSPSslRequest (NSP.SSLCertificates $version)"
        StartInShimFolder    = $true
        PauseOnExit          = $true
        WithCmd              = $true
        Path                 = $Layout.InstallerPath
        Force                = $true
        Confirm              = $false
    }
    $null = New-NSPToolShim @shim
    [IO.Path]::ChangeExtension($Layout.InstallerPath, '.cmd')
}
