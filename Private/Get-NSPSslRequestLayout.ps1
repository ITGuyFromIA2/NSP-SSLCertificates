function Get-NSPSslRequestLayout {
    # The files of one request folder. Reads this module's layout (Deliverables\) and the WSL-era
    # Rebase layout (Deliverables_<domain>\), so requests started there can be finished here.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][string]$Folder)

    $name = Split-Path -Leaf $Folder
    $domain = $name
    $names = @()
    $requestFile = Join-Path $Folder 'request.json'
    if (Test-Path -LiteralPath $requestFile) {
        $request = Get-Content -LiteralPath $requestFile -Raw | ConvertFrom-Json
        $domain = [string]$request.Domain
        $names = @($request.Names)
    }

    $deliverables = Join-Path $Folder 'Deliverables'
    $legacy = Join-Path $Folder "Deliverables_$name"
    if (-not (Test-Path -LiteralPath $deliverables) -and (Test-Path -LiteralPath $legacy)) { $deliverables = $legacy }

    [pscustomobject]@{
        Domain            = $domain
        Names             = $names
        Folder            = $Folder
        Inputs            = Join-Path $Folder 'Inputs'
        Deliverables      = $deliverables
        KeyPath           = Join-Path $deliverables "$($name)_priv.key"
        CsrPath           = Join-Path $deliverables "$name.csr"
        CertificatePath   = Join-Path $deliverables "$name.crt"
        IntermediatesPath = Join-Path $deliverables "$($name)_intermediates.crt"
        FullChainPath     = Join-Path $deliverables "$($name)_FullChain.pem"
        PfxPath           = Join-Path $deliverables "$name.pfx"
        InstallFolder     = Join-Path $deliverables "$($name)_Install"
        InstallerPath     = Join-Path $deliverables "$($name)_Install\Install-$name.ps1"
    }
}
