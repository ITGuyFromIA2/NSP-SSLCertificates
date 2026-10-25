function Get-NSPSslRequest {
    <#
    .SYNOPSIS
        Lists certificate requests and where each one stands.
    .DESCRIPTION
        One row per request folder under -Path that has a private key:

            AwaitingCertificate  CSR generated; nothing from the issuer in Inputs yet
            CertificateReady     a ZIP or certificate file is in Inputs; run Complete-NSPSslRequest
            Completed            the PFX has been built (Expires shows the certificate's end date)

        Reads WSL-era Rebase folders too.
    .PARAMETER Domain
        Only requests whose domain matches (wildcards allowed).
    .PARAMETER Status
        Only requests in this state.
    .PARAMETER Path
        The folder that holds request folders (see New-NSPSslRequest).
    .EXAMPLE
        Get-NSPSslRequest
    .EXAMPLE
        Get-NSPSslRequest -Path D:\NSP-SSLCertificates\Rebase -Status Completed | Sort-Object Expires
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Position = 0)][string]$Domain = '*',
        [ValidateSet('AwaitingCertificate', 'CertificateReady', 'Completed')][string]$Status,
        [string]$Path
    )

    $root = Get-NSPSslWorkRoot -Path $Path
    if (-not (Test-Path -LiteralPath $root)) { return }

    $rows = foreach ($directory in Get-ChildItem -LiteralPath $root -Directory) {
        $layout = Get-NSPSslRequestLayout -Folder $directory.FullName
        if (-not (Test-Path -LiteralPath $layout.KeyPath)) { continue }
        if ($layout.Domain -notlike $Domain -and $directory.Name -notlike $Domain) { continue }

        $expires = $null
        if (Test-Path -LiteralPath $layout.PfxPath) {
            $state = 'Completed'
            if (Test-Path -LiteralPath $layout.CertificatePath) {
                try { $expires = @(Read-NSPSslCertificateFile -Path $layout.CertificatePath)[0].NotAfter } catch { Write-Verbose "Could not read $($layout.CertificatePath): $($_.Exception.Message)" }
            }
        } elseif (@(Get-ChildItem -LiteralPath $layout.Inputs -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.zip', '.crt', '.cer', '.pem', '.p7b' }).Count) {
            $state = 'CertificateReady'
        } else {
            $state = 'AwaitingCertificate'
        }
        if ($Status -and $state -ne $Status) { continue }

        [pscustomobject]@{
            Domain  = $layout.Domain
            Status  = $state
            Expires = $expires
            Created = (Get-Item -LiteralPath $layout.KeyPath).LastWriteTime
            Folder  = $directory.FullName
        }
    }
    $rows | Sort-Object Domain
}
