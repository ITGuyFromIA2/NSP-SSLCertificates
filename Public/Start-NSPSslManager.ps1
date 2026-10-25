function Start-NSPSslManager {
    <#
    .SYNOPSIS
        The interactive menu for public SSL certificates: start a request, or finish one when the
        issuer's ZIP arrives.
    .DESCRIPTION
        Lists the requests under -Path with their state. Pick a number to finish that request
        (Complete-NSPSslRequest), N to start a new one (New-NSPSslRequest; the CSR goes to the
        clipboard), O to open the folder, Q to quit. Blank answers take the defaults shown in
        brackets; www.<domain> is added unless you answer n. A new request takes up to five names,
        the domain and www included.

        Replaces Wrapper.sh from NSP-SSLCertificates.
    .PARAMETER Path
        The folder that holds request folders (see New-NSPSslRequest).
    .PARAMETER NoNameLimit
        Allow new requests more than five names.
    .EXAMPLE
        Start-NSPSslManager
    .EXAMPLE
        Start-NSPSslManager -Path D:\NSP-SSLCertificates\Rebase
    #>
    [CmdletBinding()]
    param(
        [string]$Path,
        [switch]$NoNameLimit
    )

    $root = Get-NSPSslWorkRoot -Path $Path
    $ask = {
        param([string]$Prompt, [string]$Default)
        $answer = Read-Host $(if ($Default) { "$Prompt [$Default]" } else { $Prompt })
        if ([string]::IsNullOrWhiteSpace($answer)) { $Default } else { $answer.Trim() }
    }

    while ($true) {
        $requests = @(Get-NSPSslRequest -Path $root)
        Write-Host ''
        Write-Host "SSL certificate requests in $root" -ForegroundColor Cyan
        if (-not $requests) { Write-Host '  (none yet)' }
        for ($i = 0; $i -lt $requests.Count; $i++) {
            $request = $requests[$i]
            $color = switch ($request.Status) { 'CertificateReady' { 'Yellow' } 'Completed' { 'Green' } default { 'Gray' } }
            $detail = if ($request.Expires) { "expires $($request.Expires.ToString('yyyy-MM-dd'))" } else { "created $($request.Created.ToString('yyyy-MM-dd'))" }
            Write-Host ('  {0,2}: {1,-40} {2,-20} {3}' -f ($i + 1), $request.Domain, $request.Status, $detail) -ForegroundColor $color
        }
        Write-Host ''
        $choice = Read-Host 'Number = finish that request, N = new request, O = open folder, Q = quit'

        try {
            if ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le $requests.Count) {
                $request = $requests[[int]$choice - 1]
                $layout = Get-NSPSslRequestLayout -Folder $request.Folder
                if ($request.Status -eq 'AwaitingCertificate') {
                    Write-Host "Put the issuer's ZIP (IIS format) in $($layout.Inputs) first." -ForegroundColor Yellow
                    if ((& $ask 'Open that folder now? (y/n)' 'y') -match '^[yY]') { Invoke-Item -LiteralPath $layout.Inputs }
                    continue
                }
                if ($request.Status -eq 'Completed' -and (& $ask 'Already completed. Build the deliverables again? (y/n)' 'n') -notmatch '^[yY]') { continue }

                $password = Read-Host 'PFX password' -AsSecureString
                $confirm = Read-Host 'PFX password again' -AsSecureString
                if ((ConvertFrom-NSPSslSecureString -SecureString $password) -ne (ConvertFrom-NSPSslSecureString -SecureString $confirm)) {
                    Write-Host 'The passwords did not match.' -ForegroundColor Red
                    continue
                }
                if (-not (ConvertFrom-NSPSslSecureString -SecureString $password)) {
                    Write-Host 'A PFX password is required.' -ForegroundColor Red
                    continue
                }
                $result = Complete-NSPSslRequest -Folder $request.Folder -PfxPassword $password
                $result | Format-List Subject, Names, NotAfter, Chain, PfxPath, FullChainPath | Out-Host
                Write-Host 'Send the PFX password separately from the PFX.' -ForegroundColor Yellow
                if ((& $ask 'Open the deliverables folder? (y/n)' 'y') -match '^[yY]') { Invoke-Item -LiteralPath $layout.Deliverables }
            } elseif ($choice -match '^[nN]') {
                $domain = & $ask 'Domain (the certificate''s main name, e.g. vpn.contoso.com)' ''
                if (-not $domain) { continue }
                $sans = [Collections.Generic.List[string]]::new()
                while ($true) {
                    if (-not $NoNameLimit -and $sans.Count -ge 4) {
                        Write-Host '  That is 5 names, the limit (start the menu with -NoNameLimit for more).' -ForegroundColor Yellow
                        break
                    }
                    $san = & $ask 'Another name for the certificate (blank when done)' ''
                    if (-not $san) { break }
                    if (Test-NSPSslDnsName -Name $san) { $sans.Add($san) } else { Write-Host "  '$san' is not a valid name." -ForegroundColor Red }
                }
                $parameters = @{
                    Domain                 = $domain
                    SubjectAlternativeName = $sans.ToArray()
                    IncludeWww             = ($domain -notmatch '^(\*|www)\.' -and ($NoNameLimit -or $sans.Count -lt 4) -and (& $ask "Add www.$domain too? (y/n)" 'y') -match '^[yY]')
                    NoNameLimit            = [bool]$NoNameLimit
                    Organization           = & $ask 'Organization' 'Network Systems Plus, Inc.'
                    City                   = & $ask 'City' 'Sioux City'
                    State                  = & $ask 'State' 'IA'
                    Country                = & $ask 'Country (2 letters)' 'US'
                    Path                   = $root
                    CopyToClipboard        = $true
                }
                $existing = Get-NSPSslRequestLayout -Folder (Join-Path $root (ConvertTo-NSPSslFolderName -Domain $domain))
                if (Test-Path -LiteralPath $existing.KeyPath) {
                    if ((& $ask "$domain already has a key. Start over with a new one (the old one is archived)? (y/n)" 'n') -notmatch '^[yY]') { continue }
                    $parameters.Force = $true
                }
                $result = New-NSPSslRequest @parameters
                Write-Host ''
                Write-Host $result.Csr
                Write-Host 'The CSR is on the clipboard. Paste it into the issuer''s order page.' -ForegroundColor Green
                Write-Host "When the certificate is issued, choose IIS as the download format and put the ZIP in $($result.Inputs)." -ForegroundColor Green
            } elseif ($choice -match '^[oO]') {
                if (-not (Test-Path -LiteralPath $root)) { New-Item -ItemType Directory -Path $root -Force | Out-Null }
                Invoke-Item -LiteralPath $root
            } elseif ($choice -match '^[qQ]') {
                return
            }
        } catch {
            Write-Host $_.Exception.Message -ForegroundColor Red
        }
    }
}
