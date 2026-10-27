function Install-NSPSslCertificate {
    <#
    .SYNOPSIS
        Installs a PFX on a Windows server, start to finish: certificate stores, IIS bindings, and
        the certificate it replaces. Interactive.
    .DESCRIPTION
        What the _Install folder from Complete-NSPSslRequest runs. Step by step:

          1. Finds the PFX: -Path, else the .pfx in the current folder (a choice when there are
             several, a file prompt when there's none). Asks for the password.
          2. Imports it with Import-NSPSslPfx into LocalMachine: the certificate in My, the
             intermediates in CA. When the chain doesn't validate because the root isn't trusted
             here (a machine without Windows Update), offers to add the root the PFX carries.
          3. If IIS is installed, lists its https bindings with their current certificates and
             proposes the ones the new certificate belongs on (NSP.IIS's matching: the host name is
             on the certificate, or the current certificate covers the same names). Enter takes the
             proposal; numbers, A (all) or N (none) choose otherwise.
          4. For each certificate a binding was moved off: if no IIS or other http.sys binding uses it
             any more, offers to delete it and its key. Anything still using it is listed instead.
             Services that don't go through http.sys (RDP, SQL Server, LDAPS) aren't checked, and
             the prompt says so.

        Runs elevated: from a non-elevated session it relaunches itself in a new elevated window
        (NSP.Bootstrap's Invoke-NSPElevated; UAC prompt). Loads NSP.Console, and NSP.IIS when IIS is
        installed, on first use.
    .PARAMETER Path
        The PFX. Default: the one in the current folder.
    .PARAMETER Password
        The PFX password. Prompted for when not given.
    .PARAMETER TrustRoot
        Add the PFX's root to Trusted Root without asking, when it isn't trusted here.
    .PARAMETER SkipIis
        Import only; leave IIS alone.
    .PARAMETER NoElevate
        Don't relaunch elevated; fail instead when the session isn't.
    .EXAMPLE
        Install-NSPSslCertificate
    .EXAMPLE
        Install-NSPSslCertificate -Path C:\Temp\portal.contoso.com_Install\portal.contoso.com.pfx
    #>
    [CmdletBinding()]
    param(
        [string]$Path,
        [securestring]$Password,
        [switch]$TrustRoot,
        [switch]$SkipIis,
        [switch]$NoElevate
    )

    Import-NSPToolkitModule -Name NSP.Console -MinimumVersion 0.1.5
    $x509 = 'System.Security.Cryptography.X509Certificates'
    $simpleName = [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName

    if (-not $Path) {
        $here = (Get-Location).ProviderPath
        $found = @(Get-ChildItem -LiteralPath $here -File | Where-Object Extension -In '.pfx', '.p12' | Sort-Object Name)
        if ($found.Count -eq 1) {
            $Path = $found[0].FullName
        } elseif ($found.Count -gt 1) {
            $Path = Read-NSPChoice -Prompt "Which PFX in $here" -Choices @($found | ForEach-Object { [pscustomobject]@{ Label = $_.Name; Value = $_.FullName } })
            if (-not $Path) { return }
        } else {
            $Path = Read-NSPFilePath -Prompt 'PFX file' -Filter 'PFX files (*.pfx;*.p12)|*.pfx;*.p12|All files (*.*)|*.*' -InitialDirectory $here -AllowBack
            if (Test-NSPBackSignal $Path) { return }
        }
    }
    # Full path: the elevated window starts in System32.
    $Path = (Resolve-Path -LiteralPath $Path).ProviderPath

    Use-NSPSslDependency
    if (-not (Test-NSPIsAdmin)) {
        if (-not $NoElevate -and $env:NSP_NO_ELEVATE -ne '1') {
            $quote = { param([string]$Text) "'" + $Text.Replace("'", "''") + "'" }
            $relaunch = "Import-Module $(& $quote (Join-Path $script:ModuleRoot 'NSP.SSLCertificates.psd1')); Install-NSPSslCertificate -Path $(& $quote $Path) -NoElevate"
            if ($TrustRoot) { $relaunch += ' -TrustRoot' }
            if ($SkipIis) { $relaunch += ' -SkipIis' }
            if (Invoke-NSPElevated -Command $relaunch -NoExit) {
                Write-Warning 'Not elevated: the install continues in a new elevated PowerShell window (UAC prompt).'
                return
            }
        }
        throw 'Installing a certificate needs an elevated PowerShell session. Run as administrator.'
    }

    Clear-NSPConsole
    Write-NSPConsoleHeader -Title 'Certificate Install' -Subtitle $env:COMPUTERNAME
    Write-NSPConsoleLine "  PFX  $Path" -Role Muted
    Write-NSPConsoleLine ''

    # The password, checked by opening the PFX without keeping its key anywhere.
    $leaf = $null
    for ($try = 1; -not $leaf; $try++) {
        if (-not $Password) { $Password = Read-Host 'PFX password' -AsSecureString }
        $preview = New-Object "$x509.X509Certificate2Collection"
        try {
            $preview.Import($Path, (ConvertFrom-NSPSslSecureString -SecureString $Password), [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
        } catch {
            if ($try -ge 3) { throw "Could not open $Path after 3 tries. Check the password. ($($_.Exception.Message))" }
            Write-NSPConsoleLine '  That password did not open the PFX. Try again.' -Role Warning
            $Password = $null
            continue
        }
        $leaf = @($preview | Where-Object HasPrivateKey)[0]
        if (-not $leaf) { throw "$Path has no certificate with a private key." }
    }
    $names = @(Get-NSPSslDnsName -Certificate $leaf)
    Write-NSPConsoleLine "  Certificate  $($leaf.GetNameInfo($simpleName, $false))" -Role Strong
    Write-NSPConsoleLine "  Names        $($names -join ', ')"
    Write-NSPConsoleLine "  Expires      $($leaf.NotAfter.ToString('yyyy-MM-dd'))   Issued by $($leaf.GetNameInfo($simpleName, $true))"
    Write-NSPConsoleLine "  Thumbprint   $($leaf.Thumbprint)" -Role Muted

    # 1. Certificate stores.
    Write-NSPConsoleRule -Title 'Certificate stores'
    $import = @{ Path = $Path; Password = $Password; StoreLocation = 'LocalMachine'; NoElevate = $true; WarningAction = 'SilentlyContinue' }
    $rows = @(Import-NSPSslPfx @import -TrustRoot:$TrustRoot)
    $certificateRow = $rows | Where-Object Role -EQ 'Certificate' | Select-Object -First 1
    $skippedRoot = $rows | Where-Object { $_.Role -eq 'Root' -and $_.Action -eq 'Skipped' } | Select-Object -First 1
    if ($skippedRoot -and $certificateRow.ChainStatus -ne 'Valid') {
        Write-NSPConsoleLine "  The chain doesn't validate here ($($certificateRow.ChainStatus))." -Role Warning
        if (Read-NSPConfirm -Prompt "  Add the PFX's root, $($skippedRoot.Subject), to Trusted Root?" -DefaultYes) {
            $rows = @(Import-NSPSslPfx @import -TrustRoot)
            $certificateRow = $rows | Where-Object Role -EQ 'Certificate' | Select-Object -First 1
        }
    }
    foreach ($row in $rows) {
        $role = switch ($row.Action) { 'Added' { 'Success' } 'AlreadyPresent' { 'Normal' } default { 'Muted' } }
        $subject = ($row.Subject -split ',')[0] -replace '^CN=', ''
        Write-NSPConsoleLine ('  {0,-13} {1,-15} {2,-22} {3}' -f $row.Role, $row.Action, $row.Store, $subject) -Role $role
    }
    if ($certificateRow.ChainStatus -eq 'Valid') {
        Write-NSPConsoleLine "  Chain valid: $($certificateRow.Chain -join ' > ')" -Role Success
    } else {
        Write-NSPConsoleLine "  Chain problem: $($certificateRow.ChainStatus)" -Role Warning
    }

    $store = New-Object "$x509.X509Store" 'My', 'LocalMachine'
    try {
        $store.Open('ReadOnly')
        $installed = @($store.Certificates.Find('FindByThumbprint', $leaf.Thumbprint, $false))[0]
    } finally {
        $store.Close()
    }

    # 2. IIS bindings.
    $replaced = [Collections.Generic.List[string]]::new()
    $iis = -not $SkipIis -and [bool](Get-Service -Name W3SVC -ErrorAction SilentlyContinue)
    if ($iis) {
        Import-NSPToolkitModule -Name NSP.IIS -MinimumVersion 0.1.0
        Write-NSPConsoleRule -Title 'IIS https bindings'
        $bindings = @(Get-NSPIisBinding -Certificate $installed)
        if (-not $bindings) {
            Write-NSPConsoleLine '  IIS has no https bindings. Add one in IIS Manager, then run this again to bind it.' -Role Muted
        } else {
            $proposed = @(); $selectable = @()
            for ($i = 0; $i -lt $bindings.Count; $i++) {
                $b = $bindings[$i]
                $number = $i + 1
                if ($b.Match) { $proposed += $number }
                if ($b.MatchReason -notmatch '^(Already uses|Uses the Central)') { $selectable += $number }
                $current = if ($b.CertificateFound) { '{0} (expires {1:yyyy-MM-dd})' -f (($b.CertificateSubject -split ',')[0] -replace '^CN=', ''), $b.CertificateNotAfter } elseif ($b.Thumbprint) { "$($b.Thumbprint) (not in the store)" } else { '(none)' }
                $mark = if ($b.Match) { '*' } else { ' ' }
                $role = if ($b.Match) { 'Strong' } elseif ($b.MatchReason -like 'Already uses*') { 'Success' } else { 'Normal' }
                Write-NSPConsoleLine ('  {0} {1,2}  {2,-24} {3,-34} {4}' -f $mark, $number, $b.SiteName, $b.BindingInformation, $current) -Role $role
                Write-NSPConsoleLine ('         {0}' -f $b.MatchReason) -Role Muted
            }
            $hint = if ($proposed) { "Enter = the * ones ($($proposed -join ','))" } else { 'Enter = none' }
            $chosen = $null
            while ($null -eq $chosen) {
                $answer = Read-Host "  Rebind which? $hint, numbers (1,3 or 2-4), A = all, N = none"
                try {
                    $chosen = @(Resolve-NSPSslBindingSelection -Answer $answer -Count $bindings.Count -Proposed $proposed -Selectable $selectable)
                } catch {
                    Write-NSPConsoleLine "  $($_.Exception.Message)" -Role Warning
                }
            }
            foreach ($number in $chosen) {
                $b = $bindings[$number - 1]
                try {
                    $result = Set-NSPIisBindingCertificate -SiteName $b.SiteName -BindingInformation $b.BindingInformation -Thumbprint $installed.Thumbprint -Confirm:$false
                    Write-NSPConsoleLine "  $($result.Action): $($b.SiteName) $($b.BindingInformation)" -Role Success
                    if ($result.Action -eq 'Updated' -and $result.PreviousThumbprint -and $result.PreviousThumbprint -ne $installed.Thumbprint -and -not $replaced.Contains($result.PreviousThumbprint)) {
                        $replaced.Add($result.PreviousThumbprint)
                    }
                } catch {
                    Write-NSPConsoleLine "  Failed: $($b.SiteName) $($b.BindingInformation): $($_.Exception.Message)" -Role Error
                }
            }
            if (-not $chosen) { Write-NSPConsoleLine '  No bindings changed.' -Role Muted }
        }
    } elseif (-not $SkipIis) {
        Write-NSPConsoleLine ''
        Write-NSPConsoleLine '  IIS is not installed here; nothing to bind.' -Role Muted
    }

    # 3. The certificates the bindings were moved off.
    if ($replaced.Count) {
        Write-NSPConsoleRule -Title 'Replaced certificates'
        $allBindings = @(Get-NSPIisBinding)
        foreach ($thumbprint in $replaced) {
            $old = Get-Item -LiteralPath "Cert:\LocalMachine\My\$thumbprint" -ErrorAction SilentlyContinue
            if (-not $old) { continue }
            $label = '{0} (expires {1:yyyy-MM-dd}, {2})' -f $old.GetNameInfo($simpleName, $false), $old.NotAfter, $thumbprint
            $uses = @(
                $allBindings | Where-Object Thumbprint -EQ $thumbprint | ForEach-Object { "IIS $($_.SiteName) $($_.BindingInformation)" }
                Get-NSPHttpSysSslBinding -Thumbprint $thumbprint -ExcludeIis | ForEach-Object { "http.sys $($_.Endpoint) (app $($_.Owner))" }
            )
            if ($uses) {
                Write-NSPConsoleLine "  Kept $label - still used by:" -Role Warning
                foreach ($use in $uses) { Write-NSPConsoleLine "    $use" }
                continue
            }
            Write-NSPConsoleLine "  $label is no longer bound in IIS or http.sys." -Role Normal
            Write-NSPConsoleLine '  Not checked: services that load it themselves (RDP, SQL Server, LDAPS, Exchange).' -Role Muted
            if (Read-NSPConfirm -Prompt '  Delete it and its private key from LocalMachine\My?') {
                try {
                    Remove-NSPSslStoreCertificate -Thumbprint $thumbprint -Confirm:$false
                    Write-NSPConsoleLine '  Deleted.' -Role Success
                } catch {
                    Write-NSPConsoleLine "  Could not delete it: $($_.Exception.Message)" -Role Error
                }
            }
        }
    }

    Write-NSPConsoleLine ''
    Write-NSPConsoleLine "Done. $($leaf.GetNameInfo($simpleName, $false)) is installed in LocalMachine\My." -Role Success
}
