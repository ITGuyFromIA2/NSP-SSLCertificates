function Import-NSPSslPfx {
    <#
    .SYNOPSIS
        Imports a PFX on Windows with each certificate in the right store: the certificate and key in
        Personal, intermediates in Intermediate Certification Authorities, roots in Trusted Root.
    .DESCRIPTION
        Import-PfxCertificate puts every certificate in a PFX into the one store you name, so the
        intermediates land in Personal (My) next to the certificate, where Windows doesn't use them
        to build chains, and an intermediate imported into Trusted Root becomes a trust anchor it
        should never be. This command sorts them the way the Certificate Import Wizard's automatic
        placement does:

            the certificate with the private key   -> <StoreLocation>\My
            intermediates (not self-signed)        -> <StoreLocation>\CA
            roots (self-signed)                    -> <StoreLocation>\Root, only with -TrustRoot

        Whether a certificate is a root is decided by whether it issued itself, not by its name: a
        cross-signed "Starfield TLS Root CA - R1" issued by Starfield Root Certificate Authority -
        G2 is an intermediate and goes to CA.

        A root that isn't trusted on this machine yet is reported and skipped unless -TrustRoot is
        given. Public roots normally arrive through Windows' automatic root update when a chain is
        first built; -TrustRoot is for machines that can't reach Windows Update.

        -ChainFile adds certificates from separate files (.cer/.crt/.pem/.p7b), placed by the same
        rules - for example the root or cross-signed intermediate an issuer offers as separate
        downloads.

        Certificates already in their store are left alone. Afterwards the certificate's chain is
        built (without revocation checks) and reported on its row: Chain lists the path Windows
        chose, ChainStatus is Valid or the problems found.

        One row per certificate: Role (Certificate, Intermediate, Root), Subject, Thumbprint, Store,
        Action (Added, AlreadyPresent, Skipped, WhatIf), Note, and on the certificate's row Chain and
        ChainStatus.
    .PARAMETER Path
        The PFX file.
    .PARAMETER Password
        The PFX password. Prompted for when not given (in the elevated window, when it relaunches).
    .PARAMETER StoreLocation
        LocalMachine (default) or CurrentUser. LocalMachine needs an elevated session: from a
        non-elevated one the command relaunches itself in a new elevated window (NSP.Bootstrap's
        Invoke-NSPElevated, UAC prompt) and the import runs and reports there.
    .PARAMETER ChainFile
        Extra intermediate or root certificate files to place.
    .PARAMETER Exportable
        Let the private key be exported again later. Off by default.
    .PARAMETER TrustRoot
        Add self-signed roots from the PFX or -ChainFile to Trusted Root when they aren't there.
    .PARAMETER NoElevate
        Don't relaunch elevated; fail instead when the session isn't (for scripts and RMM jobs that
        already run as SYSTEM or an administrator).
    .EXAMPLE
        Import-NSPSslPfx -Path C:\Temp\vpn.contoso.com.pfx
    .EXAMPLE
        Import-NSPSslPfx -Path .\portal.contoso.com.pfx -ChainFile .\CAR1.cer, .\G2.cer -TrustRoot -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Path,
        [securestring]$Password,
        [ValidateSet('LocalMachine', 'CurrentUser')][string]$StoreLocation = 'LocalMachine',
        [string[]]$ChainFile = @(),
        [switch]$Exportable,
        [switch]$TrustRoot,
        [switch]$NoElevate
    )

    # Full paths: the elevated window starts in System32.
    $Path = (Resolve-Path -LiteralPath $Path).ProviderPath
    $ChainFile = @($ChainFile | ForEach-Object { (Resolve-Path -LiteralPath $_).ProviderPath })

    if ($StoreLocation -eq 'LocalMachine' -and -not $WhatIfPreference) {
        Use-NSPSslDependency
        if (-not $NoElevate) {
            $quote = { param([string]$Text) "'" + $Text.Replace("'", "''") + "'" }
            $relaunch = "Import-Module $(& $quote (Join-Path $script:ModuleRoot 'NSP.SSLCertificates.psd1')); Import-NSPSslPfx -Path $(& $quote $Path) -NoElevate"
            if ($ChainFile) { $relaunch += ' -ChainFile ' + (($ChainFile | ForEach-Object { & $quote $_ }) -join ', ') }
            if ($Exportable) { $relaunch += ' -Exportable' }
            if ($TrustRoot) { $relaunch += ' -TrustRoot' }
            if (Invoke-NSPElevated -Command $relaunch -NoExit) {
                # A SecureString can't cross into the new process; the elevated window asks for it.
                Write-Warning 'Not elevated: the import continues in a new elevated PowerShell window (UAC prompt), which asks for the PFX password.'
                return
            }
        }
        if (-not (Test-NSPIsAdmin)) {
            throw 'Importing into the LocalMachine stores needs an elevated PowerShell session. Run as administrator, or use -StoreLocation CurrentUser.'
        }
    }
    if (-not $Password) { $Password = Read-Host 'PFX password' -AsSecureString }

    $x509 = 'System.Security.Cryptography.X509Certificates'
    $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]
    $plain = ConvertFrom-NSPSslSecureString -SecureString $Password

    # Look first, without writing a key anywhere: an ephemeral load to sort the certificates.
    $preview = New-Object "$x509.X509Certificate2Collection"
    try {
        $preview.Import($Path, $plain, $flags::EphemeralKeySet)
    } catch {
        throw "Could not open $Path. Check the password. ($($_.Exception.Message))"
    }
    $leaves = @($preview | Where-Object HasPrivateKey)
    if (-not $leaves) { throw "$Path has no certificate with a private key." }

    $items = [Collections.Generic.List[object]]::new()
    $seen = @{}
    foreach ($certificate in $preview) {
        $seen[$certificate.Thumbprint] = $true
        $items.Add($certificate)
    }
    foreach ($file in $ChainFile) {
        foreach ($certificate in Read-NSPSslCertificateFile -Path (Resolve-Path -LiteralPath $file).ProviderPath) {
            if (-not $seen.ContainsKey($certificate.Thumbprint)) { $seen[$certificate.Thumbprint] = $true; $items.Add($certificate) }
        }
    }

    $openStore = {
        param([string]$Name, [string]$Location, [string]$Mode)
        $store = New-Object "$x509.X509Store" $Name, $Location
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]$Mode)
        $store
    }
    $inStore = {
        param([string]$Name, [string]$Location, [string]$Thumbprint)
        $store = & $openStore $Name $Location 'ReadOnly'
        try { @($store.Certificates.Find('FindByThumbprint', $Thumbprint, $false)) } finally { $store.Close() }
    }

    $results = [Collections.Generic.List[object]]::new()
    $leafRow = $null
    foreach ($certificate in $items) {
        if ($certificate.HasPrivateKey) { $role = 'Certificate'; $storeName = 'My' }
        elseif (Test-NSPSslSelfSigned -Certificate $certificate) { $role = 'Root'; $storeName = 'Root' }
        else { $role = 'Intermediate'; $storeName = 'CA' }

        $row = [pscustomobject]@{
            Role        = $role
            Subject     = $certificate.Subject
            Thumbprint  = $certificate.Thumbprint
            Store       = "$StoreLocation\$storeName"
            Action      = ''
            Note        = ''
            Chain       = $null
            ChainStatus = $null
        }
        $results.Add($row)

        $existing = @(& $inStore $storeName $StoreLocation $certificate.Thumbprint)
        if ($role -eq 'Root' -and -not $existing -and $StoreLocation -eq 'CurrentUser') {
            # The CurrentUser root view already includes the machine's roots.
            $existing = @(& $inStore 'Root' 'LocalMachine' $certificate.Thumbprint)
        }
        if ($existing -and ($role -ne 'Certificate' -or $existing[0].HasPrivateKey)) {
            $row.Action = 'AlreadyPresent'
            if ($role -eq 'Certificate') { $leafRow = $row }
            continue
        }
        if ($role -eq 'Root' -and -not $TrustRoot) {
            $row.Action = 'Skipped'
            $row.Note = 'Not trusted on this machine. Windows normally fetches public roots itself; use -TrustRoot to add it.'
            continue
        }
        if (-not $PSCmdlet.ShouldProcess("$StoreLocation\$storeName", "Add $role $($certificate.Subject) ($($certificate.Thumbprint))")) {
            $row.Action = 'WhatIf'
            continue
        }

        $toAdd = $certificate
        if ($role -eq 'Certificate') {
            # Load again, this time keeping the key, only now that it's going in.
            $keyFlags = $flags::PersistKeySet
            $keyFlags = $keyFlags -bor $(if ($StoreLocation -eq 'LocalMachine') { $flags::MachineKeySet } else { $flags::UserKeySet })
            if ($Exportable) { $keyFlags = $keyFlags -bor $flags::Exportable }
            $persisted = New-Object "$x509.X509Certificate2Collection"
            $persisted.Import($Path, $plain, $keyFlags)
            $toAdd = $persisted | Where-Object Thumbprint -EQ $certificate.Thumbprint | Select-Object -First 1
            $leafRow = $row
        }
        $store = & $openStore $storeName $StoreLocation 'ReadWrite'
        try { $store.Add($toAdd) } finally { $store.Close() }
        $row.Action = 'Added'
    }

    if ($leafRow -and $leafRow.Action -in 'Added', 'AlreadyPresent') {
        $installed = @(& $inStore 'My' $StoreLocation $leafRow.Thumbprint)[0]
        $chain = New-Object "$x509.X509Chain" ($StoreLocation -eq 'LocalMachine')
        try {
            $chain.ChainPolicy.RevocationMode = 'NoCheck'
            $valid = $chain.Build($installed)
            $leafRow.Chain = @($chain.ChainElements | ForEach-Object { $_.Certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) })
            $leafRow.ChainStatus = if ($valid) { 'Valid' } else { (@($chain.ChainStatus | ForEach-Object { $_.StatusInformation.Trim() }) | Select-Object -Unique) -join ' ' }
        } finally {
            $chain.Reset()
        }
        if ($leafRow.ChainStatus -ne 'Valid') { Write-Warning "The certificate's chain doesn't validate on this machine: $($leafRow.ChainStatus)" }
    }

    $results
}
