function Complete-NSPSslRequest {
    <#
    .SYNOPSIS
        Turns the issuer's certificate files into deliverables: certificate, intermediates, full-chain
        PEM, and a password-protected PFX.
    .DESCRIPTION
        Reads the certificate files the issuer sent - by default the newest ZIP in the request's
        Inputs folder (IIS format: <serial>.crt plus *_intermediates.p7b), or any .crt/.cer/.pem/.p7b
        /.ca-bundle files or ZIPs given with -InputPath. The request's certificate is the one whose
        public key matches the request's private key, so extra files in the ZIP don't matter, and a
        ZIP for the wrong request is refused.

        The intermediates are put in order from the certificate up. Self-signed roots are left out
        (clients already trust them; -IncludeRoot keeps one). A cross-signed intermediate that
        carries a root's name, such as Starfield TLS Root CA - R1 issued by Starfield Root
        Certificate Authority - G2, is an intermediate and stays in.

        Writes to the request's Deliverables folder:

            <domain>.crt                the certificate (PEM)
            <domain>_intermediates.crt  the intermediates, in order (PEM)
            <domain>_FullChain.pem      certificate + intermediates (for FortiGate, nginx, Apache)
            <domain>.pfx                certificate + intermediates + private key (for Windows/IIS)

        The PFX password is not saved anywhere; send it separately from the PFX. Import the PFX on
        Windows with Import-NSPSslPfx, which puts each certificate in the right store.

        Replaces 2_CombineCerts.sh from NSP-SSLCertificates. Requests started there (Rebase\<domain>
        with Deliverables_<domain>) work too: pass -Path <the Rebase folder>.
    .PARAMETER Domain
        The request to finish, as given to New-NSPSslRequest.
    .PARAMETER Path
        The folder that holds request folders (see New-NSPSslRequest).
    .PARAMETER Folder
        A request folder, instead of -Domain and -Path. Get-NSPSslRequest output pipes here.
    .PARAMETER InputPath
        ZIPs, certificate files or folders to read instead of the newest ZIP in Inputs.
    .PARAMETER PfxPassword
        The password for the PFX. Prompted for when not given.
    .PARAMETER FriendlyName
        The PFX certificate's friendly name. Default: <domain>_<year issued>.
    .PARAMETER IncludeRoot
        Keep a self-signed root, when the issuer sent one, in the intermediates, full chain, and PFX.
    .EXAMPLE
        Complete-NSPSslRequest -Domain vpn.contoso.com
    .EXAMPLE
        Complete-NSPSslRequest -Domain vpn.contoso.com -InputPath C:\Downloads\vpn.contoso.com.zip -PfxPassword (Read-Host -AsSecureString 'PFX password')
    .EXAMPLE
        Get-NSPSslRequest -Status CertificateReady | Complete-NSPSslRequest
    #>
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Domain')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'Domain')][string]$Domain,
        [Parameter(ParameterSetName = 'Domain')][string]$Path,
        [Parameter(Mandatory, ParameterSetName = 'Folder', ValueFromPipelineByPropertyName)][string]$Folder,
        [string[]]$InputPath,
        [Parameter(Mandatory)][securestring]$PfxPassword,
        [string]$FriendlyName,
        [switch]$IncludeRoot
    )

    process {
        if ($PSCmdlet.ParameterSetName -eq 'Domain') {
            $Folder = Join-Path (Get-NSPSslWorkRoot -Path $Path) (ConvertTo-NSPSslFolderName -Domain $Domain.Trim())
        }
        $layout = Get-NSPSslRequestLayout -Folder $Folder
        if (-not (Test-Path -LiteralPath $layout.KeyPath)) { throw "No private key at $($layout.KeyPath). Start the request with New-NSPSslRequest." }

        if (-not $InputPath) {
            $zips = @(Get-ChildItem -LiteralPath $layout.Inputs -Filter '*.zip' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
            if (-not $zips) { throw "No ZIP in $($layout.Inputs). Download the certificate from the issuer in IIS format and put the ZIP there, or pass -InputPath." }
            if ($zips.Count -gt 1) { Write-Warning "$($zips.Count) ZIPs in $($layout.Inputs); using the newest, $($zips[0].Name)." }
            $InputPath = @($zips[0].FullName)
        }

        $extract = Join-Path ([IO.Path]::GetTempPath()) ('NSP-SSL-' + [guid]::NewGuid().ToString('N'))
        $candidates = [Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]]::new()
        $seen = @{}
        $rsa = $null
        try {
            $files = foreach ($item in $InputPath) {
                if (-not (Test-Path -LiteralPath $item)) { throw "Not found: $item" }
                $entry = Get-Item -LiteralPath $item
                if ($entry.PSIsContainer) {
                    Get-ChildItem -LiteralPath $entry.FullName -File -Recurse
                } elseif ($entry.Extension -eq '.zip') {
                    $target = Join-Path $extract ([guid]::NewGuid().ToString('N'))
                    Expand-Archive -LiteralPath $entry.FullName -DestinationPath $target
                    Get-ChildItem -LiteralPath $target -File -Recurse
                } else {
                    $entry
                }
            }
            foreach ($file in @($files | Where-Object { $_.Extension -in '.crt', '.cer', '.pem', '.der', '.p7b', '.p7c', '.ca-bundle' })) {
                try {
                    foreach ($certificate in Read-NSPSslCertificateFile -Path $file.FullName) {
                        if (-not $seen.ContainsKey($certificate.Thumbprint)) { $seen[$certificate.Thumbprint] = $true; $candidates.Add($certificate) }
                    }
                } catch {
                    Write-Warning "Skipped $($file.Name): not a certificate file ($($_.Exception.Message))."
                }
            }
            if (-not $candidates.Count) { throw "No certificates found in $($InputPath -join ', ')." }

            $keyParameters = ConvertFrom-NSPSslPrivateKeyPem -Text ([IO.File]::ReadAllText($layout.KeyPath))
            $modulus = [Convert]::ToBase64String($keyParameters.Modulus)
            $leaf = $candidates | Where-Object {
                $publicKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($_)
                $publicKey -and [Convert]::ToBase64String($publicKey.ExportParameters($false).Modulus) -eq $modulus
            } | Sort-Object NotAfter -Descending | Select-Object -First 1
            if (-not $leaf) {
                throw "None of the $($candidates.Count) certificates in $($InputPath -join ', ') belong to the private key for $($layout.Domain). Check that the files are for this request and were issued from its CSR."
            }

            $chain = @(Get-NSPSslCertificateChain -Certificate $leaf -Candidates $candidates.ToArray())
            $issuers = @($chain | Where-Object { $IncludeRoot -or -not (Test-NSPSslSelfSigned -Certificate $_) })
            if (-not $chain -or -not (Test-NSPSslSelfSigned -Certificate $chain[-1])) {
                $top = if ($chain) { $chain[-1] } else { $leaf }
                if (-not $chain) { Write-Warning "The issuer sent no intermediates for $($leaf.Subject); clients may not be able to build its chain." }
                Write-Verbose "Chain ends at $($top.Subject), issued by $($top.Issuer) (not included)."
            }

            $now = Get-Date
            if ($leaf.NotAfter -lt $now) { Write-Warning "The certificate expired on $($leaf.NotAfter)." }
            if ($leaf.NotBefore -gt $now) { Write-Warning "The certificate isn't valid until $($leaf.NotBefore)." }
            $issuedNames = @(Get-NSPSslDnsName -Certificate $leaf)
            $missing = @($layout.Names | Where-Object { $_ -notin $issuedNames })
            if ($missing) { Write-Warning "Requested but not on the certificate: $($missing -join ', ')." }

            if (-not $PSCmdlet.ShouldProcess($layout.Deliverables, "Write the certificate, intermediates, full chain and PFX for $($leaf.Subject)")) { return }

            $certificatePem = ConvertTo-NSPSslPem -Label 'CERTIFICATE' -Bytes $leaf.RawData
            $issuersPem = ($issuers | ForEach-Object { ConvertTo-NSPSslPem -Label 'CERTIFICATE' -Bytes $_.RawData }) -join ''
            [IO.File]::WriteAllText($layout.CertificatePath, $certificatePem)
            [IO.File]::WriteAllText($layout.IntermediatesPath, $issuersPem)
            [IO.File]::WriteAllText($layout.FullChainPath, $certificatePem + $issuersPem)

            $rsa = New-NSPSslRsa -Parameters $keyParameters
            $withKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($leaf, $rsa)
            if (-not $FriendlyName) { $FriendlyName = '{0}_{1}' -f (ConvertTo-NSPSslFolderName -Domain $layout.Domain), $leaf.NotBefore.Year }
            $withKey.FriendlyName = $FriendlyName
            $bundle = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
            [void]$bundle.Add($withKey)
            foreach ($issuer in $issuers) { [void]$bundle.Add($issuer) }
            $pfx = $bundle.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, (ConvertFrom-NSPSslSecureString -SecureString $PfxPassword))
            [IO.File]::WriteAllBytes($layout.PfxPath, $pfx)

            [pscustomobject]@{
                Domain            = $layout.Domain
                Subject           = $leaf.Subject
                Names             = $issuedNames
                Thumbprint        = $leaf.Thumbprint
                NotAfter          = $leaf.NotAfter
                Chain             = @($issuers | ForEach-Object { $_.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) })
                FriendlyName      = $FriendlyName
                CertificatePath   = $layout.CertificatePath
                IntermediatesPath = $layout.IntermediatesPath
                FullChainPath     = $layout.FullChainPath
                PfxPath           = $layout.PfxPath
            }
        } finally {
            if ($rsa) { $rsa.Dispose() }
            Remove-Item -LiteralPath $extract -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
