function New-NSPSslRequest {
    <#
    .SYNOPSIS
        Generates a private key and a certificate signing request (CSR) for a public SSL certificate.
    .DESCRIPTION
        Creates a request folder <Path>\<domain> with:

            Inputs\                        put the issuer's ZIP here when the certificate comes back
            Deliverables\<domain>.csr      the CSR to paste into the issuer's order page
            Deliverables\<domain>_priv.key the private key (unencrypted PKCS#8 PEM)
            request.json                   the names and subject used

        The domain is the certificate's common name and first subject alternative name (SAN); add
        more names with -SubjectAlternativeName, and www.<domain> with -IncludeWww. Five names at
        most, the domain included, unless -NoNameLimit. Wildcards
        (*.contoso.com) work; their folder is named wildcard.contoso.com.

        A request folder that already has a key is never overwritten: the CSR may already be with
        the issuer. -Force starts over with a new key and moves the old Deliverables folder to
        Archive\<timestamp>.

        When the certificate is issued, download it in IIS format and run Complete-NSPSslRequest.

        Replaces 1_Gen_NewPrivKey_And_CSR.sh from NSP-SSLCertificates (no WSL or openssl needed).
    .PARAMETER Domain
        The certificate's main name (common name), for example vpn.contoso.com.
    .PARAMETER SubjectAlternativeName
        More names for the certificate. The domain is always included, and counts toward the
        five-name limit.
    .PARAMETER IncludeWww
        Also add www.<domain>, when one of the five names is still free (a warning says when it isn't).
    .PARAMETER NoNameLimit
        Allow more than five names, for a certificate product that covers more.
    .PARAMETER Organization
        Subject O. Domain-validated certificates ignore it; for organization-validated ones use the
        client's legal name.
    .PARAMETER City
        Subject L.
    .PARAMETER State
        Subject ST.
    .PARAMETER Country
        Subject C, two letters.
    .PARAMETER KeySize
        RSA key size: 2048 (default), 3072 or 4096.
    .PARAMETER Path
        The folder that holds request folders. Default: $env:NSP_SSL_PATH, else
        Documents\NSP-SSLCertificates.
    .PARAMETER CopyToClipboard
        Copy the CSR text to the clipboard.
    .PARAMETER Force
        Replace an existing request's key (the old files are archived, not deleted).
    .EXAMPLE
        New-NSPSslRequest -Domain vpn.contoso.com -CopyToClipboard
    .EXAMPLE
        New-NSPSslRequest -Domain contoso.com -IncludeWww -SubjectAlternativeName mail.contoso.com -Organization 'Contoso, Inc.' -City Omaha -State NE
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Domain,
        [string[]]$SubjectAlternativeName = @(),
        [switch]$IncludeWww,
        [switch]$NoNameLimit,
        [string]$Organization = 'Network Systems Plus, Inc.',
        [string]$City = 'Sioux City',
        [string]$State = 'IA',
        [ValidatePattern('^[A-Za-z]{2}$')][string]$Country = 'US',
        [ValidateSet(2048, 3072, 4096)][int]$KeySize = 2048,
        [string]$Path,
        [switch]$CopyToClipboard,
        [switch]$Force
    )

    $Domain = $Domain.Trim().ToLowerInvariant()
    $names = [Collections.Generic.List[string]]::new()
    $candidates = @($Domain) + @($SubjectAlternativeName | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })
    foreach ($name in $candidates) {
        if (-not (Test-NSPSslDnsName -Name $name)) { throw "'$name' is not a valid certificate name (expected something like vpn.contoso.com)." }
        if (-not $names.Contains($name)) { $names.Add($name) }
    }
    $limit = 5
    if (-not $NoNameLimit -and $names.Count -gt $limit) {
        throw "$($names.Count) names requested; the certificate products we buy cover $limit (the domain included). Drop some, or use -NoNameLimit for a product that covers more."
    }
    # www.<domain> takes a spare slot only, as the WSL scripts did.
    $www = "www.$Domain"
    if ($IncludeWww -and $Domain -notmatch '^(\*|www)\.' -and -not $names.Contains($www)) {
        if ($NoNameLimit -or $names.Count -lt $limit) { $names.Add($www) }
        else { Write-Warning "$www was not added: all $limit names are in use." }
    }

    $root = Get-NSPSslWorkRoot -Path $Path
    $folderName = ConvertTo-NSPSslFolderName -Domain $Domain
    $folder = Join-Path $root $folderName
    $layout = Get-NSPSslRequestLayout -Folder $folder
    if (Test-Path -LiteralPath $layout.KeyPath) {
        if (-not $Force) {
            throw "$Domain already has a key ($($layout.KeyPath)). Its CSR may already be with the issuer: finish it with Complete-NSPSslRequest, or use -Force to start over with a new key."
        }
    }
    if (-not $PSCmdlet.ShouldProcess($folder, "Create a $KeySize-bit key and CSR for $($names -join ', ')")) { return }

    if (Test-Path -LiteralPath $layout.KeyPath) {
        $archive = Join-Path $folder ("Archive\{0:yyyyMMdd-HHmmss}" -f (Get-Date))
        New-Item -ItemType Directory -Path $archive -Force | Out-Null
        Move-Item -LiteralPath $layout.Deliverables -Destination $archive
        Write-Warning "The previous key and deliverables for $Domain were moved to $archive."
    }
    $deliverables = Join-Path $folder 'Deliverables'
    foreach ($directory in $layout.Inputs, $deliverables) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
    $layout = Get-NSPSslRequestLayout -Folder $folder

    # Subject in the order openssl's config wrote it (C, ST, L, O, CN). .NET lists names most
    # specific first and encodes them in reverse; values with commas ("Plus, Inc.") are quoted.
    $parts = foreach ($pair in @(@('CN', $Domain), @('O', $Organization), @('L', $City), @('S', $State), @('C', $Country.ToUpperInvariant()))) {
        $value = $pair[1]
        if (-not $value) { continue }
        if ($value -match '[,+=";<>#\\]|^\s|\s$') { $value = '"{0}"' -f ($value -replace '"', '""') }
        '{0}={1}' -f $pair[0], $value
    }
    $subject = New-Object System.Security.Cryptography.X509Certificates.X500DistinguishedName ($parts -join ', ')

    $rsa = New-NSPSslRsa -KeySize $KeySize
    try {
        $request = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest($subject, $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $san = New-Object System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder
        foreach ($name in $names) { $san.AddDnsName($name) }
        $request.CertificateExtensions.Add($san.Build())
        $csr = ConvertTo-NSPSslPem -Label 'CERTIFICATE REQUEST' -Bytes $request.CreateSigningRequest()
        $key = ConvertTo-NSPSslPrivateKeyPem -Parameters $rsa.ExportParameters($true)
    } finally {
        $rsa.Dispose()
    }

    [IO.File]::WriteAllText($layout.KeyPath, $key)
    [IO.File]::WriteAllText($layout.CsrPath, $csr)
    $requestInfo = [ordered]@{
        Domain  = $Domain
        Names   = @($names)
        Subject = $subject.Name
        KeySize = $KeySize
        Created = (Get-Date).ToString('s')
    }
    [IO.File]::WriteAllText((Join-Path $folder 'request.json'), ($requestInfo | ConvertTo-Json))

    if ($CopyToClipboard) { Set-Clipboard -Value $csr }
    Write-Information "CSR for $Domain written to $($layout.CsrPath). When the certificate is issued, download it in IIS format, put the ZIP in $($layout.Inputs), and run: Complete-NSPSslRequest -Domain $Domain"

    [pscustomobject]@{
        Domain  = $Domain
        Names   = @($names)
        Subject = $subject.Name
        Folder  = $folder
        Inputs  = $layout.Inputs
        CsrPath = $layout.CsrPath
        KeyPath = $layout.KeyPath
        Csr     = $csr
    }
}
