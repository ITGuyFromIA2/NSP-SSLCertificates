$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'NSP.SSLCertificates.psd1') -Force
$module = Get-Module NSP.SSLCertificates

function Assert-Equal($Actual, $Expected, $Message) {
    if ($Actual -ne $Expected) { throw "$Message. Expected '$Expected', got '$Actual'." }
}
function Assert-Error([scriptblock]$Script, [string]$Pattern, [string]$Message) {
    try { & $Script } catch { if ($_.Exception.Message -match $Pattern) { return }; throw "$Message. Wrong error: $($_.Exception.Message)" }
    throw "$Message. Expected an error."
}
# A test password as a SecureString, built a character at a time.
function New-TestSecureString([string]$Text) {
    $secure = New-Object Security.SecureString
    foreach ($character in $Text.ToCharArray()) { $secure.AppendChar($character) }
    $secure
}

$x509 = 'System.Security.Cryptography.X509Certificates'
$sha256 = [System.Security.Cryptography.HashAlgorithmName]::SHA256
$pkcs1 = [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
$now = [DateTimeOffset]::Now
$serial = 0
# A test issuer: self-signed, or signed by -Issuer. Returned with its private key so it can sign.
function New-TestIssuer([string]$Subject, $Issuer) {
    $key = New-Object System.Security.Cryptography.RSACryptoServiceProvider 2048
    $key.PersistKeyInCsp = $false
    $request = New-Object "$x509.CertificateRequest"($Subject, $key, $sha256, $pkcs1)
    $request.CertificateExtensions.Add((New-Object "$x509.X509BasicConstraintsExtension"($true, $false, 0, $true)))
    $request.CertificateExtensions.Add((New-Object "$x509.X509SubjectKeyIdentifierExtension"($request.PublicKey, $false)))
    if (-not $Issuer) { return $request.CreateSelfSigned($now.AddDays(-1), $now.AddYears(5)) }
    $script:serial++
    $issued = $request.Create($Issuer, $now.AddDays(-1), $now.AddYears(4), [byte[]](1, 0, $script:serial))
    [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($issued, $key)
}
# Shaped like Starfield's DV chain: G2 root -> cross-signed "Root CA - R1" -> DV intermediate.
$g2 = New-TestIssuer 'CN=NSP Test Root - G2, O=NSP Test' $null
$r1 = New-TestIssuer 'CN=NSP Test TLS Root - R1, O=NSP Test' $g2
$dv = New-TestIssuer 'CN=NSP Test TLS Intermediate DV, O=NSP Test' $r1
# Issue a leaf for a request's key, the way the CA would from the CSR.
function New-TestLeaf([string]$KeyPath, [string[]]$Names, $Issuer = $dv) {
    $parameters = & $module { param($Path) ConvertFrom-NSPSslPrivateKeyPem -Text ([IO.File]::ReadAllText($Path)) } $KeyPath
    $key = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    $key.ImportParameters($parameters)
    $request = New-Object "$x509.CertificateRequest"("CN=$($Names[0])", $key, $sha256, $pkcs1)
    $san = New-Object "$x509.SubjectAlternativeNameBuilder"
    foreach ($name in $Names) { $san.AddDnsName($name) }
    $request.CertificateExtensions.Add($san.Build())
    $script:serial++
    $request.Create($Issuer, $now.AddDays(-1), $now.AddDays(90), [byte[]](2, 0, $script:serial))
}
function New-TestZip([string]$Path, $Leaf, [object[]]$Bundle, [object[]]$Extra = @()) {
    $staging = Join-Path ([IO.Path]::GetTempPath()) ('NSP-SSL-Zip-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $staging | Out-Null
    $pem = & $module { param($Bytes) ConvertTo-NSPSslPem -Label 'CERTIFICATE' -Bytes $Bytes } $Leaf.RawData
    [IO.File]::WriteAllText((Join-Path $staging 'a1b2c3d4e5f60718.crt'), $pem)
    [IO.File]::WriteAllText((Join-Path $staging 'a1b2c3d4e5f60718.pem'), $pem)
    $collection = New-Object "$x509.X509Certificate2Collection"
    foreach ($certificate in $Bundle) { [void]$collection.Add((New-Object "$x509.X509Certificate2"(, $certificate.RawData))) }
    [IO.File]::WriteAllBytes((Join-Path $staging 'test_iis_intermediates.p7b'), $collection.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs7))
    foreach ($certificate in $Extra) { [IO.File]::WriteAllBytes((Join-Path $staging "$($certificate.Thumbprint).cer"), $certificate.RawData) }
    Compress-Archive -Path (Join-Path $staging '*') -DestinationPath $Path -Force
    Remove-Item -LiteralPath $staging -Recurse -Force
}

$work = Join-Path ([IO.Path]::GetTempPath()) ('NSP-SSL-Smoke-' + [guid]::NewGuid().ToString('N'))
$password = New-TestSecureString 'Smoke-Test-1!'
$imported = @()
try {
    # Names: validated, lower-cased, de-duplicated; www only when asked for.
    $request = New-NSPSslRequest -Domain 'VPN.Contoso.com' -SubjectAlternativeName 'remote.contoso.com', 'vpn.contoso.com' -IncludeWww -Organization 'Contoso, Inc.' -Path $work -InformationAction SilentlyContinue
    Assert-Equal ($request.Names -join ',') 'vpn.contoso.com,remote.contoso.com,www.vpn.contoso.com' 'Request names'
    Assert-Equal $request.Subject 'CN=vpn.contoso.com, O="Contoso, Inc.", L=Sioux City, S=IA, C=US' 'Subject keeps the comma in O'
    Assert-Equal ($request.Csr -match '^-----BEGIN CERTIFICATE REQUEST-----') $true 'CSR is PEM'
    Assert-Equal ([IO.File]::ReadAllText($request.KeyPath) -match '^-----BEGIN PRIVATE KEY-----') $true 'Key is PKCS#8 PEM'
    Assert-Equal (Test-Path (Join-Path $request.Folder 'request.json')) $true 'request.json written'
    Assert-Error { New-NSPSslRequest -Domain 'bad_name' -Path $work } 'not a valid certificate name' 'Invalid name refused'
    Assert-Error { New-NSPSslRequest -Domain 'vpn.contoso.com' -Path $work } 'already has a key' 'Existing key never overwritten'
    $wildcard = New-NSPSslRequest -Domain '*.contoso.com' -Path $work -InformationAction SilentlyContinue
    Assert-Equal (Split-Path -Leaf $wildcard.Folder) 'wildcard.contoso.com' 'Wildcard folder name'

    # Five names at most; www only takes a spare slot; -NoNameLimit lifts both.
    $four = 'a.contoso.com', 'b.contoso.com', 'c.contoso.com', 'd.contoso.com'
    Assert-Error { New-NSPSslRequest -Domain 'six.contoso.com' -SubjectAlternativeName ($four + 'e.contoso.com') -Path $work -WhatIf } 'limit|cover 5' 'Six names refused'
    $full = New-NSPSslRequest -Domain 'five.contoso.com' -SubjectAlternativeName $four -IncludeWww -Path $work -WarningVariable fullWarning -WarningAction SilentlyContinue -InformationAction SilentlyContinue
    Assert-Equal $full.Names.Count 5 'www skipped when five names are in use'
    Assert-Equal ([string]$fullWarning -match 'www.five.contoso.com was not added') $true 'Skipped www warned about'
    $many = New-NSPSslRequest -Domain 'many.contoso.com' -SubjectAlternativeName ($four + 'e.contoso.com') -IncludeWww -NoNameLimit -Path $work -InformationAction SilentlyContinue
    Assert-Equal $many.Names.Count 7 '-NoNameLimit'

    # Key round trip: PKCS#8 and the PKCS#1 form the openssl 1.x Rebase scripts wrote read the same.
    $keyText = [IO.File]::ReadAllText($request.KeyPath)
    $roundTrip = & $module {
        param($Text)
        $pkcs8 = ConvertFrom-NSPSslPrivateKeyPem -Text $Text
        $der = (ConvertFrom-NSPSslPem -Text $Text)[0].Bytes
        $outer = Read-NSPSslDerElement -Bytes $der
        $version = Read-NSPSslDerElement -Bytes $outer.Content
        $algorithm = Read-NSPSslDerElement -Bytes $outer.Content -Offset $version.Next
        $inner = (Read-NSPSslDerElement -Bytes $outer.Content -Offset $algorithm.Next).Content
        $pkcs1 = ConvertFrom-NSPSslPrivateKeyPem -Text (ConvertTo-NSPSslPem -Label 'RSA PRIVATE KEY' -Bytes $inner)
        $rsa = New-NSPSslRsa -Parameters $pkcs1
        try { $signature = $rsa.SignData([byte[]](1, 2, 3), [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1) } finally { $rsa.Dispose() }
        [pscustomobject]@{ Same = [Convert]::ToBase64String($pkcs8.D) -eq [Convert]::ToBase64String($pkcs1.D); Signed = $signature.Length; Again = (ConvertTo-NSPSslPrivateKeyPem -Parameters $pkcs1) -eq $Text }
    } $keyText
    Assert-Equal $roundTrip.Same $true 'PKCS#1 and PKCS#8 read the same key'
    Assert-Equal $roundTrip.Signed 256 'Imported key signs'
    Assert-Equal $roundTrip.Again $true 'Key writes back byte-identical'

    # Chain sorting: root by self-signature, not by name.
    Assert-Equal (& $module { param($c) Test-NSPSslSelfSigned -Certificate $c } $r1) $false 'Cross-signed "Root - R1" is an intermediate'
    Assert-Equal (& $module { param($c) Test-NSPSslSelfSigned -Certificate $c } $g2) $true 'G2 is a root'

    Assert-Equal @(Get-NSPSslRequest -Path $work -Domain 'vpn.contoso.com')[0].Status 'AwaitingCertificate' 'Status before the ZIP'
    Assert-Error { Complete-NSPSslRequest -Domain vpn.contoso.com -Path $work -PfxPassword $password } 'No ZIP' 'Complete without a ZIP'

    # A ZIP for another request's key is refused.
    $otherLeaf = New-TestLeaf -KeyPath $wildcard.KeyPath -Names '*.contoso.com'
    New-TestZip -Path (Join-Path $request.Inputs 'wrong.zip') -Leaf $otherLeaf -Bundle $dv, $r1
    Assert-Error { Complete-NSPSslRequest -Domain vpn.contoso.com -Path $work -PfxPassword $password } 'belong to the private key' 'Wrong ZIP refused'
    Remove-Item -LiteralPath (Join-Path $request.Inputs 'wrong.zip')

    # The IIS-format ZIP: leaf .crt/.pem, intermediates .p7b (DV + cross-signed R1), plus the G2 root.
    $leaf = New-TestLeaf -KeyPath $request.KeyPath -Names $request.Names
    New-TestZip -Path (Join-Path $request.Inputs 'vpn.contoso.com.zip') -Leaf $leaf -Bundle $r1, $dv -Extra $g2
    Assert-Equal @(Get-NSPSslRequest -Path $work -Domain 'vpn.contoso.com')[0].Status 'CertificateReady' 'Status with the ZIP'
    $done = Complete-NSPSslRequest -Domain vpn.contoso.com -Path $work -PfxPassword $password
    Assert-Equal $done.Thumbprint $leaf.Thumbprint 'Leaf found by key'
    Assert-Equal ($done.Chain -join ' > ') 'NSP Test TLS Intermediate DV > NSP Test TLS Root - R1' 'Chain in order, root left out'
    Assert-Equal $done.FriendlyName "vpn.contoso.com_$($leaf.NotBefore.Year)" 'Default friendly name'
    $full = @(& $module { param($p) Read-NSPSslCertificateFile -Path $p } $done.FullChainPath)
    Assert-Equal (($full | ForEach-Object Thumbprint) -join ',') (($leaf, $dv, $r1 | ForEach-Object Thumbprint) -join ',') 'Full chain: leaf, DV, R1'
    Assert-Equal @(& $module { param($p) Read-NSPSslCertificateFile -Path $p } $done.IntermediatesPath).Count 2 'Intermediates file'
    $pfx = New-Object "$x509.X509Certificate2Collection"
    $pfx.Import($done.PfxPath, 'Smoke-Test-1!', [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
    Assert-Equal $pfx.Count 3 'PFX holds leaf + 2 intermediates'
    Assert-Equal (@($pfx | Where-Object HasPrivateKey)[0].Thumbprint) $leaf.Thumbprint 'PFX key is on the leaf'
    Assert-Equal (@($pfx | Where-Object HasPrivateKey)[0].FriendlyName) $done.FriendlyName 'PFX friendly name'
    $withRoot = Complete-NSPSslRequest -Folder $request.Folder -PfxPassword $password -IncludeRoot -FriendlyName 'custom'
    Assert-Equal $withRoot.Chain.Count 3 '-IncludeRoot keeps G2'
    Assert-Equal @(Get-NSPSslRequest -Path $work -Status Completed).Count 1 'Completed status'

    # -Force archives the old key instead of deleting it.
    $again = New-NSPSslRequest -Domain '*.contoso.com' -Path $work -Force -WarningAction SilentlyContinue -InformationAction SilentlyContinue
    Assert-Equal @(Get-ChildItem -LiteralPath (Join-Path $again.Folder 'Archive') -Recurse -Filter '*_priv.key').Count 1 'Old key archived'

    # WSL-era Rebase layout: Deliverables_<domain>, PKCS#1 key, no request.json.
    $legacy = Join-Path $work 'legacy.contoso.com'
    New-Item -ItemType Directory -Path (Join-Path $legacy 'Deliverables_legacy.contoso.com'), (Join-Path $legacy 'Inputs') | Out-Null
    $legacyKey = Join-Path $legacy 'Deliverables_legacy.contoso.com\legacy.contoso.com_priv.key'
    & $module {
        param($Path)
        $rsa = New-NSPSslRsa -KeySize 2048
        try { $pem = ConvertTo-NSPSslPrivateKeyPem -Parameters $rsa.ExportParameters($true) } finally { $rsa.Dispose() }
        [IO.File]::WriteAllText($Path, $pem)
    } $legacyKey
    New-TestZip -Path (Join-Path $legacy 'Inputs\legacy.contoso.com.zip') -Leaf (New-TestLeaf -KeyPath $legacyKey -Names 'legacy.contoso.com') -Bundle $dv, $r1
    $legacyDone = Complete-NSPSslRequest -Domain legacy.contoso.com -Path $work -PfxPassword $password
    Assert-Equal (Split-Path -Parent $legacyDone.PfxPath) (Join-Path $legacy 'Deliverables_legacy.contoso.com') 'Legacy deliverables folder reused'

    # Client side: WhatIf changes nothing; a CurrentUser import sorts the stores.
    $preview = @(Import-NSPSslPfx -Path $withRoot.PfxPath -Password $password -StoreLocation CurrentUser -WhatIf)
    Assert-Equal (($preview | ForEach-Object { "$($_.Role)=$($_.Action)" }) -join ',') 'Certificate=WhatIf,Intermediate=WhatIf,Intermediate=WhatIf,Root=Skipped' 'WhatIf plan'
    Assert-Equal (($preview | ForEach-Object Store) -join ',') 'CurrentUser\My,CurrentUser\CA,CurrentUser\CA,CurrentUser\Root' 'Stores by role'

    $result = @(Import-NSPSslPfx -Path $done.PfxPath -Password $password -StoreLocation CurrentUser -ChainFile $done.IntermediatesPath -WarningAction SilentlyContinue)
    $imported = @($result | Where-Object Action -EQ 'Added')
    Assert-Equal (($result | ForEach-Object { "$($_.Role)=$($_.Action)" }) -join ',') 'Certificate=Added,Intermediate=Added,Intermediate=Added,Root=Skipped' 'Import actions (the -IncludeRoot PFX; untrusted root skipped)'
    $my = New-Object "$x509.X509Store" 'My', 'CurrentUser'
    $my.Open('ReadOnly')
    try { $installed = @($my.Certificates.Find('FindByThumbprint', $leaf.Thumbprint, $false))[0] } finally { $my.Close() }
    Assert-Equal $installed.HasPrivateKey $true 'Installed with its key'
    Assert-Equal ($result[0].Chain -join ' > ') 'vpn.contoso.com > NSP Test TLS Intermediate DV > NSP Test TLS Root - R1' 'Chain built through the CA store (up to the untrusted root)'
    Assert-Equal ($result[0].ChainStatus -ne 'Valid') $true 'Untrusted test root reported'
    $twice = @(Import-NSPSslPfx -Path $done.PfxPath -Password $password -StoreLocation CurrentUser -WarningAction SilentlyContinue)
    Assert-Equal (($twice | Where-Object Role -NE 'Root' | ForEach-Object Action | Select-Object -Unique) -join ',') 'AlreadyPresent' 'Second import changes nothing'
    Assert-Error { Import-NSPSslPfx -Path $done.PfxPath -Password (New-TestSecureString 'wrong') -StoreLocation CurrentUser } 'Check the password' 'Wrong PFX password'
} finally {
    foreach ($row in $imported) {
        $store = New-Object "$x509.X509Store" ($row.Store -split '\\')[1], 'CurrentUser'
        $store.Open('ReadWrite')
        try {
            foreach ($certificate in @($store.Certificates.Find('FindByThumbprint', $row.Thumbprint, $false))) {
                # Delete the persisted key too, not just the store entry.
                if ($certificate.HasPrivateKey) {
                    $key = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
                    if ($key -is [System.Security.Cryptography.RSACng]) { $key.Key.Delete() }
                    elseif ($key -is [System.Security.Cryptography.RSACryptoServiceProvider]) { $key.PersistKeyInCsp = $false; $key.Clear() }
                }
                $store.Remove($certificate)
            }
        } finally { $store.Close() }
    }
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

"$($PSVersionTable.PSVersion): NSP.SSLCertificates smoke checks passed."
